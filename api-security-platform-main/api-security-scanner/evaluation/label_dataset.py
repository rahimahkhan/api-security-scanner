#!/usr/bin/env python3
"""Label a dataset log by joining it to ground truth.

Usage:
    python3 evaluation/label_dataset.py <dataset.jsonl> <ground-truth.yaml>
        [--out <labeled.jsonl>]

Why this exists: the dataset log carries NO training label on purpose.
A label taken from the scanner's own verdict would be circular — a model
trained to predict "Confirmed" just copies the signature layer and learns
nothing about the Suspected cases, which are the ones that need ranking.
The label comes from joining each logged pair to the ground-truth YAML:
a pair is a POSITIVE for an item when the probe targets that item's
(template, parameter) with a probe whose category matches the item's
category. Everything else is a NEGATIVE for its probed category. The
scanner's verdict stays in the record as the scanner_label feature
column — it is a feature, never the label.

A pair is positive iff:
  1. its endpoint_url path matches the item's template (same
     template_regex as the scorer), AND
  2. its parameter matches the item's parameter (an item with no
     parameter matches any parameter on its template), AND
  3. its probed category (from probe_type) matches the item's category.

Output: the same records with `label` (1/0), `label_source` and
`matched_item` added, written to <input-stem>-labeled.jsonl (or --out),
plus a summary printed to stdout.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from score_scan import template_regex  # noqa: E402

# Probe type -> the vulnerability category that probe tests. The finding's
# attack_type is the scanner's verdict and must NOT decide the label.
PROBE_TYPE_TO_CATEGORY = {
    "SQL_Injection_GET": "SQL_Injection",
    "SQL_Injection_Error": "SQL_Injection",
    "SQL_Injection_Time": "SQL_Injection",
    "Cross_Site_Scripting": "XSS",
    "Command_Injection": "Command_Injection",
    "BOLA_IDOR": "BOLA_IDOR",
    "Mass_Assignment": "Mass_Assignment",
    "Sensitive_Data_Exposure": "Sensitive_Data_Exposure",
    "Verbose_Error_Exposure": "Verbose_Error_Exposure",
    "Open_Redirect": "Open_Redirect",
    "XXE": "XXE",
    "SSRF": "SSRF",
    "Auth_Weakness": "Auth_Weakness",
}


def probe_category(record):
    probe_type = record.get("probe_type", "")
    if probe_type in PROBE_TYPE_TO_CATEGORY:
        return PROBE_TYPE_TO_CATEGORY[probe_type]
    # Fall back to the finding's attack_type (the category the probe was
    # testing when a finding exists), else the raw probe type.
    return record.get("finding", {}).get("attack_type") or probe_type


def _item_parameter(item):
    """The item's parameter name, without a ' (path)'/' (body)' suffix."""
    param = (item.get("parameter") or "").strip()
    for suffix in (" (path)", " (body)", " (query)", " (header)"):
        if param.endswith(suffix):
            param = param[: -len(suffix)]
    return param


def match_item(record, items):
    """Return the ground-truth item this pair targets, or None."""
    path = record.get("endpoint_url", "")
    # Strip scheme/host the same way the scorer does.
    from urllib.parse import urlsplit
    try:
        path = urlsplit(path).path
    except Exception:
        pass
    parameter = record.get("parameter", "")
    category = probe_category(record)
    mode = (record.get("mode") or "").strip()
    for item in items:
        if item.get("category") != category:
            continue
        # A mode-scoped item only labels runs in that mode (VAmPI's SQLi
        # is real in vulnerable mode and absent in secure mode — the same
        # probe on the same endpoint is a positive in one and a negative
        # in the other). Items without a modes list match any mode.
        modes = item.get("modes")
        if modes and mode and mode not in modes:
            continue
        if not template_regex(item.get("template", "")).fullmatch(path):
            continue
        item_param = _item_parameter(item)
        if item_param and item_param != parameter:
            # A path-appended probe is bound to a path segment, so it
            # targets the template's path parameter (e.g. the {username}
            # in /users/v1/{username}) — the logger records it as "path".
            if not (parameter == "path" and "{" in item.get("template", "")):
                continue
        return item
    return None


def label(records, ground_truth_path):
    items = yaml.safe_load(Path(ground_truth_path).read_text())["items"]
    labeled = []
    stats = {"total": 0, "positive": 0, "negative": 0, "by_category": {}}
    for record in records:
        item = match_item(record, items)
        category = probe_category(record)
        bucket = stats["by_category"].setdefault(
            category, {"positive": 0, "negative": 0})
        if item is not None:
            record["label"] = 1
            record["label_source"] = f"ground_truth:{item.get('id', '?')}"
            record["matched_item"] = item.get("id")
            stats["positive"] += 1
            bucket["positive"] += 1
        else:
            record["label"] = 0
            record["label_source"] = "ground_truth:no_match"
            record["matched_item"] = None
            stats["negative"] += 1
            bucket["negative"] += 1
        stats["total"] += 1
        labeled.append(record)
    return labeled, stats


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dataset", help="dataset-session-<id>.jsonl to label")
    ap.add_argument("ground_truth", help="ground-truth YAML for this target")
    ap.add_argument("--out", help="output path (default: <stem>-labeled.jsonl)")
    args = ap.parse_args()

    records = [json.loads(line) for line in open(args.dataset)
               if line.strip()]
    labeled, stats = label(records, args.ground_truth)
    out = args.out or str(Path(args.dataset).with_name(
        Path(args.dataset).stem + "-labeled.jsonl"))
    with open(out, "w", encoding="utf-8") as fh:
        for record in labeled:
            fh.write(json.dumps(record) + "\n")
    print(f"labeled {stats['total']} pairs -> {out}")
    print(f"  positive: {stats['positive']}  negative: {stats['negative']}")
    for category in sorted(stats["by_category"]):
        b = stats["by_category"][category]
        print(f"  {category}: +{b['positive']} / -{b['negative']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
