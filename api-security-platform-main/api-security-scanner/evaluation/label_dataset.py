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
category. Everything else is a NEGATIVE for its probed category — with
one exception: pairs matching a `needs_auth` entry are EXCLUDED from the
labeled output entirely. Those bugs exist, but their routes need a
logged-in user the scanner never has, so the probe can never trigger
them; labeling such a pair 0 would teach a model that a real bug looks
benign. The scanner's verdict stays in the record as the scanner_label
feature column — it is a feature, never the label.

A second, opposite list is `near_misses`: bench-documented safe code
of the same shape as a scored bug, on its own reachable endpoint with
a matching scanner category (e.g. fastapi's bound-parameter
/api/posts/list beside the injectable /api/posts/search). A pair on a
near-miss labels 0 — the code is safe by the bench's design — but with
`matched_item` set to the near-miss id and `near_miss: true`, so the
dataset distinguishes a DELIBERATE hard negative from a default
negative. Only endpoint-level near-misses qualify: code-level
look-alikes (a dead helper function in the same file, a safe-twin-only
fix) are not separately observable endpoints and the join cannot
express them — see METHODOLOGY.md §2 and the ground-truth files.

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


def probe_effective(record):
    """Did this probe's response show the bug? A response-based rule on
    the logged differential features — NOT the scanner's verdict, so it
    is not circular.

    "The endpoint has this bug" is not the same as "this probe's response
    shows it": a probe that never triggered the bug looks like a normal
    response, and no model can detect it. A pair is effective when the
    probe visibly changed the response vs the baseline: the status
    changed, the body differs materially, an error keyword appeared, or
    the payload was reflected. Report results on both the full positives
    and the effective-only positives.
    """
    feats = record.get("telemetry", {}) or {}
    if feats.get("status_changed"):
        return 1
    try:
        if float(feats.get("body_diff_ratio") or 0) > 0.1:
            return 1
    except (TypeError, ValueError):
        pass
    try:
        if float(feats.get("error_keyword_delta") or 0) > 0:
            return 1
    except (TypeError, ValueError):
        pass
    if feats.get("payload_reflected"):
        return 1
    # A time-based probe whose injected delay fired: the response took
    # much longer than the baseline. Only for delay payloads — a plain
    # slow response on another probe type is not a visible bug effect.
    if record.get("probe_type") == "SQL_Injection_Time":
        try:
            if float(feats.get("time_delta_ratio") or 0) > 1.0:
                return 1
        except (TypeError, ValueError):
            pass
    return 0


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
    gt = yaml.safe_load(Path(ground_truth_path).read_text())
    items = gt["items"]
    # needs_auth (2026-11-27): bugs that exist but whose routes need a
    # logged-in user. A pair there can never trigger the bug, so it is
    # neither a positive nor a negative — it is dropped from the labeled
    # output, not labeled 0.
    needs_auth = gt.get("needs_auth", [])
    # near_misses (2026-11-28): bench-documented safe look-alikes on
    # their own endpoints. A pair there is a deliberate hard negative:
    # label 0, but record which near-miss it matched and flag it, so
    # the dataset can tell a verified-clean endpoint from an untested
    # one. Checked AFTER items — a real bug outranks its look-alike if
    # the two ever shared a template (they do not in the current files).
    near_misses = gt.get("near_misses", [])
    labeled = []
    stats = {"total": 0, "positive": 0, "negative": 0,
             "positive_effective": 0, "positive_not_effective": 0,
             "excluded_needs_auth": 0, "near_miss_negatives": 0,
             "by_category": {}}
    for record in records:
        if match_item(record, needs_auth):
            stats["excluded_needs_auth"] += 1
            continue
        item = match_item(record, items)
        category = probe_category(record)
        bucket = stats["by_category"].setdefault(
            category, {"positive": 0, "negative": 0})
        record["probe_effective"] = probe_effective(record)
        # VAmPI's vulnerable and secure modes are ONE group for splitting
        # (training on one mode and testing on the other is leakage).
        record["group"] = record.get("group") or record.get("target_app", "")
        if item is not None:
            record["label"] = 1
            record["label_source"] = f"ground_truth:{item.get('id', '?')}"
            record["matched_item"] = item.get("id")
            record["near_miss"] = False
            stats["positive"] += 1
            bucket["positive"] += 1
            if record["probe_effective"]:
                stats["positive_effective"] += 1
            else:
                stats["positive_not_effective"] += 1
        else:
            near_miss = match_item(record, near_misses)
            record["label"] = 0
            record["matched_item"] = (near_miss.get("id")
                                      if near_miss else None)
            record["near_miss"] = bool(near_miss)
            if near_miss:
                record["label_source"] = (
                    f"ground_truth:near_miss:{near_miss.get('id', '?')}")
                stats["near_miss_negatives"] += 1
            else:
                record["label_source"] = "ground_truth:no_match"
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
    print(f"  positive: {stats['positive']} "
          f"(effective {stats['positive_effective']}, "
          f"not-effective {stats['positive_not_effective']})  "
          f"negative: {stats['negative']} "
          f"(of which deliberate near-miss negatives: "
          f"{stats['near_miss_negatives']})  "
          f"excluded (needs_auth): {stats['excluded_needs_auth']}")
    for category in sorted(stats["by_category"]):
        b = stats["by_category"][category]
        print(f"  {category}: +{b['positive']} / -{b['negative']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
