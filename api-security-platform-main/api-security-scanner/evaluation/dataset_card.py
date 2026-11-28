"""Generate a dataset manifest (card) for one dataset version.

Reads the labeled JSONL files listed in evaluation/dataset-sessions.yaml
and writes evaluation/dataset-card-<version>.md and .json.

The sessions file is the human-maintained record: per session, the app,
tier, mode, scanner commit, harness commit and run date. This script
computes the counts and the file hashes from the labeled files, so the
manifest is derived, not hand-filled. A session marked ``excluded`` or
``superseded`` is listed with its reason and left out of the counts —
superseded records are removed from the dataset, never just ignored
(the same endpoint must not appear twice with different timing, which
would leak between folds).

Counts: by app, by tier, by category; positives, effective positives,
near-miss negatives. Review rules applied are printed from RULES below
(see evaluation/METHODOLOGY.md for the full text).

Usage:
    python3 evaluation/dataset_card.py
        [--sessions evaluation/dataset-sessions.yaml]
        [--out-dir evaluation]
"""

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

# Review rules applied to every version of this dataset. The full text
# lives in evaluation/METHODOLOGY.md; these one-liners are what the card
# records, so a reader can check which rules a version was built under.
RULES = {
    "incidental": (
        "Incidental findings (METHODOLOGY.md §5): a Confirmed finding not "
        "in the ground truth is checked by hand against request + response; "
        "if real and unlisted it becomes an incidental GT item (never a TP "
        "or FP in scoring, labeled 1 for training); if not real it is a "
        "precision defect to fix. Counts are reported before and after review."
    ),
    "near_miss": (
        "Near-misses (METHODOLOGY.md §2): a bench near-miss qualifies as an "
        "explicit negative only as a separately reachable endpoint with a "
        "matching scanner category, verified in the app's source. Pairs on "
        "one label 0 with near_miss=true; findings on one count as FP."
    ),
    "mode_scoped_labeling": (
        "Mode-scoped labeling: a GT item only labels runs in its modes list "
        "(e.g. a bug real in vulnerable mode and absent in safe mode is a "
        "positive in one and a negative in the other). needs_auth pairs are "
        "excluded entirely, never labeled 0. Labels come only from the "
        "ground-truth join on (template, parameter, category), never from "
        "the scanner's own verdict."
    ),
    "grouping": (
        "Grouping: each vulnerable app and its patched twin are ONE group "
        "for splitting; training on one and testing on the other is leakage."
    ),
}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def summarize(records):
    """Counts for one list of labeled records (pure function, tested)."""
    total = len(records)
    positive = sum(1 for r in records if r.get("label") == 1)
    positive_effective = sum(
        1 for r in records
        if r.get("label") == 1 and r.get("probe_effective")
    )
    near_miss_negatives = sum(
        1 for r in records
        if r.get("label") == 0 and r.get("near_miss")
    )
    by_category = defaultdict(lambda: {"positive": 0, "negative": 0})
    for r in records:
        cat = r.get("category") or _category_of(r)
        bucket = by_category[cat]
        if r.get("label") == 1:
            bucket["positive"] += 1
        else:
            bucket["negative"] += 1
    return {
        "pairs": total,
        "positive": positive,
        "positive_effective": positive_effective,
        "negative": total - positive,
        "near_miss_negatives": near_miss_negatives,
        "by_category": dict(sorted(by_category.items())),
    }


def _category_of(record):
    """Category of a labeled record, from the probe type when unstated."""
    probe_type = record.get("probe_type", "")
    mapping = {
        "SQL_Injection_GET": "SQL_Injection",
        "SQL_Injection_Time": "SQL_Injection",
        "SQL_Injection_Error": "SQL_Injection",
        "Cross_Site_Scripting": "XSS",
        "Command_Injection_Time": "Command_Injection",
    }
    return mapping.get(probe_type, probe_type)


def build_manifest(sessions_path):
    doc = yaml.safe_load(Path(sessions_path).read_text())
    version = doc["version"]
    sessions = doc["sessions"]
    included = [s for s in sessions if s.get("status", "included") == "included"]
    excluded = [s for s in sessions if s.get("status", "included") != "included"]

    per_session = []
    all_records = []
    combined_hash = hashlib.sha256()
    for s in included:
        path = Path(s["file"])
        records = [json.loads(line) for line in open(path) if line.strip()]
        file_hash = sha256_file(path)
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                combined_hash.update(chunk)
        summary = summarize(records)
        summary.update({
            "session_id": s["id"],
            "app": s["app"],
            "tier": s["tier"],
            "mode": s["mode"],
            "scanner_commit": s.get("scanner_commit", "unknown"),
            "harness_commit": s.get("harness_commit", "unknown"),
            "run_date": s.get("run_date", "unknown"),
            "labeled_date": s.get("labeled_date", "unknown"),
            "file": str(path),
            "file_sha256": file_hash,
        })
        per_session.append(summary)
        all_records.extend(records)

    total = summarize(all_records)
    by_app = defaultdict(lambda: {"pairs": 0, "positive": 0})
    by_tier = defaultdict(lambda: {"pairs": 0, "positive": 0})
    for s in per_session:
        by_app[s["app"]]["pairs"] += s["pairs"]
        by_app[s["app"]]["positive"] += s["positive"]
        by_tier[s["tier"]]["pairs"] += s["pairs"]
        by_tier[s["tier"]]["positive"] += s["positive"]

    return {
        "version": version,
        "generated_by": "evaluation/dataset_card.py",
        "sessions_file": str(sessions_path),
        "totals": total,
        "by_app": dict(sorted(by_app.items())),
        "by_tier": dict(sorted(by_tier.items())),
        "combined_sha256": combined_hash.hexdigest(),
        "sessions": per_session,
        "excluded": [
            {k: s.get(k) for k in
             ("id", "app", "tier", "mode", "status", "reason", "superseded_by")}
            for s in excluded
        ],
        "review_rules": RULES,
    }


def render_markdown(manifest):
    t = manifest["totals"]
    lines = [
        f"# Dataset card — {manifest['version']}",
        "",
        f"Generated by `{manifest['generated_by']}` from "
        f"`{manifest['sessions_file']}`.",
        "",
        "## Totals",
        "",
        f"- Pairs: **{t['pairs']}**; positive: **{t['positive']}** "
        f"({t['positive_effective']} effective); "
        f"negative: {t['negative']} "
        f"(of which deliberate near-miss negatives: "
        f"{t['near_miss_negatives']}).",
        f"- Combined sha256 of the included labeled files: "
        f"`{manifest['combined_sha256']}`.",
        "",
        "## By app",
        "",
    ]
    for app, c in manifest["by_app"].items():
        lines.append(f"- {app}: {c['pairs']} pairs, {c['positive']} positive.")
    lines += ["", "## By tier", ""]
    for tier, c in manifest["by_tier"].items():
        lines.append(f"- {tier}: {c['pairs']} pairs, {c['positive']} positive.")
    lines += ["", "## By category", ""]
    for cat, c in t["by_category"].items():
        lines.append(f"- {cat}: +{c['positive']} / -{c['negative']}.")
    lines += ["", "## Sessions", ""]
    for s in manifest["sessions"]:
        lines.append(
            f"- Session {s['session_id']} ({s['app']}, {s['tier']}, "
            f"mode {s['mode']}): {s['pairs']} pairs, {s['positive']} "
            f"positive ({s['positive_effective']} effective). "
            f"Scanner commit `{s['scanner_commit']}`, harness commit "
            f"`{s['harness_commit']}`, run {s['run_date']}, labeled "
            f"{s['labeled_date']}. File `{s['file']}`, "
            f"sha256 `{s['file_sha256']}`."
        )
    if manifest["excluded"]:
        lines += ["", "## Excluded sessions (not in the counts)", ""]
        for s in manifest["excluded"]:
            lines.append(
                f"- Session {s.get('id')} ({s.get('app')}, "
                f"{s.get('tier')}, mode {s.get('mode')}): "
                f"status {s.get('status')}"
                + (f", superseded by session {s['superseded_by']}"
                   if s.get("superseded_by") else "")
                + (f" — {s['reason']}" if s.get("reason") else ".")
            )
    lines += ["", "## Review rules applied", ""]
    for name, text in manifest["review_rules"].items():
        lines.append(f"- **{name}**: {text}")
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sessions", default="evaluation/dataset-sessions.yaml")
    ap.add_argument("--out-dir", default="evaluation")
    args = ap.parse_args()

    manifest = build_manifest(args.sessions)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / f"dataset-card-{manifest['version']}.md"
    json_path = out_dir / f"dataset-card-{manifest['version']}.json"
    md_path.write_text(render_markdown(manifest))
    json_path.write_text(json.dumps(manifest, indent=2) + "\n")
    t = manifest["totals"]
    print(f"wrote {md_path} and {json_path}")
    print(f"  {t['pairs']} pairs, {t['positive']} positive "
          f"({t['positive_effective']} effective), "
          f"{t['near_miss_negatives']} near-miss negatives; "
          f"{len(manifest['sessions'])} sessions included, "
          f"{len(manifest['excluded'])} excluded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
