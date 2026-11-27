#!/usr/bin/env python3
"""Score a scanner run against a ground-truth file.

Counts UNIQUE BUGS, not findings: findings are normalized to endpoint
templates (/users/v1/{username}) and scored by (template, parameter,
category). Four Confirmed SQLi rows on the same sink with different
username values are ONE bug, not four.

Input:
  --ground-truth  YAML with items: id, template, parameter, category,
                  how_verified, date, added_after_scan
  --findings      findings .txt from a scan run (lines like
                  "[Confirmed] CRITICAL SQL_Injection :: <url> (score=100.0)")
  --run-name      label for this run (e.g. vampi-vuln-2026-11-27)
  --out-dir       where to store the dated result files (default: alongside
                  the findings file)

Output: a dated JSON + markdown report with TP / FN / FP, Confirmed and
Suspected reported separately, plus the list of missed bugs. Precision
and recall are computed on unique bugs.

Usage:
  python3 score_scan.py --ground-truth ground-truth.yaml \
      --findings vuln/findings4.txt --run-name vampi-vuln
"""
import argparse
import json
import re
import sys
import urllib.parse
from datetime import date
from pathlib import Path

import yaml

FINDING_RE = re.compile(
    # The URL may contain spaces (a raw payload in a path-appended URL,
    # e.g. /books/v1/admin' OR 1=1 --), so match it non-greedily up to
    # the trailing (score=...).
    r"^\[(Confirmed|Suspected|Informational)\]\s+\S+\s+(\S+)\s+::\s+(.+?)\s+\(score=([\d.]+)\)\s*$"
)


def template_regex(template):
    """Compile a path template into a regex: {param} matches one segment."""
    if template == "*":
        return re.compile(r"^/.*$")
    escaped = re.escape(template)
    pattern = re.sub(r"\\\{[^}]+\\\}", r"[^/]+", escaped)
    return re.compile(r"^" + pattern + r"$")


def normalize_path(url):
    path = urllib.parse.urlparse(url).path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


def load_findings(path):
    findings = []
    for line in Path(path).read_text().splitlines():
        m = FINDING_RE.match(line.strip())
        if not m:
            continue
        status, attack_type, url, score = m.groups()
        findings.append({
            "status": status,
            "attack_type": attack_type,
            "url": url,
            "path": normalize_path(url),
            "score": float(score),
        })
    return findings


def score(ground_truth_path, findings_path):
    """Score one findings file against a ground-truth YAML.

    Returns the report dict (also written to disk by main()). Counts
    unique bugs by (template, parameter, category), never raw rows.
    """
    gt = yaml.safe_load(Path(ground_truth_path).read_text())
    items = gt["items"]
    for item in items:
        item["_regex"] = template_regex(item["template"])
    findings = load_findings(findings_path)

    def matches(item, finding):
        if finding["attack_type"] != item["category"]:
            return False
        return bool(item["_regex"].match(finding["path"]))

    results = []
    tp_confirmed = tp_suspected = fn = 0
    wrong_category = []
    for item in items:
        confirmed = [f for f in findings
                     if f["status"] == "Confirmed" and matches(item, f)]
        suspected = [f for f in findings
                     if f["status"] == "Suspected" and matches(item, f)]
        if confirmed:
            verdict, tp_confirmed = "TP-Confirmed", tp_confirmed + 1
        elif suspected:
            verdict, tp_suspected = "TP-Suspected", tp_suspected + 1
        else:
            verdict, fn = "FN (missed)", fn + 1
            # Third bucket (2026-11-27): the bug WAS detected, but filed
            # under the wrong category. A proof-bearing (Confirmed) finding
            # on the item's template with a category listed in the item's
            # also_detected_by means the underlying evidence was seen — the
            # scanner found it, it just named it wrong. The item still
            # counts as FN for recall; this bucket is reported separately
            # and never improves the headline numbers.
            wc = [f for f in findings
                  if f["status"] == "Confirmed"
                  and f["attack_type"] in (item.get("also_detected_by") or [])
                  and item["_regex"].match(f["path"])]
            if wc:
                verdict = ("FN (detected, wrong category: "
                           + ", ".join(sorted({f["attack_type"] for f in wc})))
                wrong_category.append({
                    "id": item["id"], "template": item["template"],
                    "category": item["category"],
                    "detected_as": sorted({f["attack_type"] for f in wc}),
                    "finding_paths": sorted({f["path"] for f in wc}),
                })
        results.append({
            "id": item["id"],
            "template": item["template"],
            "parameter": item.get("parameter"),
            "category": item["category"],
            "verdict": verdict,
            "confirmed_findings": len(confirmed),
            "suspected_findings": len(suspected),
            "added_after_scan": bool(item.get("added_after_scan")),
        })

    # False positives: findings matching NO ground-truth item, counted as
    # unique (template-normalized path, category) pairs, not raw rows.
    fp_confirmed_pairs, fp_suspected_pairs = set(), set()
    for f in findings:
        if f["status"] not in ("Confirmed", "Suspected"):
            continue
        if any(matches(item, f) for item in items):
            continue
        key = (f["path"], f["attack_type"])
        if f["status"] == "Confirmed":
            fp_confirmed_pairs.add(key)
        else:
            fp_suspected_pairs.add(key)

    total = len(items)
    recall_confirmed = tp_confirmed / total if total else 0.0
    recall_any = (tp_confirmed + tp_suspected) / total if total else 0.0
    fp_c, fp_s = len(fp_confirmed_pairs), len(fp_suspected_pairs)
    # Precision is reported with its n (TP + FP unique bugs). Three
    # confirmations is a tiny sample — "100% precision" without n=3
    # would overstate the evidence.
    n_precision_c = tp_confirmed + fp_c
    n_precision_any = tp_confirmed + tp_suspected + fp_c + fp_s
    precision_confirmed = (tp_confirmed / n_precision_c if n_precision_c else 0.0)
    precision_any = ((tp_confirmed + tp_suspected) / n_precision_any
                     if n_precision_any else 0.0)

    return {
        "ground_truth": str(ground_truth_path),
        "findings_file": str(findings_path),
        "ground_truth_items": total,
        "raw_findings": len(findings),
        "confirmed": {
            "tp_unique_bugs": tp_confirmed,
            "fp_unique_pairs": fp_c,
            "recall": round(recall_confirmed, 3),
            "precision": round(precision_confirmed, 3),
            "precision_n": n_precision_c,
        },
        "confirmed_plus_suspected": {
            "tp_unique_bugs": tp_confirmed + tp_suspected,
            "fp_unique_pairs": fp_c + fp_s,
            "recall": round(recall_any, 3),
            "precision": round(precision_any, 3),
            "precision_n": n_precision_any,
        },
        "missed_bugs": [r for r in results if r["verdict"].startswith("FN")],
        "detected_wrong_category": wrong_category,
        "results": results,
        "false_positives": {
            "confirmed": sorted(f"{p} :: {c}" for p, c in fp_confirmed_pairs),
            "suspected": sorted(f"{p} :: {c}" for p, c in fp_suspected_pairs),
        },
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--findings", required=True)
    ap.add_argument("--run-name", required=True)
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args()

    report = score(args.ground_truth, args.findings)
    today = date.today().isoformat()
    report["run"] = args.run_name
    report["date"] = today
    total = report["ground_truth_items"]
    tp_confirmed = report["confirmed"]["tp_unique_bugs"]
    tp_suspected = (report["confirmed_plus_suspected"]["tp_unique_bugs"]
                    - tp_confirmed)
    fp_c = report["confirmed"]["fp_unique_pairs"]
    fp_s = (report["confirmed_plus_suspected"]["fp_unique_pairs"] - fp_c)
    recall_confirmed = report["confirmed"]["recall"]
    recall_any = report["confirmed_plus_suspected"]["recall"]
    precision_confirmed = report["confirmed"]["precision"]
    precision_any = report["confirmed_plus_suspected"]["precision"]
    n_precision_c = report["confirmed"]["precision_n"]
    n_precision_any = report["confirmed_plus_suspected"]["precision_n"]
    missed = report["missed_bugs"]
    wrong_category = report["detected_wrong_category"]
    results = report["results"]
    raw_findings = report["raw_findings"]
    fp_confirmed_pairs = {tuple(s.split(" :: ", 1))
                          for s in report["false_positives"]["confirmed"]}
    fp_suspected_pairs = {tuple(s.split(" :: ", 1))
                          for s in report["false_positives"]["suspected"]}

    out_dir = Path(args.out_dir) if args.out_dir else Path(args.findings).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"score-{today}-{args.run_name}"
    json_path = out_dir / f"{stem}.json"
    json_path.write_text(json.dumps(report, indent=2) + "\n")

    md = [
        f"# Score — {args.run_name} ({today})",
        "",
        f"Ground truth: {total} items ({args.ground_truth})",
        f"Findings file: {args.findings} ({raw_findings} raw rows)",
        "",
        "## Confirmed only (unique bugs)",
        f"- TP: {tp_confirmed} / {total} — recall **{recall_confirmed:.0%}**",
        f"- FP: {fp_c} unique (template, category) pairs — "
        f"precision **{precision_confirmed:.0%}** (n={n_precision_c})",
        "",
        "## Confirmed + Suspected (unique bugs)",
        f"- TP: {tp_confirmed + tp_suspected} / {total} — recall **{recall_any:.0%}**",
        f"- FP: {fp_c + fp_s} unique pairs — precision **{precision_any:.0%}** "
        f"(n={n_precision_any})",
        "",
        "## Detected, wrong category",
        "Bugs the scanner found but filed under another category. They stay "
        "FN for recall — this bucket is reported separately and never "
        "improves the headline numbers.",
    ]
    if wrong_category:
        for w in wrong_category:
            md.append(f"- {w['id']} `{w['template']}` [{w['category']}] — "
                      f"detected as {', '.join(w['detected_as'])} "
                      f"on {', '.join(w['finding_paths'])}")
    else:
        md.append("- none")
    md += ["", "## Per-item results"]
    for r in results:
        md.append(f"- {r['id']} `{r['template']}` [{r['category']}] — "
                  f"{r['verdict']} (Confirmed rows: {r['confirmed_findings']}, "
                  f"Suspected rows: {r['suspected_findings']})")
    md += ["", "## Missed bugs"]
    if missed:
        for r in missed:
            md.append(f"- {r['id']} `{r['template']}` [{r['category']}] "
                      f"(parameter: {r['parameter']})")
    else:
        md.append("- none")
    md += ["", "## False positives (unique pairs)"]
    if fp_confirmed_pairs:
        md.append("Confirmed:")
        md += [f"- {p} :: {c}" for p, c in sorted(fp_confirmed_pairs)]
    if fp_suspected_pairs:
        md.append("Suspected:")
        md += [f"- {p} :: {c}" for p, c in sorted(fp_suspected_pairs)]
    if not fp_confirmed_pairs and not fp_suspected_pairs:
        md.append("- none")
    md_path = out_dir / f"{stem}.md"
    md_path.write_text("\n".join(md) + "\n")

    print(f"Run: {args.run_name} ({today})")
    print(f"Ground truth: {total} items; raw findings: {raw_findings}")
    print(f"Confirmed: TP {tp_confirmed}, FP {fp_c}, "
          f"recall {recall_confirmed:.0%}, precision {precision_confirmed:.0%} "
          f"(n={n_precision_c})")
    print(f"Confirmed+Suspected: TP {tp_confirmed + tp_suspected}, "
          f"FP {fp_c + fp_s}, recall {recall_any:.0%}, "
          f"precision {precision_any:.0%} (n={n_precision_any})")
    print(f"Missed ({len(missed)}): " + (", ".join(r['id'] for r in missed) or "none"))
    print(f"Detected, wrong category ({len(wrong_category)}): "
          + (", ".join(w['id'] for w in wrong_category) or "none"))
    print(f"Wrote {json_path} and {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
