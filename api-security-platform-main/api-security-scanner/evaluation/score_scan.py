#!/usr/bin/env python3
"""Score a scanner run against a ground-truth file.

Counts UNIQUE BUGS, not findings: findings are normalized to endpoint
templates (/users/v1/{username}) and scored by (template, parameter,
category). Four Confirmed SQLi rows on the same sink with different
username values are ONE bug, not four.

Input:
  --ground-truth  YAML with items: id, template, parameter, category,
                  how_verified, date, added_after_scan, modes — plus an
                  optional needs_auth list: bugs that exist but whose
                  routes need a logged-in user. They are never scored
                  (never TP, never missed), and a finding on one is
                  reported separately, never counted as an FP.
  --findings      findings .txt from a scan run (lines like
                  "[Confirmed] CRITICAL SQL_Injection :: <url> (score=100.0)")
  --run-name      label for this run (e.g. vampi-vuln-2026-11-27)
  --mode          run mode to score in (e.g. vulnerable, safe). Items whose
                  `modes` list does not contain it are excluded — a safe
                  twin has none of the vulnerable-mode bugs, so scoring it
                  against the full list reports phantom "TP" matches on
                  findings that are false alarms by construction. Items
                  with no `modes` list match any mode. Omit for the old
                  behaviour (all items apply).
  --out-dir       where to store the dated result files (default: alongside
                  the findings file)
  --surface       SURFACE.yaml for the target app (DynaST's own endpoint
                  catalog) and --discovered <file>: the endpoints the scan
                  actually found — a raw dataset JSONL (endpoint_url +
                  http_method per pair) or a text file with one URL per
                  line (optionally "METHOD URL"). With both, the report
                  splits recall in two (Claude's 2026-11-27 finding that
                  discovery limits recall more than detection): Part 1,
                  discovery recall = surface operations found / total;
                  Part 2, detection given found = ground-truth items on
                  found endpoints that were detected. Misses split into
                  missed-by-discovery vs missed-despite-found.

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


def load_surface(path):
    """DynaST SURFACE.yaml: the app's endpoint catalog (the discovery
    denominator). Returns [{id, method, path, reachability}]."""
    data = yaml.safe_load(Path(path).read_text())
    ops = []
    for op in data.get("operations", []):
        if op.get("kind", "http") != "http":
            continue
        ops.append({
            "id": op.get("id", "?"),
            "method": (op.get("method") or "").upper(),
            "path": op.get("path", ""),
            "reachability": op.get("reachability"),
        })
    return ops


_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def load_discovered(path):
    """Endpoints the scan actually found, as a set of
    (method-or-None, normalized-path) pairs. Accepts a raw dataset JSONL
    (endpoint_url + http_method per pair) or a text file with one URL per
    line, optionally prefixed with the method ("GET /api/x")."""
    found = set()
    text = Path(path).read_text()
    if str(path).endswith(".jsonl"):
        for line in text.splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            url = r.get("endpoint_url") or ""
            method = (r.get("http_method") or "").upper() or None
            if url:
                found.add((method, normalize_path(url)))
        return found
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].upper() in _METHODS:
            found.add((parts[0].upper(), normalize_path(parts[1])))
        else:
            found.add((None, normalize_path(line)))
    return found


def score(ground_truth_path, findings_path, mode=None,
          surface_path=None, discovered_path=None):
    """Score one findings file against a ground-truth YAML.

    Returns the report dict (also written to disk by main()). Counts
    unique bugs by (template, parameter, category), never raw rows.
    When `mode` is given, only ground-truth items whose `modes` list
    contains it (or that have no `modes` list) are scored — a safe-twin
    run scored without this reports phantom TP matches on findings that
    are false alarms by construction.
    """
    gt = yaml.safe_load(Path(ground_truth_path).read_text())
    items = gt["items"]
    # needs_auth (2026-11-27): bugs that exist but need a login. They are
    # not scored items, and a finding on one is neither a TP nor an FP —
    # it goes in its own bucket below.
    needs_auth = gt.get("needs_auth", [])
    if mode:
        items = [it for it in items
                 if not it.get("modes") or mode in it["modes"]]
    # Incidental items (2026-11-28): real bugs the bench's answer key
    # does not list, found on a safe twin and verified with request +
    # response. They are NOT scored items — a finding on one is neither
    # a TP nor an FP — it goes in its own bucket below.
    incidental = [it for it in items if it.get("incidental")]
    items = [it for it in items if not it.get("incidental")]
    for item in items:
        item["_regex"] = template_regex(item["template"])
    for inc in incidental:
        inc["_regex"] = template_regex(inc["template"])
    for na in needs_auth:
        na["_regex"] = template_regex(na["template"])
    findings = load_findings(findings_path)
    # Two-part recall (2026-11-27): discovery vs detection. Only when
    # both inputs are given; otherwise the report is unchanged.
    surface_ops, discovered = None, None
    if surface_path and discovered_path:
        surface_ops = load_surface(surface_path)
        for op in surface_ops:
            op["_regex"] = template_regex(op["path"])
        discovered = load_discovered(discovered_path)
    discovered_paths = {p for (_, p) in discovered} if discovered else None

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
            "discovered": (None if discovered_paths is None else
                           any(item["_regex"].match(p)
                               for p in discovered_paths)),
        })

    # False positives: findings matching NO ground-truth item, counted as
    # unique (template-normalized path, category) pairs, not raw rows.
    # Findings on a needs_auth template are not false alarms — the bug
    # exists there, the scanner just cannot reach it without a login —
    # so they go in their own bucket, never into FP.
    fp_confirmed_pairs, fp_suspected_pairs = set(), set()
    needs_auth_pairs = set()
    incidental_pairs = set()
    for f in findings:
        if f["status"] not in ("Confirmed", "Suspected"):
            continue
        if any(matches(item, f) for item in items):
            continue
        if any(matches(inc, f) for inc in incidental):
            incidental_pairs.add((f["path"], f["attack_type"]))
            continue
        if any(matches(na, f) for na in needs_auth):
            needs_auth_pairs.add((f["path"], f["attack_type"]))
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
    # Part 1 (discovery recall) and Part 2 (detection given found).
    discovery = None
    if surface_ops is not None and discovered is not None:
        def op_found(op):
            return any((m is None or m == op["method"])
                       and op["_regex"].match(p)
                       for (m, p) in discovered)
        found_ops = [op for op in surface_ops if op_found(op)]
        pre_ops = [op for op in surface_ops
                   if op.get("reachability") == "pre-auth"]
        pre_found = [op for op in pre_ops if op_found(op)]
        found_results = [r for r in results if r["discovered"]]
        tp_found_c = sum(1 for r in found_results
                         if r["verdict"] == "TP-Confirmed")
        tp_found_any = sum(1 for r in found_results
                           if r["verdict"].startswith("TP"))
        discovery = {
            "surface_operations": len(surface_ops),
            "found_operations": len(found_ops),
            "discovery_recall": round(
                len(found_ops) / len(surface_ops), 3) if surface_ops else 0.0,
            "pre_auth_operations": len(pre_ops),
            "pre_auth_found": len(pre_found),
            "pre_auth_recall": round(
                len(pre_found) / len(pre_ops), 3) if pre_ops else 0.0,
            "missed_operations": sorted(
                f"{op['method']} {op['path']}" for op in surface_ops
                if not op_found(op)),
            "ground_truth_on_found_endpoints": len(found_results),
            "detected_given_found_confirmed": {
                "tp": tp_found_c, "total": len(found_results),
                "recall": round(tp_found_c / len(found_results), 3)
                          if found_results else 0.0,
            },
            "detected_given_found_any": {
                "tp": tp_found_any, "total": len(found_results),
                "recall": round(tp_found_any / len(found_results), 3)
                          if found_results else 0.0,
            },
            "missed_by_discovery": [r["id"] for r in results
                                    if not r["discovered"]],
            "missed_despite_found": [
                r["id"] for r in results
                if r["discovered"] and r["verdict"].startswith("FN")],
        }
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
        "mode": mode,
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
        "needs_auth_items": len(needs_auth),
        "needs_auth_matches": sorted(f"{p} :: {c}"
                                     for p, c in needs_auth_pairs),
        "incidental_items": len(incidental),
        "incidental_matches": sorted(f"{p} :: {c}"
                                     for p, c in incidental_pairs),
        "discovery": discovery,
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
    ap.add_argument("--mode", default=None,
                    help="run mode to score in (e.g. vulnerable, safe); "
                         "ground-truth items not listed for this mode "
                         "are excluded")
    ap.add_argument("--surface", default=None,
                    help="SURFACE.yaml for the target app (DynaST's "
                         "endpoint catalog — the discovery denominator)")
    ap.add_argument("--discovered", default=None,
                    help="endpoints the scan found: a raw dataset JSONL "
                         "or a text file with one URL per line "
                         "(optionally 'METHOD URL')")
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args()

    report = score(args.ground_truth, args.findings, mode=args.mode,
                   surface_path=args.surface,
                   discovered_path=args.discovered)
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
    ]
    if args.mode:
        md.append(f"Mode: {args.mode} (ground-truth items filtered to this mode)")
    if args.mode and total == 0:
        md.append("")
        md.append("**No ground-truth items apply in this mode — every "
                  "Confirmed/Suspected finding is a false alarm by "
                  "construction. Recall is meaningless here; the FP "
                  "counts below are the false-alarm rate.**")
    md += [
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
    md += ["", "## Findings on needs_auth items"]
    md.append("The bug exists here, but the route needs a login the "
              "scanner never has — so these are neither TP nor FP.")
    if report["needs_auth_matches"]:
        md += [f"- {s}" for s in report["needs_auth_matches"]]
    else:
        md.append("- none")
    md += ["", "## Incidental findings (verified, unlisted bugs)"]
    md.append("Real bugs the bench's answer key does not list, verified "
              "with request + response on a safe twin — so these are "
              "neither TP nor FP, and pairs on them are labeled 1.")
    if report["incidental_matches"]:
        md += [f"- {s}" for s in report["incidental_matches"]]
    else:
        md.append("- none")
    disc = report.get("discovery")
    if disc:
        md += ["", "## Two-part recall (discovery vs detection)"]
        md.append(f"- Discovery: found {disc['found_operations']}/"
                  f"{disc['surface_operations']} surface operations — "
                  f"recall **{disc['discovery_recall']:.0%}** "
                  f"(pre-auth {disc['pre_auth_found']}/"
                  f"{disc['pre_auth_operations']}, "
                  f"{disc['pre_auth_recall']:.0%})")
        md.append(f"- Detection given found: Confirmed "
                  f"{disc['detected_given_found_confirmed']['tp']}/"
                  f"{disc['detected_given_found_confirmed']['total']} "
                  f"({disc['detected_given_found_confirmed']['recall']:.0%}), "
                  f"Confirmed+Suspected "
                  f"{disc['detected_given_found_any']['tp']}/"
                  f"{disc['detected_given_found_any']['total']} "
                  f"({disc['detected_given_found_any']['recall']:.0%})")
        md.append("- Missed by discovery (endpoint never found): "
                  + (", ".join(f"`{i}`" for i in disc["missed_by_discovery"])
                     or "none"))
        md.append("- Missed despite found (detection misses): "
                  + (", ".join(f"`{i}`" for i in disc["missed_despite_found"])
                     or "none"))
        md.append("- Missed surface operations:")
        if disc["missed_operations"]:
            md += [f"  - `{o}`" for o in disc["missed_operations"]]
        else:
            md.append("  - none")
    md_path = out_dir / f"{stem}.md"
    md_path.write_text("\n".join(md) + "\n")

    print(f"Run: {args.run_name} ({today})")
    print(f"Ground truth: {total} items; raw findings: {raw_findings}")
    if args.mode and total == 0:
        print(f"No ground-truth items apply in mode '{args.mode}' — "
              f"every finding is a false alarm by construction.")
    print(f"Confirmed: TP {tp_confirmed}, FP {fp_c}, "
          f"recall {recall_confirmed:.0%}, precision {precision_confirmed:.0%} "
          f"(n={n_precision_c})")
    print(f"Confirmed+Suspected: TP {tp_confirmed + tp_suspected}, "
          f"FP {fp_c + fp_s}, recall {recall_any:.0%}, "
          f"precision {precision_any:.0%} (n={n_precision_any})")
    print(f"Missed ({len(missed)}): " + (", ".join(r['id'] for r in missed) or "none"))
    print(f"Detected, wrong category ({len(wrong_category)}): "
          + (", ".join(w['id'] for w in wrong_category) or "none"))
    print(f"Needs_auth matches ({len(report['needs_auth_matches'])}): "
          + (", ".join(report["needs_auth_matches"]) or "none"))
    print(f"Incidental matches ({len(report['incidental_matches'])}): "
          + (", ".join(report["incidental_matches"]) or "none"))
    disc = report.get("discovery")
    if disc:
        print(f"Discovery: found {disc['found_operations']}/"
              f"{disc['surface_operations']} surface operations "
              f"(recall {disc['discovery_recall']:.0%}; pre-auth "
              f"{disc['pre_auth_found']}/{disc['pre_auth_operations']}, "
              f"{disc['pre_auth_recall']:.0%})")
        print(f"Detection given found: Confirmed "
              f"{disc['detected_given_found_confirmed']['tp']}/"
              f"{disc['detected_given_found_confirmed']['total']} "
              f"({disc['detected_given_found_confirmed']['recall']:.0%}), "
              f"Confirmed+Suspected "
              f"{disc['detected_given_found_any']['tp']}/"
              f"{disc['detected_given_found_any']['total']} "
              f"({disc['detected_given_found_any']['recall']:.0%})")
        print(f"Missed by discovery: "
              + (", ".join(disc["missed_by_discovery"]) or "none"))
        print(f"Missed despite found: "
              + (", ".join(disc["missed_despite_found"]) or "none"))
    print(f"Wrote {json_path} and {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
