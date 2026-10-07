#!/usr/bin/env python3
"""Xploiter CLI — run scans and fetch results from your terminal.

Talks to the Xploiter JSON API using a personal token from
Settings > CLI token in the web app.

Usage:
    python xploiter_cli.py scan https://api.example.com --token <token>
    python xploiter_cli.py status 12 --token <token>
    python xploiter_cli.py results 12 --token <token>

Options:
    --base-url   Xploiter app URL (default: https://xploiter.onrender.com)
    --token      CLI token (or XPLOITER_TOKEN env var)
"""
import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error


def _request(base_url, token, method, path, data=None):
    url = base_url.rstrip("/") + path
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    if body:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as exc:
        try:
            detail = json.load(exc)
        except Exception:
            detail = {"message": exc.read().decode("utf-8", "replace")[:500]}
        return exc.code, detail


def cmd_scan(args):
    status, data = _request(args.base_url, args.token, "POST", "/api/scan",
                            {"target_url": args.url})
    if status != 202:
        print(f"Error {status}: {data.get('message', data)}", file=sys.stderr)
        return 1
    session_id = data["session_id"]
    print(f"Scan started: session {session_id}")
    print(f"Results: {data.get('results_url')}")
    if args.wait:
        while True:
            time.sleep(10)
            s, d = _request(args.base_url, args.token, "GET", f"/api/sessions/{session_id}")
            if s != 200:
                print(f"Polling failed ({s}); the scan may still be running.", file=sys.stderr)
                return 1
            state = (d.get("session") or {}).get("scan_status")
            done = (d.get("session") or {}).get("progress_done", 0)
            total = (d.get("session") or {}).get("progress_total", 0)
            print(f"  ... {state} ({done}/{total} endpoints)")
            if state != "running":
                print(f"Scan {state}.")
                return 0 if state == "complete" else 1
    return 0


def cmd_status(args):
    status, data = _request(args.base_url, args.token, "GET", f"/api/sessions/{args.id}")
    if status != 200:
        print(f"Error {status}: {data.get('message', data)}", file=sys.stderr)
        return 1
    s = data["session"]
    print(f"Session {s['id']}: {s['target_url']}")
    print(f"  status:   {s['scan_status']}")
    print(f"  progress: {s['progress_done']}/{s['progress_total']} ({s['progress_stage']})")
    print(f"  score:    {s['overall_risk_score']} ({s['overall_severity']})")
    print(f"  findings: {s['total_vulnerabilities_found']} across {len(data['endpoints'])} endpoints")
    return 0


def cmd_results(args):
    status, data = _request(args.base_url, args.token, "GET", f"/api/sessions/{args.id}")
    if status != 200:
        print(f"Error {status}: {data.get('message', data)}", file=sys.stderr)
        return 1
    s = data["session"]
    print(f"Results for session {s['id']} ({s['target_url']}) — score {s['overall_risk_score']}/100 [{s['overall_severity']}]")
    for f in data.get("findings", []):
        print(f"  [{f['severity']}/{f['finding_status']}] {f['attack_type']} — {f['url']} (risk {f['risk_score']})")
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Xploiter CLI")
    parser.add_argument("--base-url", default=os.getenv("XPLOITER_URL", "https://xploiter.onrender.com"))
    parser.add_argument("--token", default=os.getenv("XPLOITER_TOKEN", ""))
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Start a scan")
    p_scan.add_argument("url", help="Target API base URL")
    p_scan.add_argument("--wait", action="store_true", help="Poll until the scan finishes")

    p_status = sub.add_parser("status", help="Show scan progress")
    p_status.add_argument("id", type=int, help="Session ID")

    p_results = sub.add_parser("results", help="Show scan findings")
    p_results.add_argument("id", type=int, help="Session ID")
    p_results.add_argument("--json", action="store_true", help="Dump the full JSON payload")

    args = parser.parse_args(argv)
    if not args.token:
        print("A CLI token is required: --token <token> or XPLOITER_TOKEN env var.\n"
              "Generate one in the web app under Settings > CLI token.", file=sys.stderr)
        return 2
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "status":
        return cmd_status(args)
    if args.command == "results":
        return cmd_results(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
