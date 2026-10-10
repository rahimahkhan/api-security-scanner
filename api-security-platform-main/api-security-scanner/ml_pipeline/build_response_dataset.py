"""Build the benign/anomalous response-telemetry dataset for Layer-2/3 training.

Reproducible recipe (run: `python ml_pipeline/build_response_dataset.py`):

1. LIVE BENIGN — send harmless baseline-style probes (empty / plain-text
   payloads) through the same request path the scanner uses, against stable
   public endpoints (httpbin.org, example.com, postman-echo.com). Each probe
   is paired with its own baseline request so differential features are real.
2. SYNTHETIC BENIGN — jitter the live samples (size ±8%, time × U(0.7,1.4),
   tiny body edits) to widen the benign distribution without leaving the
   "normal response" manifold.
3. SYNTHETIC ANOMALOUS — derive from real benign samples by injecting the
   response signatures of real exploits: SQL error page (500 + error text),
   reflected payload, 5s time delay, Python traceback, empty 500.

Output: ml_pipeline/datasets/response_diff_v1.csv with one row per probe,
columns = FEATURE_KEYS + label (0 benign / 1 anomalous) + source.

The Isolation Forest trains on label==0 rows only (novelty detection);
the supervised ranker and the autoencoder threshold use both classes.
"""

import csv
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from ml_pipeline.feature_extractor import FEATURE_KEYS, extract_response_features

DATASET_PATH = ROOT_DIR / "ml_pipeline" / "datasets" / "response_diff_v1.csv"

# Stable public endpoints for live benign telemetry. Plain GETs with harmless
# payloads only — nothing attack-like ever leaves this machine.
LIVE_TARGETS: List[Tuple[str, str]] = [
    ("GET", "https://httpbin.org/get"),
    ("GET", "https://httpbin.org/json"),
    ("GET", "https://httpbin.org/html"),
    ("GET", "https://httpbin.org/status/200"),
    ("GET", "https://httpbin.org/response-headers?x-test=1"),
    ("GET", "https://example.com/"),
    ("GET", "https://postman-echo.com/get"),
]

BENIGN_PAYLOADS = ["", "hello", "test123", "q=search+term", "page=2", "name=alice"]

ANOMALY_TEMPLATES = {
    "sql_error": {
        "status_code": 500,
        "body_suffix": "\nSQL syntax error near ''{p}'' at line 1\n"
                       "mysql_fetch_array() expects parameter 1 to be resource, boolean given\n",
        "content_type": "text/html",
    },
    "traceback": {
        "status_code": 500,
        "body_suffix": '\nTraceback (most recent call last):\n  File "app.py", line 42, in get_user\n'
                       "    cursor.execute(query)\n"
                       'sqlite3.OperationalError: near "{p}": syntax error\n',
        "content_type": "text/html",
    },
    "reflected": {
        "status_code": 200,
        "body_suffix": "\n<div>Search results for: {p}</div>\n",
        "content_type": "text/html",
    },
    "empty_500": {
        "status_code": 500,
        "body_suffix": "",
        "content_type": "text/plain",
    },
}


def _send(method: str, url: str, payload: str = "", timeout: float = 15.0) -> Dict[str, Any]:
    """Send one benign probe and return scanner-style telemetry."""
    import requests

    target_url = url
    data = None
    if payload and method.upper() == "GET":
        sep = "&" if "?" in target_url else "?"
        target_url = f"{target_url}{sep}q={payload}"
    elif payload:
        data = payload
    started = time.monotonic()
    try:
        resp = requests.request(
            method, target_url, data=data,
            headers={"User-Agent": "XploiterDatasetBuilder/1.0", "Accept": "*/*"},
            timeout=timeout,
        )
        elapsed = time.monotonic() - started
        body = resp.text or ""
        return {
            "method": method.upper(),
            "url": url,
            "payload": payload,
            "status_code": resp.status_code,
            "response_size": len(body.encode("utf-8", "replace")),
            "response_time": round(elapsed, 4),
            "response_body": body,
            "response_headers": dict(resp.headers),
        }
    except Exception as exc:  # network hiccup: skip this sample, don't poison data
        print(f"    [!] probe failed ({url}): {exc}")
        return {}


def collect_live_benign() -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Return (baseline, probe) telemetry pairs from live benign requests."""
    pairs: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for method, url in LIVE_TARGETS:
        baseline = _send(method, url, "")
        if not baseline or baseline.get("status_code") != 200:
            continue
        for payload in BENIGN_PAYLOADS:
            probe = _send(method, url, payload)
            if not probe:
                continue
            probe["method"] = baseline["method"]
            probe["url"] = baseline["url"]
            pairs.append((baseline, probe))
            time.sleep(0.3)  # be polite to public endpoints
    return pairs


def synthesize_benign(pairs: List[Tuple[Dict[str, Any], Dict[str, Any]]],
                      per_pair: int = 8, seed: int = 7) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Jitter live pairs to widen the benign distribution."""
    rng = random.Random(seed)
    out: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for baseline, probe in pairs:
        for _ in range(per_pair):
            jittered = dict(probe)
            size = probe["response_size"]
            jittered["response_size"] = max(0, int(size * rng.uniform(0.92, 1.08)))
            jittered["response_time"] = round(max(0.01, probe["response_time"] * rng.uniform(0.7, 1.4)), 4)
            if rng.random() < 0.3:
                jittered["status_code"] = rng.choice([200, 200, 200, 201, 204, 301])
            out.append((baseline, jittered))
    return out


def synthesize_anomalies(pairs: List[Tuple[Dict[str, Any], Dict[str, Any]]],
                         seed: int = 21) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Derive exploit-signature anomalies from real benign pairs."""
    rng = random.Random(seed)
    attack_payloads = [
        "' OR '1'='1", "<script>alert(1)</script>", "'; DROP TABLE users--",
        "../../etc/passwd", "' UNION SELECT password FROM users--",
    ]
    out: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    templates = list(ANOMALY_TEMPLATES.items())
    for baseline, probe in pairs:
        # One anomaly per template kind so every exploit signature is covered.
        for kind, tmpl in templates:
            payload = rng.choice(attack_payloads)
            evil = dict(probe)
            evil["payload"] = payload
            suffix = tmpl["body_suffix"].format(p=payload)
            evil["response_body"] = probe["response_body"] + suffix
            evil["response_size"] = len(evil["response_body"].encode("utf-8", "replace"))
            evil["status_code"] = tmpl["status_code"]
            evil["response_headers"] = dict(probe.get("response_headers") or {})
            evil["response_headers"]["Content-Type"] = tmpl["content_type"]
            out.append((baseline, evil))

        # Time-based variants: same body as baseline, big delay.
        for _ in range(2):
            payload = rng.choice(attack_payloads)
            slow = dict(probe)
            slow["payload"] = payload
            slow["response_time"] = round(probe["response_time"] + rng.uniform(4.5, 6.5), 4)
            out.append((baseline, slow))
    return out


def build_dataset() -> Path:
    print("[+] Collecting live benign telemetry (this takes ~1-2 minutes)...")
    live_pairs = collect_live_benign()
    print(f"    live (baseline, probe) pairs: {len(live_pairs)}")
    if not live_pairs:
        raise RuntimeError("No live telemetry collected — check network/proxy settings.")

    benign_pairs = live_pairs + synthesize_benign(live_pairs)
    anomaly_pairs = synthesize_anomalies(live_pairs)
    print(f"    benign pairs: {len(benign_pairs)}, anomalous pairs: {len(anomaly_pairs)}")

    rows: List[Dict[str, Any]] = []
    for baseline, probe in benign_pairs:
        feats = extract_response_features(probe, baseline)
        rows.append({k: feats[k] for k in FEATURE_KEYS} | {"label": 0, "source": "benign"})
    for baseline, probe in anomaly_pairs:
        feats = extract_response_features(probe, baseline)
        rows.append({k: feats[k] for k in FEATURE_KEYS} | {"label": 1, "source": "anomalous"})

    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(DATASET_PATH, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FEATURE_KEYS + ["label", "source"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] Dataset written: {DATASET_PATH} ({len(rows)} rows)")
    return DATASET_PATH


if __name__ == "__main__":
    build_dataset()
