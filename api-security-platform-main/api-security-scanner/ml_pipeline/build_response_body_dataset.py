"""Build the response-body LSTM corpus v1 — FINAL, label-reviewed.

Sources (all real HTTP responses captured live):
  live:*   public test services via curl (httpbin, example.com, postman-echo)
  gt:*     local ground-truth app (planted vulns)
  vampi:*  VAmPI vulnerable API (vulnerable=1)

Label rules (reviewed body-by-body after capture):
  0 = normal application response, incl. safely-escaped echoes, ordinary
      auth failures (401 / 'user does not exist'), and attack inputs the app
      handled safely (normal-shaped response).
  1 = exploit-effect response: SQL error text, sensitive data dump
      (/_debug user list with passwords), unescaped attack reflection,
      open-redirect page to an external URL.
  Ambiguous captures whose body is indistinguishable from a normal response
  (VAmPI SQLi-login returning 'Username does not exist'; SQLi-user returning
  a normal single-user record) are DROPPED, never guessed.
"""
import csv
import json
import os
import subprocess
import sys
import time

ORIGINAL_ENV = dict(os.environ)  # curl needs the proxy vars; httpx must not see them
for var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
            "ALL_PROXY", "all_proxy", "no_proxy", "NO_PROXY"):
    os.environ.pop(var, None)

import httpx

APP_DIR = "/home/hatch/workspace/api-security-scanner/api-security-platform-main/api-security-scanner"
GT = "http://127.0.0.1:5123"
V = "http://127.0.0.1:5000"
rows = []


def ensure_targets():
    def up(url):
        try:
            return httpx.get(url, timeout=3).status_code == 200
        except Exception:
            return False
    if not up(f"{GT}/clean"):
        subprocess.Popen(["nohup", f"{APP_DIR}/venv/bin/python",
                          "/home/hatch/workspace/tmp/ground_truth/app.py"],
                         stdout=open("/tmp/gt.log", "w"), stderr=subprocess.STDOUT,
                         env={k: v for k, v in os.environ.items()})
    if not up(f"{V}/users/v1"):
        subprocess.Popen(["nohup", "./venv/bin/python", "app.py"],
                         cwd="/home/hatch/workspace/api-security-scanner/api-security-platform-main/VAmPI",
                         stdout=open("/tmp/vampi.log", "w"), stderr=subprocess.STDOUT,
                         env={**os.environ, "vulnerable": "1"})
    for _ in range(20):
        if up(f"{GT}/clean") and up(f"{V}/users/v1"):
            return
        time.sleep(1)
    raise SystemExit("targets did not come up")


def cap(method, url, label, source, **kw):
    try:
        r = httpx.request(method, url, timeout=15, follow_redirects=False, **kw)
        rows.append(((r.text or "")[:4000], label, f"{source}[{r.status_code}]"))
        print(f"  {source:26s} label={label} status={r.status_code} len={len(r.text or '')}")
    except Exception as exc:
        print(f"  {source:26s} FAILED: {exc}")


def curl(url, label, source, args=None):
    cmd = ["curl", "-s", "--max-time", "25"] + (args or []) + [url]
    out = subprocess.run(cmd, capture_output=True, text=True, env=ORIGINAL_ENV).stdout
    if out:
        rows.append((out[:4000], label, source))
        print(f"  {source:26s} label={label} len={len(out)}")
    else:
        print(f"  {source:26s} FAILED (empty)")


ensure_targets()

print("== live benign (curl) ==")
curl("https://httpbin.org/get", 0, "live:httpbin-get")
curl("https://httpbin.org/get?book=harry+potter&page=2", 0, "live:httpbin-get-q")
curl("https://httpbin.org/json", 0, "live:httpbin-json")
curl("https://httpbin.org/html", 0, "live:httpbin-html")
curl("https://httpbin.org/xml", 0, "live:httpbin-xml")
curl("https://httpbin.org/robots.txt", 0, "live:httpbin-robots")
curl("https://httpbin.org/deny", 0, "live:httpbin-deny")
curl("https://httpbin.org/headers", 0, "live:httpbin-headers")
curl("https://httpbin.org/uuid", 0, "live:httpbin-uuid")
curl("https://httpbin.org/forms/post", 0, "live:httpbin-form")
curl("https://example.com/", 0, "live:example")
curl("https://postman-echo.com/get?item=notebook&qty=2", 0, "live:echo-get")
curl("https://postman-echo.com/post", 0, "live:echo-post",
     ["-X", "POST", "-H", "Content-Type: application/json", "-d", '{"name":"alice","item":"notebook","qty":2}'])
# malformed JSON in, normal echo out -> benign hard negative (reviewed)
curl("https://postman-echo.com/post", 0, "live:echo-badjson-normal",
     ["-X", "POST", "-H", "Content-Type: application/json", "-d", "{not json!!"])

print("== ground truth benign ==")
cap("GET", f"{GT}/clean", 0, "gt:clean")
cap("GET", f"{GT}/search?q=shoes", 0, "gt:search")
cap("GET", f"{GT}/search?q=laptop+stand", 0, "gt:search2")
cap("GET", f"{GT}/sqli?id=1", 0, "gt:sqli-normal")
cap("GET", f"{GT}/sqli?id=2", 0, "gt:sqli-normal2")
cap("GET", f"{GT}/xss_r?name=alice", 0, "gt:xss-normal-name")
cap("GET", f"{GT}/xss_r?name=bob", 0, "gt:xss-normal-name2")
cap("GET", f"{GT}/xss_r?name=charlie", 0, "gt:xss-normal-name3")
cap("GET", f"{GT}/xss_r?name=admin", 0, "gt:xss-normal-name4")
cap("GET", f"{GT}/search?q=wireless+mouse", 0, "gt:search3")
cap("GET", f"{GT}/search?q=coffee", 0, "gt:search4")
cap("GET", f"{GT}/search?q=%27+OR+1%3D1--", 0, "gt:search-escaped-attack")
cap("GET", f"{GT}/sqli?id=1 UNION SELECT 1,2,3", 0, "gt:sqli-union-normal")  # reviewed: normal-shaped echo

print("== ground truth anomalous ==")
cap("GET", f"{GT}/sqli?id=' OR '1'='1", 1, "gt:sqli-tautology")
cap("GET", f"{GT}/sqli?id=1'", 1, "gt:sqli-quote-error")
cap("GET", f"{GT}/sqli?id=1 OR 1=1", 1, "gt:sqli-or-error")
cap("GET", f"{GT}/sqli?id=2' AND '1'='1", 1, "gt:sqli-and-error")
cap("GET", f"{GT}/xss_r?name=<script>alert(1)</script>", 1, "gt:xss-reflect")
cap("GET", f"{GT}/xss_r?name=<svg onload=alert(1)>", 1, "gt:xss-reflect2")
cap("GET", f"{GT}/xss_r?name=<img src=x onerror=alert(1)>", 1, "gt:xss-reflect3")
cap("GET", f"{GT}/xss_r?name=<iframe src=javascript:alert(1)>", 1, "gt:xss-reflect4")
cap("GET", f"{GT}/open_redirect?url=https://evil.example.com", 1, "gt:open-redirect")
cap("GET", f"{GT}/open_redirect?url=https://phish.example.org/login", 1, "gt:open-redirect2")

print("== VAmPI benign ==")
cap("GET", f"{V}/", 0, "vampi:home")
cap("GET", f"{V}/books/v1", 0, "vampi:books")
cap("GET", f"{V}/users/v1/name1", 0, "vampi:user-lookup")
cap("POST", f"{V}/users/v1/login", 0, "vampi:login-badcreds",
    json={"username": "nosuchuser", "password": "wrongpass"})
cap("GET", f"{V}/books/v1/' OR '1'='1", 0, "vampi:sqli-book-401")  # reviewed: plain 401 auth page
cap("POST", f"{V}/users/v1/register", 0, "vampi:register",
    json={"username": "corpususer8", "password": "CorpusPass1!", "email": "corpus8@mail.com"})
cap("POST", f"{V}/users/v1/login", 0, "vampi:login-ok",
    json={"username": "corpususer8", "password": "CorpusPass1!"})

print("== VAmPI anomalous ==")
cap("GET", f"{V}/users/v1/_debug", 1, "vampi:debug-dump")

# /users/v1 full list: label by content — a dump containing passwords is an
# exploit-effect body; a name-only list is the app's normal index response.
try:
    r = httpx.get(f"{V}/users/v1", timeout=15)
    lbl = 1 if "password" in (r.text or "") else 0
    rows.append(((r.text or "")[:4000], lbl, f"vampi:users-list[{r.status_code}]"))
    print(f"  vampi:users-list           label={lbl} status={r.status_code} len={len(r.text or '')} (passwords in body: {lbl==1})")
except Exception as exc:
    print(f"  vampi:users-list           FAILED: {exc}")

# Authenticated book probes: SQLi against /books/v1/<title> with a real token.
try:
    tok = None
    for b, l, s in rows:
        if s.startswith("vampi:login-ok"):
            tok = json.loads(b).get("auth_token") or json.loads(b).get("token")
    if tok:
        hdr = {"Authorization": f"Bearer {tok}"}
        cap("GET", f"{V}/books/v1/bookTitle32", 0, "vampi:book-auth-normal", headers=hdr)
        cap("GET", f"{V}/books/v1/' OR '1'='1", 0, "vampi:book-sqli-auth", headers=hdr)  # reviewed: 'Book not found!' = safe handling
        cap("GET", f"{V}/books/v1/x' UNION SELECT 1,2,3 --", 0, "vampi:book-union-auth", headers=hdr)  # reviewed: same
    else:
        print("  vampi book-auth probes skipped: no token parsed")
except Exception as exc:
    print(f"  vampi book-auth probes FAILED: {exc}")
# dropped after review: vampi:sqli-login (body identical to bad-creds),
# vampi:sqli-user (body indistinguishable from a normal user lookup)

print("== augmentation (declared) ==")
import random
random.seed(42)
aug = []
for body, label, source in list(rows):
    variants = []
    try:
        obj = json.loads(body)
        variants.append(json.dumps(obj, indent=2, sort_keys=True))
        variants.append(json.dumps(obj))  # compact form real frameworks emit
    except Exception:
        pass
    variants.append(" ".join(body.split()))
    for v in variants[:3]:
        if v and v != body:
            aug.append((v[:4000], label, source + "+aug"))
rows.extend(aug)

ben = sum(1 for r in rows if r[1] == 0)
ano = sum(1 for r in rows if r[1] == 1)
print(f"\ntotal rows: {len(rows)} (benign={ben}, anomalous={ano})")

csv_path = os.path.join(APP_DIR, "ml_pipeline", "datasets", "response_bodies_v1.csv")
with open(csv_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["body", "label", "source"])
    for b, l, s in rows:
        w.writerow([b, l, s])
print("wrote", csv_path)
