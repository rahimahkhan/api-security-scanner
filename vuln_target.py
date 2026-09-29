"""Intentionally vulnerable local target for manual scanner verification.

Ground truth:
  /search?q=   reflected XSS  (q echoed raw into HTML)
  /user?id=    SQLi           (quote in id -> 'SQL syntax error' text)
  /go?url=     open redirect  (302 to url value)
  /health      clean JSON     (expect NO finding)
"""
from flask import Flask, request, redirect, Response

app = Flask(__name__)


@app.route("/")
def index():
    return """<html><body><h1>vuln-target</h1>
<a href="/search?q=hello">search</a>
<a href="/user?id=1">user</a>
<a href="/go?url=https://example.com">go</a>
<a href="/health">health</a>
</body></html>"""


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULN: raw reflection -> reflected XSS
    return Response(f"<html><body>Results for: {q}</body></html>", mimetype="text/html")


@app.route("/user")
def user():
    uid = request.args.get("id", "")
    # VULN: simulated SQLi error disclosure
    if "'" in uid or "OR" in uid.upper():
        return Response("Database error: SQL syntax error near '%s'" % uid[:40],
                        mimetype="text/html"), 500
    return {"id": uid, "name": "user-%s" % uid}


@app.route("/go")
def go():
    url = request.args.get("url", "/")
    # VULN: open redirect
    return redirect(url, code=302)


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8765)
