"""Xploiter AI Assistant backend.

Answers questions about the platform and the user's own scan results.
Two engines:
  1. A real LLM when an API key is set (GOOGLE_AI_API_KEY for Gemini's free
     tier, or OPENAI_API_KEY) with a strict system prompt: only Xploiter
     documentation + the provided scan context, never invented scan data.
  2. A built-in knowledge-based responder otherwise (offline-safe), with
     short canned translations for Urdu, Arabic and Spanish on the main
     topics and an English fallback.

Nothing here touches the scan pipeline. When no LLM key is set, the UI
labels the assistant as offline so nobody mistakes canned answers for a live AI.
"""
import html
import json
import os
import re
import urllib.request
from typing import Optional

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"
GOOGLE_AI_API_KEY = os.getenv("GOOGLE_AI_API_KEY", "").strip()  # Gemini free tier
# Floating alias on purpose: Google retires pinned versions (gemini-2.0-flash
# died 2026-06-01 and silently broke this). Env override for pinning if wanted.
GOOGLE_AI_MODEL = os.getenv("GOOGLE_AI_MODEL", "gemini-flash-latest").strip() or "gemini-flash-latest"
_GEMINI_FALLBACK_MODELS = ["gemini-flash-latest", "gemini-flash-lite-latest"]

SYSTEM_PROMPT = """You are the Xploiter AI Assistant. Xploiter is an API security scanner.

Facts you may use (do not invent anything else):
- Users run scans from "New Scan": enter the API base URL, optionally add auth
  (Bearer token, API key, or cookie), tick "I am authorized to test this target",
  then Start scan. Every scan runs
  the complete pipeline: active probes, passive checks, and safety limits.
- Checks: SQL injection, reflected XSS, BOLA/IDOR, broken authentication, CORS
  policy, command injection, local file inclusion, open redirect, XXE, and
  GraphQL introspection — mapped to the OWASP API Top 10.
- Results group findings by endpoint (method + path), ranked by a risk score
  (Critical=10, High=7, Medium=4, Low=1, confirmed weighted above suspected).
  The page shows the top 6 riskiest endpoints; "Show all endpoints" reveals the rest.
- Finding status: Confirmed = proven with evidence; Suspected = strong signal but
  unproven; Informational = a note, not a vulnerability.
- Exports: PDF, JSON, HTML, SARIF 2.1.0 — every report starts with the top risks.
- Pages: Dashboard, New Scan, Scan History (search/filter/compare), Reports,
  Targets, Vulnerability Guide, AI Assistant, Settings.
- Safety: only scan APIs you own or are authorized to test; scans use an endpoint
  budget and bounded concurrency.

Rules:
- Answer in the user's language.
- Use ONLY the scan context provided below for anything about their scans. If a
  question asks for scan details not present in the context, say you don't have
  that data instead of inventing it.
- Keep answers short and step-by-step. End fix-related answers with: review any
  fix before applying it.
"""

# ---------------------------------------------------------------------------
# Built-in knowledge base (offline fallback)
# ---------------------------------------------------------------------------

def _t(en, ur=None, ar=None, es=None):
    return {"en": en, "ur": ur or en, "ar": ar or en, "es": es or en}


TOPICS = [
    {
        "id": "run_scan",
        "keywords": ["run a scan", "start a scan", "new scan", "how do i scan", "scan my api", "first scan"],
        "text": _t(
            "To run a scan:\n1. Open **New Scan** from the sidebar.\n2. Enter your API base URL (e.g. https://api.example.com).\n3. Add authentication if your API needs it (Bearer token, API key, or cookie).\n4. Tick **I am authorized to test this target**.\n5. Press **Start scan** — live progress shows the current module, endpoints scanned, and findings so far.",
            ur="اسکین چلانے کے لیے:\n1. سائڈبار سے **New Scan** کھولیں۔\n2. اپنی API کا بیس URL درج کریں (مثلاً https://api.example.com)۔\n3. اگر ضرورت ہو تو authentication شامل کریں۔\n4. **I am authorized to test this target** پر ٹک کریں۔\n5. **Start scan** دبائیں۔",
            ar="لتشغيل الفحص:\n1. افتح **New Scan** من الشريط الجانبي.\n2. أدخل رابط الـ API الأساسي.\n3. أضف المصادقة إن لزم الأمر.\n4. حدّد **I am authorized to test this target**.\n5. اضغط **Start scan**.",
            es="Para ejecutar un análisis:\n1. Abre **New Scan** en la barra lateral.\n2. Ingresa la URL base de tu API.\n3. Agrega autenticación si es necesario.\n4. Marca **I am authorized to test this target**.\n5. Pulsa **Start scan**.",
        ),
        "actions": [{"label": "Open this screen", "href": "/new-scan"}],
    },
    {
        "id": "fix_first",
        "keywords": ["fix first", "what should i fix", "priorit", "top risk", "most important"],
        "text": _t(
            "Start with the **Top Risks** on your scan results page — the 6 riskiest endpoints, ranked by score. Fix **Confirmed** findings first (proven with evidence), then **Suspected** ones. Each endpoint card tells you exactly what to fix first.",
            ur="اپنے اسکین کے نتائج میں **Top Risks** سے شروع کریں — اسکور کے لحاظ سے 6 سب سے خطرناک اینڈ پوائنٹس۔ پہلے **Confirmed** مسائل ٹھیک کریں (ثبوت کے ساتھ ثابت شدہ)، پھر **Suspected**۔",
            ar="ابدأ بـ **Top Risks** في صفحة النتائج — أخطر 6 نقاط نهاية مرتبة حسب الدرجة. أصلح نتائج **Confirmed** أولاً (مثبتة بدليل)، ثم **Suspected**.",
            es="Empieza por **Top Risks** en la página de resultados: los 6 endpoints más riesgosos, ordenados por puntuación. Corrige primero los hallazgos **Confirmed** (probados con evidencia) y luego los **Suspected**.",
        ),
        "actions": [{"label": "Open this screen", "href": "/history"}],
    },
    {
        "id": "read_results",
        "keywords": ["read result", "understand result", "explain this finding", "what does", "severity", "confirmed", "suspected", "score", "risk score"],
        "text": _t(
            "Results group findings by endpoint (method + path) so nothing repeats. **Severity**: Critical, High, Medium, Low. **Status**: Confirmed = proven with evidence; Suspected = strong signal, not yet proven; Informational = a note. The **score (0–100)** ranks what to fix first. Use the tabs to filter, or **Show all endpoints** for the full list.",
            ur="نتائج اینڈ پوائنٹ کے لحاظ سے گروپ کیے جاتے ہیں۔ **شدت**: Critical، High، Medium، Low۔ **حیثیت**: Confirmed = ثبوت کے ساتھ ثابت؛ Suspected = مضبوط اشارہ؛ Informational = نوٹ۔ **اسکور (0–100)** بتاتا ہے کہ پہلے کیا ٹھیک کریں۔",
            ar="تُجمَّع النتائج حسب نقطة النهاية. **الخطورة**: Critical وHigh وMedium وLow. **الحالة**: Confirmed = مثبت بدليل؛ Suspected = إشارة قوية؛ Informational = ملاحظة. **الدرجة (0–100)** ترتب الأولويات.",
            es="Los resultados agrupan hallazgos por endpoint. **Severidad**: Critical, High, Medium, Low. **Estado**: Confirmed = probado con evidencia; Suspected = señal fuerte; Informational = nota. La **puntuación (0–100)** ordena qué corregir primero.",
        ),
        "actions": [{"label": "Read the guide", "href": "/vuln-guide"}],
    },
    {
        "id": "exports",
        "keywords": ["export", "pdf", "json", "sarif", "html", "download report", "report"],
        "text": _t(
            "Every finished scan can be downloaded as **PDF**, **JSON**, **HTML**, or **SARIF** 2.1.0 — use the Export button on the results page, or the Reports page for all scans. Every report starts with the top risks, followed by the full endpoint list.",
        ),
        "actions": [{"label": "Open this screen", "href": "/reports"}],
    },
    {
        "id": "login",
        "keywords": ["log in", "login", "sign in", "sign up", "password", "account", "forgot"],
        "text": _t(
            "Log in with your **email or username** plus password, or **Continue with Google**. New here? Create an account from the login page — each account only ever sees its own scans. Forgot your password? Use **Forgot password** for a reset link or a one-time code.",
        ),
        "actions": [{"label": "Open this screen", "href": "/login"}],
    },
    {
        "id": "cancel",
        "keywords": ["cancel", "stop the scan", "stop scan"],
        "text": _t(
            "You can cancel a running scan with the **Cancel scan** button on the New Scan page's live-progress panel or on the results page. The session is marked as failed so it stops cleanly.",
        ),
    },
    {
        "id": "sqli",
        "keywords": ["sql injection", "sqli"],
        "text": _t("**SQL injection**: user input pasted into a database query lets attackers read or change data. Xploiter probes with error-based and time-based payloads and confirms on database errors or timing delays. Fix: always use parameterized queries — never build SQL from strings."),
        "actions": [{"label": "Read the guide", "href": "/vuln-guide?check=sql-injection"}],
    },
    {
        "id": "xss",
        "keywords": ["xss", "cross-site", "cross site"],
        "text": _t("**Reflected XSS**: the API echoes input back without escaping, letting attackers run scripts in victims' browsers. Xploiter reflects payloads and checks they return unescaped. Fix: escape all output."),
        "actions": [{"label": "Read the guide", "href": "/vuln-guide?check=reflected-xss"}],
    },
    {
        "id": "bola",
        "keywords": ["bola", "idor", "object level", "authorization"],
        "text": _t("**BOLA/IDOR**: the API checks login but not ownership — changing an ID exposes another user's data. Xploiter registers two test identities and tries cross-account access. Fix: check ownership on every object access."),
        "actions": [{"label": "Read the guide", "href": "/vuln-guide?check=bola-idor"}],
    },
    {
        "id": "default",
        "keywords": [],
        "text": _t(
            "I can help with: **running a scan**, **reading results**, **what to fix first**, **exports**, **login help**, and what each **vulnerability check** means. What would you like to know?",
            ur="میں مدد کر سکتا ہوں: **اسکین چلانا**، **نتائج پڑھنا**، **پہلے کیا ٹھیک کریں**، **رپورٹس**، **لاگ اِن**، اور ہر **چیک** کا مطلب۔ آپ کیا جاننا چاہیں گے؟",
            ar="يمكنني المساعدة في: **تشغيل الفحص**، **قراءة النتائج**، **ما يجب إصلاحه أولاً**، **التقارير**، **تسجيل الدخول**، ومعنى كل **فحص**. ما الذي تريد معرفته؟",
            es="Puedo ayudar con: **ejecutar un análisis**, **leer resultados**, **qué corregir primero**, **exportaciones**, **inicio de sesión** y el significado de cada **comprobación**. ¿Qué quieres saber?",
        ),
    },
]

DISCLAIMER = _t(
    "\n\n_Review any fix before applying it._",
    ur="\n\n_کسی بھی فکس کو لاگو کرنے سے پہلے اس کا جائزہ لیں۔_",
    ar="\n\n_راجع أي إصلاح قبل تطبيقه._",
    es="\n\n_Revisa cualquier corrección antes de aplicarla._",
)


def detect_language(text: str) -> str:
    """Naive auto-detect: Urdu-specific chars -> ur, Arabic script -> ar, else en."""
    if re.search(r"[\u06D2\u0679\u0688\u0691\u06BA\u06BE\u06C1\u06CC]", text):
        return "ur"
    if re.search(r"[\u0600-\u06FF]", text):
        return "ar"
    return "en"


def _match_topic(question: str):
    q = question.lower()
    for topic in TOPICS:
        if topic["id"] == "default":
            continue
        for kw in topic["keywords"]:
            if kw in q:
                return topic
    return None


def _render_markdown(text: str) -> str:
    """Tiny safe renderer: paragraphs, numbered/bullet lists, **bold**, `code`."""
    lines = text.split("\n")
    blocks = []
    items = []
    list_kind = None

    def flush_list():
        nonlocal items, list_kind
        if items:
            tag = "ol" if list_kind == "ol" else "ul"
            blocks.append(f"<{tag}>" + "".join(f"<li>{i}</li>" for i in items) + f"</{tag}>")
            items = []
            list_kind = None

    for line in lines:
        s = line.strip()
        m_ol = re.match(r"^(\d+)\.\s+(.*)$", s)
        m_ul = re.match(r"^[-*•]\s+(.*)$", s)
        if m_ol or m_ul:
            kind = "ol" if m_ol else "ul"
            content = (m_ol or m_ul).group(2 if m_ol else 1)
            if list_kind != kind:
                flush_list()
                list_kind = kind
            items.append(content)
        elif not s:
            flush_list()
        else:
            flush_list()
            blocks.append(f"<p>{s}</p>")

    flush_list()
    out = "".join(blocks)
    # inline formatting on escaped text
    out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"`(.+?)`", r"<code>\1</code>", out)
    out = re.sub(r"^_(.+)_$", r"<em>\1</em>", out, flags=re.M)
    return out


def knowledge_answer(question: str, language: str = "auto"):
    """Answer from the built-in knowledge base. Returns (answer_html, actions)."""
    lang = language if language in ("en", "ur", "ar", "es") else detect_language(question)
    topic = _match_topic(question) or next(t for t in TOPICS if t["id"] == "default")
    text = topic["text"].get(lang, topic["text"]["en"])
    text += DISCLAIMER.get(lang, DISCLAIMER["en"])
    safe = html.escape(text)
    return _render_markdown(safe), topic.get("actions", [])


def _gemini_models():
    """Primary model first, then fallbacks, deduped."""
    seen = []
    for m in [GOOGLE_AI_MODEL] + _GEMINI_FALLBACK_MODELS:
        if m and m not in seen:
            seen.append(m)
    return seen


def _gemini_once(model, question, lang_name, scan_context):
    """One generateContent call. Raises HTTPError/OSError on failure."""
    payload = json.dumps({
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"parts": [{"text": (
            f"Answer in {lang_name}.\n"
            f"My scan context (do not invent beyond this):\n{scan_context or 'No scans yet.'}\n\n"
            f"Question: {question}"
        )}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 600},
    }).encode("utf-8")
    # Key in the header, not the URL query string (query strings get logged).
    req = urllib.request.Request(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        data=payload,
        headers={"Content-Type": "application/json", "x-goog-api-key": GOOGLE_AI_API_KEY},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    content = data["candidates"][0]["content"]["parts"][0]["text"].strip()
    return _render_markdown(html.escape(content))


def _gemini_answer(question: str, language: str, scan_context: Optional[str]):
    """Ask Google's Gemini API (free tier). Tries each model in turn.

    Retired model names (404) move to the next model immediately; transient
    5xx/timeouts are retried a few times; quota/auth errors fail fast with a
    clear message. Raises the last error if every model fails.
    """
    import time
    import urllib.error
    lang_name = {"en": "English", "ur": "Urdu", "ar": "Arabic", "es": "Spanish"}.get(language, "the user's language")
    if language == "auto":
        lang_name = "the user's language (auto-detect from their question)"
    last_exc = None
    for model in _gemini_models():
        for attempt in range(3):
            try:
                return _gemini_once(model, question, lang_name, scan_context)
            except urllib.error.HTTPError as exc:
                last_exc = exc
                if exc.code == 429:
                    raise RuntimeError(f"Gemini quota exceeded for model {model} (429). Try again tomorrow or use a paid key.")
                if exc.code in (404, 400):
                    break  # retired/unknown model or bad request: try next model
                if exc.code in (401, 403):
                    raise RuntimeError(f"Gemini rejected the API key ({exc.code}). Check the key in Google AI Studio.")
                # other 5xx: transient, retry below
            except (OSError, TimeoutError) as exc:
                last_exc = exc  # network/timeout: transient, retry below
            time.sleep(1.5 * (attempt + 1))
    raise last_exc if last_exc else RuntimeError("Gemini: all models failed")


def engine_mode() -> str:
    """'live' when a real LLM key is configured, else 'offline' (honest label)."""
    if GOOGLE_AI_API_KEY or OPENAI_API_KEY:
        return "live"
    return "offline"


_last_llm_error = None  # sanitized, never contains a key
_last_engine = "knowledge"


def _sanitize(msg: str) -> str:
    """Strip any API key material before the message is logged or shown."""
    for secret in (GOOGLE_AI_API_KEY, OPENAI_API_KEY):
        if secret and len(secret) > 4:
            msg = msg.replace(secret, "***")
            # also mask it inside URLs (?key=... / Bearer ...)
            msg = msg.replace(secret[:8], "***")
    return msg


def last_llm_error():
    """Sanitized reason the last live-AI attempt failed (None if it worked)."""
    return _last_llm_error


def last_engine():
    """Which engine produced the last answer: gemini | openai | knowledge."""
    return _last_engine


def _openai_answer(question: str, language: str, scan_context: Optional[str]):
    """Ask the OpenAI chat API. Raises on any failure (caller falls back)."""
    lang_name = {"en": "English", "ur": "Urdu", "ar": "Arabic", "es": "Spanish"}.get(language, "the user's language")
    if language == "auto":
        lang_name = "the user's language (auto-detect from their question)"
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": (
            f"Answer in {lang_name}.\n"
            f"My scan context (do not invent beyond this):\n{scan_context or 'No scans yet.'}\n\n"
            f"Question: {question}"
        )},
    ]
    payload = json.dumps({
        "model": OPENAI_MODEL,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 600,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {OPENAI_API_KEY}"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    content = data["choices"][0]["message"]["content"].strip()
    safe = html.escape(content)
    return _render_markdown(safe)


def answer(question: str, language: str = "auto", scan_context: Optional[str] = None):
    """Public entry: (answer_html, actions). Never raises."""
    lang = language if language in ("en", "ur", "ar", "es") else detect_language(question)
    topic = _match_topic(question)
    actions = topic.get("actions", []) if topic else []
    global _last_llm_error, _last_engine
    if GOOGLE_AI_API_KEY:
        try:
            out = _gemini_answer(question, lang, scan_context), actions
            _last_llm_error = None
            _last_engine = "gemini"
            return out
        except Exception as exc:
            _last_llm_error = "Gemini: " + _sanitize(str(exc))[:300]
    if OPENAI_API_KEY:
        try:
            out = _openai_answer(question, lang, scan_context), actions
            _last_llm_error = None
            _last_engine = "openai"
            return out
        except Exception as exc:
            _last_llm_error = "OpenAI: " + _sanitize(str(exc))[:300]
    _last_engine = "knowledge"
    return knowledge_answer(question, language)
