"""Static content for the Vulnerability Guide page.

Each check describes what Xploiter tests, in plain language, plus a
short fix example in three languages. This is documentation only — it
never touches the scan pipeline.
"""

GUIDE_CHECKS = [
    {
        "slug": "sql-injection",
        "title": "SQL injection",
        "owasp": "API8:2023 Security Misconfiguration",
        "what": (
            "SQL injection happens when user input is pasted straight into a "
            "database query. An attacker can read, change, or delete data they "
            "should never see — for example dumping another user's records."
        ),
        "example": (
            "GET /users?id=1' OR '1'='1  →  returns every user instead of one.\n"
            "Error message leaks: \"You have an error in your SQL syntax …\""
        ),
        "detection": (
            "Xploiter sends error-based payloads (single quotes, stacked queries) "
            "and time-based payloads (SLEEP/WAITFOR), then compares each response "
            "against a healthy baseline: database error messages, timing delays, "
            "and differential responses, backed by ML anomaly scoring."
        ),
        "fixes": {
            "python": (
                "# Use parameterized queries — never format SQL with f-strings\n"
                "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
            ),
            "nodejs": (
                "// Use parameterized queries — never concatenate input\n"
                "await db.query('SELECT * FROM users WHERE id = $1', [userId]);"
            ),
            "java": (
                "// Use PreparedStatement — never concatenate input\n"
                "PreparedStatement ps = conn.prepareStatement(\n"
                "    \"SELECT * FROM users WHERE id = ?\");\n"
                "ps.setString(1, userId);"
            ),
        },
    },
    {
        "slug": "reflected-xss",
        "title": "Reflected XSS",
        "owasp": "API8:2023 Security Misconfiguration",
        "what": (
            "Reflected cross-site scripting happens when an API echoes request "
            "input back in a response without escaping it. An attacker can craft "
            "a link that runs JavaScript in a victim's browser — stealing "
            "sessions or defacing pages."
        ),
        "example": (
            "GET /search?q=<script>alert(1)</script>\n"
            "→ response body contains the raw <script> tag, unescaped."
        ),
        "detection": (
            "Xploiter reflects a set of XSS payloads through query and body "
            "parameters and checks whether the exact payload reappears in the "
            "response without encoding. Findings are scored by signature match "
            "plus ML/LSTM payload analysis."
        ),
        "fixes": {
            "python": (
                "# Escape output (Jinja2 autoescapes by default)\n"
                "from markupsafe import escape\n"
                "return f\"<p>{escape(user_input)}</p>\""
            ),
            "nodejs": (
                "// Escape output before rendering\n"
                "const { escape } = require('html-escaper');\n"
                "res.send(`<p>${escape(userInput)}</p>`);"
            ),
            "java": (
                "// Escape output before rendering\n"
                "String safe = StringEscapeUtils.escapeHtml4(userInput);\n"
                "out.println(\"<p>\" + safe + \"</p>\");"
            ),
        },
    },
    {
        "slug": "bola-idor",
        "title": "BOLA / IDOR",
        "owasp": "API1:2023 Broken Object Level Authorization",
        "what": (
            "Broken Object Level Authorization means the API checks that you "
            "are logged in, but not that the object you asked for is yours. "
            "Changing an ID in the URL can expose another user's data."
        ),
        "example": (
            "GET /users/v1/7  →  returns user 7's profile,\n"
            "even though you are logged in as user 3."
        ),
        "detection": (
            "On APIs that expose identity paths (e.g. /users/v1/*), Xploiter "
            "registers two test identities and tries to read, update, and "
            "delete one user's objects with the other's credentials. A "
            "cross-account success is reported as confirmed."
        ),
        "fixes": {
            "python": (
                "# Check ownership on every object access\n"
                "record = db.get(User, user_id)\n"
                "if record.owner_id != current_user.id:\n"
                "    abort(403)"
            ),
            "nodejs": (
                "// Check ownership on every object access\n"
                "const record = await User.findByPk(userId);\n"
                "if (record.ownerId !== req.user.id) return res.sendStatus(403);"
            ),
            "java": (
                "// Check ownership on every object access\n"
                "User record = userRepo.findById(userId);\n"
                "if (!record.getOwnerId().equals(currentUser.getId()))\n"
                "    throw new AccessDeniedException(\"not yours\");"
            ),
        },
    },
    {
        "slug": "broken-authentication",
        "title": "Broken authentication",
        "owasp": "API2:2023 Broken Authentication",
        "what": (
            "Broken authentication covers login weaknesses: credential stuffing, "
            "weak password rules, tokens that never expire, or auth endpoints "
            "that leak whether a username exists."
        ),
        "example": (
            "POST /login with 1,000 common passwords → no rate limiting,\n"
            "and the error message differs for valid vs invalid usernames."
        ),
        "detection": (
            "Xploiter probes login and token endpoints with credential lists, "
            "checks for user-enumeration differences, missing rate-limit "
            "headers, and JWTs accepted without signature verification."
        ),
        "fixes": {
            "python": (
                "# Rate-limit logins and use one generic error message\n"
                "@limiter.limit(\"5/minute\")\n"
                "def login():\n"
                "    ...  # always return \"Invalid credentials\""
            ),
            "nodejs": (
                "// Rate-limit logins and use one generic error message\n"
                "app.post('/login', rateLimit({ max: 5 }), (req, res) => {\n"
                "  ... // always return \"Invalid credentials\"\n"
                "});"
            ),
            "java": (
                "// Rate-limit logins; never reveal which field was wrong\n"
                "// Use Spring Security's DaoAuthenticationProvider with\n"
                "// hideUserNotFoundExceptions = true (the default)."
            ),
        },
    },
    {
        "slug": "cors-policy",
        "title": "CORS policy",
        "owasp": "API8:2023 Security Misconfiguration",
        "what": (
            "A permissive CORS policy (Access-Control-Allow-Origin: * with "
            "credentials allowed) lets any malicious website make authenticated "
            "requests to your API from a victim's browser."
        ),
        "example": (
            "Response header: Access-Control-Allow-Origin: *\n"
            "Access-Control-Allow-Credentials: true  ← dangerous together"
        ),
        "detection": (
            "Xploiter sends cross-origin requests with attacker origins and "
            "inspects the CORS response headers, flagging wildcard origins "
            "combined with credentials and missing Vary: Origin."
        ),
        "fixes": {
            "python": (
                "# Allowlist exact origins; never use '*' with credentials\n"
                "CORS(app, origins=[\"https://app.example.com\"],\n"
                "     supports_credentials=True)"
            ),
            "nodejs": (
                "// Allowlist exact origins; never use '*' with credentials\n"
                "app.use(cors({ origin: 'https://app.example.com',\n"
                "                 credentials: true }));"
            ),
            "java": (
                "// Allowlist exact origins; never use '*' with credentials\n"
                "registry.addMapping(\"/**\")\n"
                "    .allowedOrigins(\"https://app.example.com\")\n"
                "    .allowCredentials(true);"
            ),
        },
    },
    {
        "slug": "command-injection",
        "title": "Command injection",
        "owasp": "API8:2023 Security Misconfiguration",
        "what": (
            "Command injection happens when API input reaches a system shell. "
            "An attacker can append OS commands and take over the server."
        ),
        "example": (
            "GET /ping?host=127.0.0.1; cat /etc/passwd\n"
            "→ response contains the passwd file."
        ),
        "detection": (
            "Xploiter injects shell metacharacters and time-delay commands "
            "into parameters, then looks for command output markers and "
            "timing anomalies versus the healthy baseline."
        ),
        "fixes": {
            "python": (
                "# Never pass user input to a shell; use argument lists\n"
                "subprocess.run([\"ping\", \"-c\", \"1\", host],\n"
                "               shell=False, timeout=5)"
            ),
            "nodejs": (
                "// Never pass user input to a shell\n"
                "const { execFile } = require('child_process');\n"
                "execFile('ping', ['-c', '1', host], (err, out) => {...});"
            ),
            "java": (
                "// Never build shell strings from input\n"
                "new ProcessBuilder(\"ping\", \"-c\", \"1\", host).start();"
            ),
        },
    },
    {
        "slug": "local-file-inclusion",
        "title": "Local file inclusion",
        "owasp": "API8:2023 Security Misconfiguration",
        "what": (
            "Local file inclusion lets an attacker read server files by "
            "manipulating a file path parameter — for example ../../etc/passwd."
        ),
        "example": (
            "GET /download?file=../../etc/passwd\n"
            "→ response contains system file contents."
        ),
        "detection": (
            "Xploiter sends path-traversal payloads (../, encoded variants, "
            "absolute paths) and checks responses for known file markers such "
            "as passwd or win.ini signatures."
        ),
        "fixes": {
            "python": (
                "# Resolve the path and confine it to the allowed directory\n"
                "base = Path(\"/srv/files\").resolve()\n"
                "target = (base / filename).resolve()\n"
                "assert str(target).startswith(str(base))"
            ),
            "nodejs": (
                "// Resolve the path and confine it to the allowed directory\n"
                "const target = path.resolve('/srv/files', filename);\n"
                "if (!target.startsWith('/srv/files/')) throw new Error('blocked');"
            ),
            "java": (
                "// Resolve the path and confine it to the allowed directory\n"
                "Path target = baseDir.resolve(filename).normalize();\n"
                "if (!target.startsWith(baseDir)) throw new SecurityException();"
            ),
        },
    },
    {
        "slug": "open-redirect",
        "title": "Open redirect",
        "owasp": "API8:2023 Security Misconfiguration",
        "what": (
            "Open redirect happens when an API redirects to a URL taken from "
            "user input. Attackers use it in phishing: a trusted domain that "
            "bounces victims to a malicious site."
        ),
        "example": (
            "GET /go?url=https://evil.example\n"
            "→ 302 redirect to https://evil.example"
        ),
        "detection": (
            "Xploiter passes external URLs into redirect parameters "
            "(url, next, return, dest, …) and confirms the vulnerability when "
            "the response actually redirects off-domain."
        ),
        "fixes": {
            "python": (
                "# Only redirect to allowlisted paths\n"
                "if not next_url.startswith(\"/\"):\n"
                "    next_url = \"/\"\n"
                "return redirect(next_url)"
            ),
            "nodejs": (
                "// Only redirect to allowlisted paths\n"
                "const dest = req.query.next;\n"
                "res.redirect(dest && dest.startsWith('/') ? dest : '/');"
            ),
            "java": (
                "// Only redirect to allowlisted paths\n"
                "String dest = request.getParameter(\"next\");\n"
                "if (dest == null || !dest.startsWith(\"/\")) dest = \"/\";\n"
                "response.sendRedirect(dest);"
            ),
        },
    },
    {
        "slug": "xxe",
        "title": "XXE",
        "owasp": "API8:2023 Security Misconfiguration",
        "what": (
            "XML External Entity injection abuses XML parsers that resolve "
            "external entities — letting attackers read server files or probe "
            "internal networks through a crafted XML document."
        ),
        "example": (
            "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n"
            "<r>&xxe;</r>  →  response contains the file."
        ),
        "detection": (
            "Xploiter submits XML payloads with external entity declarations "
            "to XML-accepting endpoints and watches for file-content markers, "
            "parser error disclosures, and out-of-band timing signals."
        ),
        "fixes": {
            "python": (
                "# Disable entity resolution (defusedxml)\n"
                "from defusedxml import ElementTree\n"
                "tree = ElementTree.fromstring(xml_data)  # entities blocked"
            ),
            "nodejs": (
                "// Disable DTD / external entities in your XML parser\n"
                "// e.g. libxmljs: { noblanks: true, noent: false, dtdload: false }"
            ),
            "java": (
                "// Disable DOCTYPE entirely\n"
                "factory.setFeature(\n"
                "  \"http://apache.org/xml/features/disallow-doctype-decl\", true);"
            ),
        },
    },
    {
        "slug": "graphql-introspection",
        "title": "GraphQL introspection",
        "owasp": "API9:2023 Improper Inventory Management",
        "what": (
            "Leaving GraphQL introspection enabled in production exposes your "
            "entire schema — every type, query, and mutation — giving attackers "
            "a free map of the API surface."
        ),
        "example": (
            "POST /graphql { \"query\": \"{ __schema { types { name } } }\" }\n"
            "→ full schema returned on a production endpoint."
        ),
        "detection": (
            "Xploiter sends standard introspection queries to GraphQL "
            "endpoints and flags the check when the server answers with "
            "schema metadata instead of rejecting the query."
        ),
        "fixes": {
            "python": (
                "# Disable introspection in production (Ariadne/Strawberry)\n"
                "# e.g. graphql_sync(..., middleware=[...]) with\n"
                "# introspection disabled via server config flag."
            ),
            "nodejs": (
                "// Disable introspection in production\n"
                "const server = new ApolloServer({\n"
                "  introspection: process.env.NODE_ENV !== 'production',\n"
                "});"
            ),
            "java": (
                "// Disable introspection in production\n"
                "// graphql-java: do not add IntrospectionQuery handling\n"
                "// or block __schema/__type at the web layer."
            ),
        },
    },
]


def get_check(slug: str):
    for check in GUIDE_CHECKS:
        if check["slug"] == slug:
            return check
    return GUIDE_CHECKS[0]
