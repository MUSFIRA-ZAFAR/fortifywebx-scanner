import requests

# ---------------------------------------------------------------------------
# Check 1: Missing / Insecure HTTP Security Headers
# ---------------------------------------------------------------------------

# Each entry: header name -> risk level + description shown when missing
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "risk": "Medium",
        "description": "Missing CSP header - increases risk of XSS attacks succeeding, as there's no browser-level restriction on script sources.",
    },
    "Strict-Transport-Security": {
        "risk": "Medium",
        "description": "Missing HSTS header - browsers won't enforce HTTPS-only connections, leaving room for downgrade/MITM attacks.",
    },
    "X-Frame-Options": {
        "risk": "Low",
        "description": "Missing X-Frame-Options header - page could be embedded in an iframe on a malicious site (clickjacking risk).",
    },
    "X-Content-Type-Options": {
        "risk": "Low",
        "description": "Missing X-Content-Type-Options header - browsers may MIME-sniff responses, which can lead to content-type confusion attacks.",
    },
}


def check_security_headers(url):
    """
    Checks a single URL's response headers for the presence of key
    security headers. Returns a list of findings (dicts) - one per
    missing header. Non-intrusive: uses a single GET request already
    being made for the page, no extra load on the target.
    """
    findings = []

    try:
        response = requests.get(url, timeout=5)
    except requests.RequestException as e:
        print(f"[!] Could not check headers for {url}: {e}")
        return findings

    response_headers = response.headers

    for header_name, meta in SECURITY_HEADERS.items():
        if header_name not in response_headers:
            findings.append({
                "name": f"Missing Security Header: {header_name}",
                "location": url,
                "risk": meta["risk"],
                "evidence": f"Header '{header_name}' not present in response.",
                "description": meta["description"],
            })

    return findings


# ---------------------------------------------------------------------------
# Check 2: Insecure Cookie Attributes
# ---------------------------------------------------------------------------

def check_cookie_security(url):
    """
    Checks Set-Cookie headers on a response for missing HttpOnly/Secure
    flags. Reads the raw header (not the parsed cookie jar) because
    Python's cookie jar strips flag metadata.
    """
    findings = []

    try:
        response = requests.get(url, timeout=5)
    except requests.RequestException as e:
        print(f"[!] Could not check cookies for {url}: {e}")
        return findings

    set_cookie_headers = response.raw.headers.get_all("Set-Cookie") if response.raw.headers else []

    for cookie_header in set_cookie_headers:
        cookie_name = cookie_header.split("=")[0].strip()
        lower_header = cookie_header.lower()

        missing_flags = []
        if "httponly" not in lower_header:
            missing_flags.append("HttpOnly")
        if "secure" not in lower_header:
            missing_flags.append("Secure")

        if missing_flags:
            findings.append({
                "name": f"Insecure Cookie: {cookie_name}",
                "location": url,
                "risk": "Medium" if "HttpOnly" in missing_flags else "Low",
                "evidence": f"Cookie '{cookie_name}' missing flag(s): {', '.join(missing_flags)}",
                "description": f"Cookie is missing {', '.join(missing_flags)} attribute(s), increasing risk of theft via XSS or network interception.",
            })

    return findings


# ---------------------------------------------------------------------------
# Check 3: XSS / Form Risk Pattern Detection (pattern-based, non-intrusive)
# ---------------------------------------------------------------------------

# Field names commonly associated with reflected content -> higher XSS risk
SUSPICIOUS_FIELD_NAMES = [
    "search", "query", "q", "name", "comment", "message", "feedback", "msg"
]

# Common CSRF token field name patterns
CSRF_FIELD_HINTS = ["csrf", "token", "_token", "authenticity_token"]


def check_form_risk(form):
    """
    Evaluates a single crawled form (dict from Crawler.extract_forms)
    for XSS-relevant risk signals. This is pattern-based only - no
    actual injection is performed, per the non-intrusive scanning rule.

    Expects a form dict with keys: page, action, method, inputs
    """
    findings = []
    method = form.get("method", "GET").upper()
    inputs = form.get("inputs", [])
    action = form.get("action", "")
    page = form.get("page", "")

    # Signal 1: GET method carrying user input
    if method == "GET" and inputs:
        findings.append({
            "name": "Form Uses GET With User Input",
            "location": f"{page} (form action: {action})",
            "risk": "Low",
            "evidence": f"Form submits via GET with fields: {', '.join(inputs)}",
            "description": "GET requests place input directly in the URL, increasing exposure via browser history, server logs, and referrer headers - and raising reflected XSS risk if these values are echoed back unsanitized.",
        })

    # Signal 2: suspicious field names commonly tied to reflected XSS
    matched_fields = [f for f in inputs if f and f.lower() in SUSPICIOUS_FIELD_NAMES]
    if matched_fields:
        findings.append({
            "name": "Form Field Commonly Associated With Reflected XSS",
            "location": f"{page} (form action: {action})",
            "risk": "Medium",
            "evidence": f"Field(s) found: {', '.join(matched_fields)}",
            "description": "These field names are commonly echoed back into page content (e.g. 'you searched for: ...'), making them frequent reflected XSS targets if input isn't sanitized/escaped on output.",
        })

    # Signal 3: no CSRF token field present
    has_csrf_field = any(
        inp and any(hint in inp.lower() for hint in CSRF_FIELD_HINTS)
        for inp in inputs
    )
    if method == "POST" and not has_csrf_field:
        findings.append({
            "name": "Form Missing Apparent CSRF Token",
            "location": f"{page} (form action: {action})",
            "risk": "Low",
            "evidence": f"POST form with fields {inputs} has no field matching common CSRF token naming patterns.",
            "description": "No CSRF token field detected by name pattern. This is a heuristic only - the app may protect via other means (e.g. cookies, headers) not visible in form fields.",
        })

    return findings


# ---------------------------------------------------------------------------
# Check 4: SQL Injection Indicators (error-based, non-intrusive)
# ---------------------------------------------------------------------------

# Patterns commonly found in raw database error messages leaked to users.
# Presence suggests unhandled DB errors reaching the response - a strong
# indicator (not proof) that unsanitized input could reach a SQL query.
DB_ERROR_PATTERNS = [
    "sql syntax",
    "mysql_fetch",
    "ora-01756",
    "sqlite3.operationalerror",
    "sqlite_error",
    "unclosed quotation mark",
    "pg_query",
    "sqlstate",
    "syntax error at or near",
    "quoted string not properly terminated",
    "sequelize",  # ORM error leakage (relevant for Juice Shop, uses Sequelize)
]


def check_sql_error_indicators(url):
    """
    Non-intrusive SQLi indicator check. Fetches the page ONCE (no
    payloads, no modified parameters) and scans the response body for
    known database error message fragments. This flags information
    disclosure and potential injection risk without ever attempting
    exploitation.
    """
    findings = []

    try:
        response = requests.get(url, timeout=5)
    except requests.RequestException as e:
        print(f"[!] Could not check SQLi indicators for {url}: {e}")
        return findings

    body_lower = response.text.lower()

    for pattern in DB_ERROR_PATTERNS:
        if pattern in body_lower:
            findings.append({
                "name": "Possible Database Error Disclosure",
                "location": url,
                "risk": "High",
                "evidence": f"Response body contains pattern associated with DB errors: '{pattern}'",
                "description": "The response appears to contain a raw database/ORM error message. This can leak schema details and is a strong indicator that unsanitized input may reach a database query (potential SQL injection point) - manual verification recommended.",
            })

    # A 500 status code alone, even without a matching text pattern, is
    # still worth flagging as lower-confidence/info-level.
    if response.status_code == 500 and not findings:
        findings.append({
            "name": "Server Error (HTTP 500) on Request",
            "location": url,
            "risk": "Info",
            "evidence": "Endpoint returned HTTP 500 with no recognized DB error pattern in body.",
            "description": "Unhandled server error. Not confirmed as DB-related, but worth manual review - error handling gaps can sometimes leak sensitive info depending on debug settings.",
        })

    return findings


# ---------------------------------------------------------------------------
# Check 5: Technology Stack Fingerprinting (passive, header-based only)
# ---------------------------------------------------------------------------

FINGERPRINT_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


def check_tech_fingerprint(url):
    """
    Non-intrusive tech stack fingerprinting via response headers only.
    No active probing (e.g. no error-triggering requests) - just reads
    what the server voluntarily discloses.
    """
    findings = []

    try:
        response = requests.get(url, timeout=5)
    except requests.RequestException as e:
        print(f"[!] Could not fingerprint {url}: {e}")
        return findings

    disclosed = {}
    for header in FINGERPRINT_HEADERS:
        if header in response.headers:
            disclosed[header] = response.headers[header]

    if disclosed:
        details = ", ".join(f"{k}: {v}" for k, v in disclosed.items())
        findings.append({
            "name": "Technology Stack Disclosed via Headers",
            "location": url,
            "risk": "Info",
            "evidence": details,
            "description": "Response headers reveal server/framework details, which can help an attacker target known vulnerabilities for that specific version. Consider suppressing these headers in production.",
        })

    return findings


# ---------------------------------------------------------------------------
# Bonus: Severity Scoring
# ---------------------------------------------------------------------------

# Numeric severity scores - used for sorting and computing an overall
# risk score, in addition to the existing text risk labels.
SEVERITY_SCORES = {
    "High": 9,
    "Medium": 6,
    "Low": 3,
    "Info": 1,
}


def add_severity_scores(findings):
    """
    Attaches a numeric 'score' field to each finding based on its risk
    label, and returns findings sorted highest score first, along with
    the total accumulated score as a simple overall risk metric.
    """
    for finding in findings:
        finding["score"] = SEVERITY_SCORES.get(finding.get("risk", "Info"), 1)

    sorted_findings = sorted(findings, key=lambda f: f["score"], reverse=True)
    total_score = sum(f["score"] for f in findings)

    return sorted_findings, total_score
