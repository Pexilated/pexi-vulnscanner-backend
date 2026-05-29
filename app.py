from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import re
import urllib.parse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
CORS(app)  # Allow frontend to call this API

# ─────────────────────────────────────────────
# Shared HTTP session with realistic headers
# ─────────────────────────────────────────────
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
})
TIMEOUT = 8


def safe_get(url, params=None):
    """GET request that never crashes the scanner."""
    try:
        r = SESSION.get(url, params=params, timeout=TIMEOUT, allow_redirects=True, verify=False)
        return r
    except Exception as e:
        return None


def safe_post(url, data=None):
    try:
        r = SESSION.post(url, data=data, timeout=TIMEOUT, allow_redirects=True, verify=False)
        return r
    except Exception:
        return None


# ─────────────────────────────────────────────
# 1. SECURITY HEADERS
# ─────────────────────────────────────────────
def check_security_headers(base_url):
    findings = []
    r = safe_get(base_url)
    if not r:
        return [{"vuln": "Connection Failed", "severity": "info", "detail": "Could not reach the target URL."}]

    headers = {k.lower(): v for k, v in r.headers.items()}

    checks = [
        ("strict-transport-security", "Missing HSTS",
         "HIGH", "Strict-Transport-Security header missing. Site may be vulnerable to SSL-stripping attacks."),
        ("content-security-policy", "Missing CSP",
         "HIGH", "No Content-Security-Policy header found. XSS attacks can run unrestricted scripts."),
        ("x-frame-options", "Missing X-Frame-Options",
         "MEDIUM", "No X-Frame-Options header. Page may be embeddable in iframes (clickjacking risk)."),
        ("x-content-type-options", "Missing X-Content-Type-Options",
         "MEDIUM", "nosniff not set. Browsers may MIME-sniff responses leading to XSS."),
        ("referrer-policy", "Missing Referrer-Policy",
         "LOW", "No Referrer-Policy header. Sensitive URLs may leak via the Referer header."),
        ("permissions-policy", "Missing Permissions-Policy",
         "LOW", "No Permissions-Policy header. Browser features (camera, mic, etc.) are unrestricted."),
    ]

    for header_name, vuln_name, severity, detail in checks:
        if header_name not in headers:
            findings.append({"vuln": vuln_name, "severity": severity, "detail": detail})

    # Check for server version disclosure
    if "server" in headers and any(char.isdigit() for char in headers["server"]):
        findings.append({
            "vuln": "Server Version Disclosure",
            "severity": "LOW",
            "detail": f"Server header exposes version: '{headers['server']}'. Attackers can target known CVEs."
        })

    # Check for X-Powered-By
    if "x-powered-by" in headers:
        findings.append({
            "vuln": "Technology Disclosure (X-Powered-By)",
            "severity": "LOW",
            "detail": f"X-Powered-By header exposes stack: '{headers['x-powered-by']}'."
        })

    if not findings:
        findings.append({"vuln": "Security Headers", "severity": "pass", "detail": "All major security headers are present."})

    return findings


# ─────────────────────────────────────────────
# 2. SQL INJECTION
# ─────────────────────────────────────────────
SQL_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "1' AND SLEEP(2)--",
    "' UNION SELECT NULL--",
    "admin'--",
    "1 OR 1=1",
]

SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"ora-\d{5}",
    r"syntax error",
    r"unclosed quotation",
    r"sqlite3\.operationalerror",
    r"pg::syntaxerror",
    r"warning: mysql",
    r"you have an error in your sql",
    r"quoted string not properly terminated",
    r"sqlexception",
    r"sqlsyntaxerrorexception",
    r"psql error",
    r"odbc microsoft access",
    r"jet database engine",
    r"native client",
    r"microsoft ole db",
]


def check_sql_injection(base_url):
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        # Try appending a fake param to look for errors
        params = {"id": ["1"]}

    baseline = safe_get(base_url)
    baseline_text = baseline.text.lower() if baseline else ""

    for param_name in params:
        for payload in SQL_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload

            r = safe_get(base_url.split("?")[0], params=test_params)
            if not r:
                continue

            body = r.body.lower() if hasattr(r, "body") else r.text.lower()

            for pattern in SQL_ERROR_PATTERNS:
                if re.search(pattern, body) and not re.search(pattern, baseline_text):
                    findings.append({
                        "vuln": "SQL Injection (Error-Based)",
                        "severity": "CRITICAL",
                        "detail": f"Parameter '{param_name}' with payload `{payload}` triggered SQL error pattern: '{pattern}'.",
                        "payload": payload
                    })
                    break

            # Time-based blind detection
            if "SLEEP" in payload or "WAITFOR" in payload:
                start = time.time()
                safe_get(base_url.split("?")[0], params=test_params)
                elapsed = time.time() - start
                if elapsed >= 2.0:
                    findings.append({
                        "vuln": "SQL Injection (Time-Based Blind)",
                        "severity": "CRITICAL",
                        "detail": f"Parameter '{param_name}' caused a {elapsed:.1f}s delay with SLEEP payload — likely time-based blind SQLi.",
                        "payload": payload
                    })

    if not findings:
        findings.append({"vuln": "SQL Injection", "severity": "pass", "detail": "No SQL injection indicators found."})

    return findings


# ─────────────────────────────────────────────
# 3. REFLECTED XSS
# ─────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "';alert(1)//",
    "<iframe src=javascript:alert(1)>",
    "<input autofocus onfocus=alert(1)>",
]


def check_xss(base_url):
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        params = {"q": ["test"], "search": ["test"], "id": ["1"]}

    for param_name in params:
        for payload in XSS_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload

            r = safe_get(base_url.split("?")[0], params=test_params)
            if not r:
                continue

            # Check if our raw payload is reflected without encoding
            if payload in r.text:
                findings.append({
                    "vuln": "Reflected XSS",
                    "severity": "HIGH",
                    "detail": f"Parameter '{param_name}' reflects payload unescaped: `{payload}`",
                    "payload": payload
                })
                break  # one finding per param is enough

    if not findings:
        findings.append({"vuln": "Reflected XSS", "severity": "pass", "detail": "No reflected XSS indicators found in URL parameters."})

    return findings


# ─────────────────────────────────────────────
# 4. DIRECTORY TRAVERSAL & SENSITIVE FILES
# ─────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/config.php",
    "/wp-config.php",
    "/config.yml",
    "/config.yaml",
    "/database.yml",
    "/.htaccess",
    "/web.config",
    "/server.xml",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/robots.txt",
    "/sitemap.xml",
    "/backup.zip",
    "/backup.sql",
    "/dump.sql",
    "/.DS_Store",
    "/Dockerfile",
    "/docker-compose.yml",
    "/../../../etc/passwd",
    "/etc/passwd",
    "/admin",
    "/admin/",
    "/administrator",
    "/phpmyadmin",
    "/login",
    "/console",
    "/api",
    "/api/v1",
    "/api/v2",
    "/swagger",
    "/swagger-ui.html",
    "/actuator",
    "/actuator/env",
    "/graphql",
]

SENSITIVE_KEYWORDS = [
    "root:x:", "password", "DB_PASSWORD", "APP_KEY", "SECRET_KEY",
    "access_key", "aws_secret", "[core]", "gitdir", "<?php",
    "index of /", "parent directory", "[mysqldump]",
]


def check_directory_traversal(base_url):
    findings = []
    base = base_url.rstrip("/").split("?")[0]
    # Get the scheme + netloc
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    def probe(path):
        url = origin + path
        r = safe_get(url)
        if not r:
            return None
        if r.status_code in [200, 206]:
            body_lower = r.text.lower()
            for kw in SENSITIVE_KEYWORDS:
                if kw.lower() in body_lower:
                    return {
                        "vuln": "Sensitive File Exposed",
                        "severity": "CRITICAL",
                        "detail": f"Path `{path}` returned HTTP 200 and contains sensitive keyword: '{kw}'.",
                        "url": url
                    }
            # Generic 200 on sensitive paths
            return {
                "vuln": "Potentially Sensitive Path Accessible",
                "severity": "MEDIUM",
                "detail": f"Path `{path}` returned HTTP {r.status_code}. Manual review recommended.",
                "url": url
            }
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(probe, path): path for path in SENSITIVE_PATHS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    if not findings:
        findings.append({"vuln": "Directory Traversal / Sensitive Files", "severity": "pass", "detail": "No sensitive paths exposed."})

    return findings


# ─────────────────────────────────────────────
# 5. OPEN REDIRECT
# ─────────────────────────────────────────────
REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnUrl", "return_url",
                   "redirect_uri", "redirectUrl", "goto", "destination", "target", "redir"]
REDIRECT_PAYLOAD = "https://evil.example.com"


def check_open_redirect(base_url):
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for param in REDIRECT_PARAMS:
        test_url = f"{base_url.split('?')[0]}?{param}={urllib.parse.quote(REDIRECT_PAYLOAD)}"
        r = safe_get(test_url)
        if not r:
            continue

        final_url = r.url
        if "evil.example.com" in final_url:
            findings.append({
                "vuln": "Open Redirect",
                "severity": "HIGH",
                "detail": f"Parameter `?{param}=` redirected to external URL: {final_url}",
                "payload": test_url
            })

        # Check Location header even without following redirect
        for resp in r.history:
            loc = resp.headers.get("Location", "")
            if "evil.example.com" in loc:
                findings.append({
                    "vuln": "Open Redirect (via Location header)",
                    "severity": "HIGH",
                    "detail": f"Parameter `?{param}=` set Location header to: {loc}",
                    "payload": test_url
                })

    if not findings:
        findings.append({"vuln": "Open Redirect", "severity": "pass", "detail": "No open redirect parameters found."})

    return findings


# ─────────────────────────────────────────────
# 6. CORS MISCONFIGURATION
# ─────────────────────────────────────────────
def check_cors(base_url):
    findings = []
    try:
        r = SESSION.get(base_url, headers={
            **SESSION.headers,
            "Origin": "https://evil.example.com"
        }, timeout=TIMEOUT, verify=False)
    except Exception:
        return [{"vuln": "CORS Check", "severity": "info", "detail": "Could not test CORS."}]

    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*":
        findings.append({
            "vuln": "CORS: Wildcard Origin",
            "severity": "MEDIUM",
            "detail": "Access-Control-Allow-Origin: * — any website can read API responses."
        })
    elif "evil.example.com" in acao:
        findings.append({
            "vuln": "CORS: Arbitrary Origin Reflected",
            "severity": "CRITICAL",
            "detail": f"Server reflected our fake origin in ACAO header: '{acao}'. Combined with credentials, this allows full cross-origin data theft."
        })

    if acac.lower() == "true" and acao != "*":
        findings.append({
            "vuln": "CORS: Credentials Allowed",
            "severity": "HIGH",
            "detail": "Access-Control-Allow-Credentials: true with a non-wildcard origin. If origin is attacker-controlled, cookies/auth headers are exposed."
        })

    if not findings:
        findings.append({"vuln": "CORS", "severity": "pass", "detail": "No obvious CORS misconfiguration detected."})

    return findings


# ─────────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "message": "VulnScanner API is running"})


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    target_url = data["url"].strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    selected = data.get("checks", ["headers", "sqli", "xss", "traversal", "redirect", "cors"])

    results = {
        "target": target_url,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "findings": {}
    }

    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    scanner_map = {
        "headers":    ("Security Headers",       check_security_headers),
        "sqli":       ("SQL Injection",           check_sql_injection),
        "xss":        ("Cross-Site Scripting",    check_xss),
        "traversal":  ("Directory Traversal",     check_directory_traversal),
        "redirect":   ("Open Redirect",           check_open_redirect),
        "cors":       ("CORS Misconfiguration",   check_cors),
    }

    for key in selected:
        if key in scanner_map:
            label, fn = scanner_map[key]
            try:
                results["findings"][label] = fn(target_url)
            except Exception as e:
                results["findings"][label] = [{"vuln": "Scanner Error", "severity": "info", "detail": str(e)}]

    # Summary counts
    all_findings = [f for group in results["findings"].values() for f in group]
    results["summary"] = {
        "critical": sum(1 for f in all_findings if f.get("severity") == "CRITICAL"),
        "high":     sum(1 for f in all_findings if f.get("severity") == "HIGH"),
        "medium":   sum(1 for f in all_findings if f.get("severity") == "MEDIUM"),
        "low":      sum(1 for f in all_findings if f.get("severity") == "LOW"),
        "passed":   sum(1 for f in all_findings if f.get("severity") == "pass"),
    }

    return jsonify(results)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
