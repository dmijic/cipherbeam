import ssl
import socket
import warnings
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin

import requests
from flask import Flask, request, jsonify, send_from_directory
from bs4 import BeautifulSoup

# Suppress LibreSSL warning if present (macOS)
try:
    from urllib3.exceptions import NotOpenSSLWarning
    warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
except Exception:
    pass

app = Flask(__name__)

TIMEOUT = 8

# -----------------------
# Helpers
# -----------------------

def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        return raw_url
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    if not parsed.netloc:
        raise ValueError("Invalid URL")
    return raw_url


def fetch(url: str):
    """Fetch URL, follow redirects."""
    session = requests.Session()
    headers = {"User-Agent": "SecurityCheckerBot/1.0"}
    resp = session.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
    return resp

# -----------------------
# Checks
# -----------------------

def check_https_and_cert(url: str):
    """Check HTTPS usage, TLS certificate and protocol."""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443

    https_enforced = url.startswith("https://")
    cert_valid = False
    cert_expiry = None
    cert_issuer = None
    tls_protocol = None
    errors = []

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                tls_protocol = ssock.version()

        not_after = cert.get("notAfter")
        if not_after:
            # e.g. 'Jun  1 12:00:00 2025 GMT'
            cert_expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            if cert_expiry > datetime.utcnow():
                cert_valid = True

        issuer = cert.get("issuer")
        if issuer:
            cert_issuer = ", ".join("=".join(x) for x in issuer[0])
    except Exception as e:
        errors.append(str(e))

    weak_tls = tls_protocol in ("TLSv1", "TLSv1.1")

    if not https_enforced:
        msg = "Site does not enforce HTTPS."
        recommendation = (
            "Serve the site over HTTPS only and redirect all http:// traffic to https://.\n\n"
            "Example (Apache .htaccess):\n"
            "  RewriteEngine On\n"
            "  RewriteCond %{HTTPS} !=on\n"
            "  RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n\n"
            "You can use a free certificate from Let's Encrypt or a commercial CA."
        )
        status = "warning"
        delta = -20
    elif not cert_valid:
        msg = "TLS certificate is invalid or expired."
        recommendation = (
            "Renew the TLS certificate and ensure the domain and hostname match the site.\n\n"
            "If you use Let's Encrypt (certbot), schedule automatic renewal (e.g. via cron) "
            "so the certificate is refreshed before expiry.\n"
            "Also double-check intermediate certificate chains so browsers trust it properly."
        )
        status = "warning"
        delta = -20
    else:
        msg = "HTTPS is enabled with a valid certificate."
        recommendation = (
            "Your site uses HTTPS with a valid certificate.\n\n"
            "Best practices:\n"
            "  • Only allow modern TLS versions (TLS 1.2 and TLS 1.3).\n"
            "  • Disable legacy protocols (TLS 1.0 / 1.1).\n"
            "  • Monitor certificate expiry and renew a few days before the deadline."
        )
        status = "ok"
        delta = 20

    if weak_tls:
        msg += " Server also supports legacy TLS versions."
        recommendation += (
            "\n\nSecurity tip: Disable TLS 1.0 and 1.1 in your web server configuration. "
            "Most modern clients support TLS 1.2+ and do not need these older protocols."
        )
        delta -= 5
        if status == "ok":
            status = "warning"

    return {
        "id": "https_tls",
        "name": "HTTPS & TLS",
        "status": status,
        "score_delta": delta,
        "message": msg,
        "description": (
            "Checks whether the site is served over HTTPS, whether the TLS certificate is valid, "
            "and which TLS protocol version is negotiated."
        ),
        "recommendation": recommendation,
        "details": {
            "https_enforced": https_enforced,
            "cert_valid": cert_valid,
            "cert_expiry": cert_expiry.isoformat() if cert_expiry else None,
            "cert_issuer": cert_issuer,
            "tls_protocol": tls_protocol,
            "weak_tls": weak_tls,
            "errors": errors,
        },
    }


SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces browsers to always use HTTPS for your domain.",
    "Content-Security-Policy": "Limits which sources can load scripts, styles, images and other resources.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing (usually set to 'nosniff').",
    "Referrer-Policy": "Controls how much referrer information is sent to other sites.",
    "Permissions-Policy": "Controls powerful browser features (camera, mic, geolocation, etc.).",
    "X-Frame-Options": "Helps prevent clickjacking by controlling who can embed your site in an iframe.",
    "Cross-Origin-Resource-Policy": "Controls which origins can load resources (CORP).",
    "Cross-Origin-Embedder-Policy": "Controls embedding cross-origin content (COEP).",
    "Cross-Origin-Opener-Policy": "Isolates browsing contexts (COOP).",
}

def check_security_headers(resp: requests.Response):
    """Check presence and quality of key security headers."""
    headers = resp.headers
    checks = []
    score = 0
    for hname, description in SECURITY_HEADERS.items():
        present = hname in headers
        status = "ok" if present else "warning"
        delta = 3 if present else -3
        score += delta
        checks.append(
            {
                "header": hname,
                "present": present,
                "value": headers.get(hname),
                "status": status,
                "score_delta": delta,
                "description": description,
            }
        )

    csp_analysis = None
    csp = headers.get("Content-Security-Policy")
    if csp:
        issues = []
        if "'unsafe-inline'" in csp:
            issues.append("Uses 'unsafe-inline', which weakens protection against XSS.")
        if "'unsafe-eval'" in csp:
            issues.append("Uses 'unsafe-eval', which also weakens XSS protection.")
        if "*" in csp:
            issues.append(
                "Uses wildcard * in CSP directives. Limit script-src, style-src, img-src etc. "
                "to specific domains where possible."
            )
        csp_analysis = {
            "policy": csp,
            "issues": issues,
        }

    status = "ok" if score > 0 else "warning"
    if status == "ok":
        msg = "Most recommended security headers are present."
        recommendation = (
            "Your security headers look mostly good.\n\n"
            "Use this as a quick checklist:\n"
            "  • Strict-Transport-Security (HSTS) with a long max-age.\n"
            "  • Content-Security-Policy with strict script-src/style-src.\n"
            "  • X-Content-Type-Options: nosniff.\n"
            "  • X-Frame-Options: SAMEORIGIN or frame-ancestors in CSP.\n"
            "  • Referrer-Policy: no-referrer, strict-origin or strict-origin-when-cross-origin.\n"
            "  • Permissions-Policy: explicitly disable unused features."
        )
    else:
        msg = "Some important security headers are missing or weak."
        recommendation = (
            "Add and harden key security headers on your site. For example:\n\n"
            "  • Strict-Transport-Security:\n"
            "      Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\n"
            "  • Content-Security-Policy (simple example):\n"
            "      Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:\n\n"
            "  • X-Frame-Options:\n"
            "      X-Frame-Options: SAMEORIGIN\n\n"
            "  • X-Content-Type-Options:\n"
            "      X-Content-Type-Options: nosniff\n\n"
            "These headers significantly reduce the impact of common attacks such as XSS and clickjacking."
        )

    return {
        "id": "security_headers",
        "name": "Security HTTP headers",
        "status": status,
        "score_delta": score,
        "message": msg,
        "description": (
            "Analyzes the presence of recommended HTTP security headers on the main response "
            "(HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, etc.)."
        ),
        "recommendation": recommendation,
        "details": {
            "headers": checks,
            "csp_analysis": csp_analysis,
        },
    }


def parse_cookies(resp: requests.Response):
    cookies_info = []
    set_cookie_headers = resp.headers.get("Set-Cookie")
    if not set_cookie_headers:
        return []

    raw = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else [resp.headers["Set-Cookie"]]
    for sc in raw:
        parts = sc.split(";")
        name_value = parts[0].strip()
        if "=" in name_value:
            name, value = name_value.split("=", 1)
        else:
            name, value = name_value, ""
        attrs = {"Secure": False, "HttpOnly": False, "SameSite": None}
        for attr in parts[1:]:
            a = attr.strip()
            if a.lower() == "secure":
                attrs["Secure"] = True
            elif a.lower() == "httponly":
                attrs["HttpOnly"] = True
            elif a.lower().startswith("samesite"):
                _, v = a.split("=", 1)
                attrs["SameSite"] = v.strip()
        cookies_info.append({"name": name, "attributes": attrs})
    return cookies_info


def check_cookies(resp: requests.Response):
    """Check cookie security flags (Secure, HttpOnly, SameSite)."""
    cookies = parse_cookies(resp)
    if not cookies:
        return {
            "id": "cookies",
            "name": "Cookies",
            "status": "info",
            "score_delta": 0,
            "message": "No cookies detected on the initial response.",
            "description": (
                "Checks whether cookies returned by the server include security flags such as "
                "Secure, HttpOnly and SameSite."
            ),
            "recommendation": (
                "If your application uses sessions or authentication cookies, ensure that those cookies:\n"
                "  • Are only set over HTTPS (Secure flag).\n"
                "  • Are not accessible from JavaScript (HttpOnly flag).\n"
                "  • Include an appropriate SameSite attribute (Lax or Strict where possible).\n\n"
                "Even if this particular response does not set cookies, review your login and API "
                "responses to confirm they follow these rules."
            ),
            "details": {"cookies": [], "problems": []},
        }

    problems = []
    score = 0
    for c in cookies:
        attrs = c["attributes"]
        if not attrs["Secure"]:
            problems.append(f"Cookie '{c['name']}' is missing the Secure flag.")
            score -= 3
        else:
            score += 1
        if not attrs["HttpOnly"]:
            problems.append(f"Cookie '{c['name']}' is missing the HttpOnly flag.")
            score -= 3
        else:
            score += 1
        if attrs["SameSite"] is None:
            problems.append(f"Cookie '{c['name']}' is missing the SameSite attribute.")
            score -= 2
        elif attrs["SameSite"].lower() == "none" and not attrs["Secure"]:
            problems.append(f"Cookie '{c['name']}' uses SameSite=None without Secure.")
            score -= 4
        else:
            score += 1

    status = "ok" if score >= 0 and not problems else "warning"
    if status == "ok":
        msg = "Cookies use recommended security attributes."
        recommendation = (
            "Your cookies look well-configured from a security point of view.\n\n"
            "Keep in mind:\n"
            "  • Session cookies should always have Secure and HttpOnly.\n"
            "  • SameSite=Lax is a good default; use Strict for highly sensitive actions.\n"
            "  • SameSite=None must be combined with Secure.\n\n"
            "Review cookies again whenever you add new features or third-party integrations."
        )
    else:
        msg = "Some cookies are missing recommended security attributes."
        recommendation = (
            "Harden your cookies, especially authentication and session cookies:\n\n"
            "  • Add Secure: the cookie is only sent over HTTPS.\n"
            "  • Add HttpOnly: JavaScript cannot read or modify the cookie.\n"
            "  • Add SameSite: Lax or Strict reduces CSRF risks.\n\n"
            "Example of a strong session cookie:\n"
            "  Set-Cookie: SESSIONID=...; Path=/; Secure; HttpOnly; SameSite=Lax\n"
        )

    return {
        "id": "cookies",
        "name": "Cookies",
        "status": status,
        "score_delta": score,
        "message": msg,
        "description": "Checks Secure, HttpOnly and SameSite flags on cookies returned by the site.",
        "recommendation": recommendation,
        "details": {
            "cookies": cookies,
            "problems": problems,
        },
    }


def check_mixed_content(resp: requests.Response):
    """Check if HTTPS page loads HTTP resources (mixed content)."""
    url = resp.url
    if not url.startswith("https://"):
        return {
            "id": "mixed_content",
            "name": "Mixed content",
            "status": "info",
            "score_delta": 0,
            "message": "Mixed content check is only relevant for HTTPS pages.",
            "description": (
                "Mixed content occurs when an HTTPS page loads resources (scripts, styles, images) over HTTP. "
                "This can allow attackers to tamper with those resources."
            ),
            "recommendation": (
                "If your site uses HTTPS, make sure all resources (scripts, styles, images, iframes) are also "
                "loaded over HTTPS or via relative URLs."
            ),
            "details": {"issues": []},
        }
    issues = []
    try:
        soup = BeautifulSoup(resp.text, "html.parser")
        attrs = ["src", "href"]
        for tag in soup.find_all(True):
            for attr in attrs:
                val = tag.get(attr)
                if not val:
                    continue
                if val.startswith("//"):
                    # protocol-relative URL, typically fine (uses https on https pages)
                    continue
                if val.startswith("http://"):
                    issues.append({"tag": tag.name, "attr": attr, "url": val})
    except Exception as e:
        return {
            "id": "mixed_content",
            "name": "Mixed content",
            "status": "warning",
            "score_delta": -2,
            "message": f"Error parsing HTML for mixed content: {e}",
            "description": (
                "Tried to analyze the HTML for mixed content but encountered a parsing error."
            ),
            "recommendation": (
                "Manually review your HTML templates and ensure all external resources use HTTPS.\n"
                "Search your codebase for 'http://' references."
            ),
            "details": {"issues": []},
        }

    if issues:
        return {
            "id": "mixed_content",
            "name": "Mixed content",
            "status": "warning",
            "score_delta": -10,
            "message": "HTTPS page is loading HTTP resources (mixed content).",
            "description": (
                "Mixed content weakens the security guarantees of HTTPS and can allow attackers to intercept or "
                "modify resources loaded over plain HTTP."
            ),
            "recommendation": (
                "Update all 'http://' URLs for scripts, styles, images and iframes to 'https://' or use relative URLs.\n\n"
                "Example:\n"
                "  <script src=\"http://cdn.example.com/app.js\"></script>\n"
                "…should become…\n"
                "  <script src=\"https://cdn.example.com/app.js\"></script>\n"
                "or\n"
                "  <script src=\"//cdn.example.com/app.js\"></script> (protocol-relative)."
            ),
            "details": {"issues": issues},
        }
    else:
        return {
            "id": "mixed_content",
            "name": "Mixed content",
            "status": "ok",
            "score_delta": 5,
            "message": "No mixed content detected on the scanned page.",
            "description": (
                "All resources on the HTTPS page appear to be loaded securely (no plain HTTP resources found)."
            ),
            "recommendation": (
                "Continue to ensure that any new assets or third-party scripts are loaded over HTTPS only."
            ),
            "details": {"issues": []},
        }


def check_server_info(resp: requests.Response):
    """Check whether server exposes detailed version information."""
    server = resp.headers.get("Server")
    x_powered = resp.headers.get("X-Powered-By")
    exposed = []
    if server and any(ch.isdigit() for ch in server):
        exposed.append(f"Server header exposes version: {server}")
    if x_powered and any(ch.isdigit() for ch in x_powered):
        exposed.append(f"X-Powered-By exposes technology/version: {x_powered}")

    if exposed:
        status = "warning"
        delta = -5
        msg = "Server exposes detailed version information."
        recommendation = (
            "Remove or simplify headers that reveal exact versions of your web server, runtime and framework.\n\n"
            "Attackers often search for a specific version to match known exploits.\n\n"
            "Examples:\n"
            "  • Hide or genericize the 'Server' header (e.g. 'Server: nginx' instead of 'nginx/1.18.0').\n"
            "  • Remove 'X-Powered-By: PHP/8.1.2' and similar headers from responses.\n"
        )
    else:
        status = "ok"
        delta = 3
        msg = "Server does not expose detailed version info (or exposes minimal data)."
        recommendation = (
            "Your server does not reveal detailed version numbers, which is good.\n\n"
            "Keep your stack updated and ensure that future configuration or modules do not reintroduce "
            "verbose version headers."
        )

    return {
        "id": "server_info",
        "name": "Server information exposure",
        "status": status,
        "score_delta": delta,
        "message": msg,
        "description": (
            "Looks at the 'Server' and 'X-Powered-By' headers to see whether detailed version information "
            "is exposed."
        ),
        "recommendation": recommendation,
        "details": {
            "server": server,
            "x_powered_by": x_powered,
            "issues": exposed,
        },
    }


def check_security_txt(url: str):
    """Check for /.well-known/security.txt."""
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    sec_url = urljoin(base, "/.well-known/security.txt")
    status_code = None
    has_contact = False
    try:
        resp = requests.get(sec_url, timeout=TIMEOUT)
        status_code = resp.status_code
        if resp.status_code == 200 and "contact:" in resp.text.lower():
            has_contact = True
    except Exception:
        pass

    if has_contact:
        return {
            "id": "security_txt",
            "name": "security.txt",
            "status": "ok",
            "score_delta": 3,
            "message": "security.txt file found with a contact entry.",
            "description": (
                "Checks for a .well-known/security.txt file, which provides contact details and security "
                "policy information for vulnerability reports."
            ),
            "recommendation": (
                "Keep security.txt up to date with a monitored contact address and clear disclosure policy.\n\n"
                "Example:\n"
                "  Contact: mailto:security@example.com\n"
                "  Encryption: https://example.com/pgp-key.txt\n"
                "  Acknowledgements: https://example.com/security-hall-of-fame\n"
            ),
            "details": {
                "url": sec_url,
                "status_code": status_code,
            },
        }
    else:
        return {
            "id": "security_txt",
            "name": "security.txt",
            "status": "info",
            "score_delta": 0,
            "message": "No security.txt file found (optional but recommended for larger sites).",
            "description": (
                "security.txt is an emerging standard for publishing security contact information and "
                "disclosure guidelines at /.well-known/security.txt."
            ),
            "recommendation": (
                "Consider adding a security.txt file if your site is public-facing or handles sensitive data.\n"
                "It helps security researchers reach the right people and reduces the risk of reports being missed."
            ),
            "details": {
                "url": sec_url,
                "status_code": status_code,
            },
        }


def check_cors(resp: requests.Response):
    """Check CORS (Access-Control-Allow-Origin)."""
    aco = resp.headers.get("Access-Control-Allow-Origin")
    if not aco:
        return {
            "id": "cors",
            "name": "CORS policy",
            "status": "info",
            "score_delta": 0,
            "message": "No explicit CORS headers detected.",
            "description": (
                "CORS (Cross-Origin Resource Sharing) controls which websites can access your API using "
                "browser-side JavaScript."
            ),
            "recommendation": (
                "If your site does not expose an API for use from other domains, you may not need CORS at all.\n\n"
                "If you do expose an API, configure CORS to allow only trusted front-end origins "
                "instead of using a wildcard."
            ),
            "details": {"origin": None},
        }
    if aco == "*":
        return {
            "id": "cors",
            "name": "CORS policy",
            "status": "warning",
            "score_delta": -5,
            "message": "CORS allows all origins (*).",
            "description": (
                "The response includes Access-Control-Allow-Origin: *, which means any website can make "
                "AJAX requests to this endpoint from a user's browser."
            ),
            "recommendation": (
                "Avoid using Access-Control-Allow-Origin: * for endpoints that handle authenticated or "
                "sensitive data.\n\n"
                "Instead, restrict CORS to specific trusted domains, for example:\n"
                "  Access-Control-Allow-Origin: https://app.example.com\n"
            ),
            "details": {"origin": aco},
        }
    else:
        return {
            "id": "cors",
            "name": "CORS policy",
            "status": "ok",
            "score_delta": 2,
            "message": f"CORS is configured for a specific origin: {aco}",
            "description": (
                "CORS appears to be restricted to a specific origin rather than to all sites."
            ),
            "recommendation": (
                "Confirm that only trusted front-end domains are allowed via CORS and that sensitive "
                "endpoints require proper authentication and authorization."
            ),
            "details": {"origin": aco},
        }


def check_http_methods(url: str):
    """Check advertised HTTP methods via OPTIONS."""
    try:
        resp = requests.options(url, timeout=TIMEOUT)
    except Exception as e:
        return {
            "id": "http_methods",
            "name": "HTTP methods",
            "status": "info",
            "score_delta": 0,
            "message": f"Could not determine allowed HTTP methods: {e}",
            "description": (
                "Attempts to read the Allow header from an OPTIONS response to see which HTTP methods "
                "the server advertises."
            ),
            "recommendation": (
                "Limit enabled HTTP methods on your site to only those you actually use.\n"
                "Common safe methods: GET, HEAD, POST. Be careful with PUT, DELETE, TRACE, CONNECT, etc."
            ),
            "details": {"allowed": []},
        }
    allow = resp.headers.get("Allow")
    if not allow:
        return {
            "id": "http_methods",
            "name": "HTTP methods",
            "status": "info",
            "score_delta": 0,
            "message": "The server did not advertise supported HTTP methods.",
            "description": (
                "No Allow header was returned, so the list of supported HTTP methods cannot be inferred "
                "from this simple check."
            ),
            "recommendation": (
                "Review your web server and application configuration to ensure unnecessary methods "
                "are disabled by default."
            ),
            "details": {"allowed": []},
        }
    methods = [m.strip().upper() for m in allow.split(",")]
    dangerous = [m for m in methods if m in ("PUT", "DELETE", "TRACE", "CONNECT")]
    if dangerous:
        return {
            "id": "http_methods",
            "name": "HTTP methods",
            "status": "warning",
            "score_delta": -5,
            "message": f"Potentially dangerous HTTP methods are enabled: {', '.join(dangerous)}.",
            "description": (
                "Some HTTP methods, such as PUT, DELETE, TRACE or CONNECT, can increase the attack surface "
                "if exposed on public endpoints."
            ),
            "recommendation": (
                "Disable risky methods (PUT, DELETE, TRACE, CONNECT) at the web server level unless they are "
                "strictly necessary and protected by additional security controls.\n\n"
                "For APIs that legitimately use PUT/DELETE, ensure they require strong authentication and "
                "authorization and are not exposed broadly to the public internet."
            ),
            "details": {"allowed": methods},
        }
    else:
        return {
            "id": "http_methods",
            "name": "HTTP methods",
            "status": "ok",
            "score_delta": 2,
            "message": f"Only common HTTP methods are advertised: {', '.join(methods)}.",
            "description": (
                "The Allow header only lists common HTTP methods, which is usually a good sign."
            ),
            "recommendation": (
                "Continue to keep the set of enabled HTTP methods as small as possible. When adding new APIs, "
                "review their supported methods and restrict them appropriately."
            ),
            "details": {"allowed": methods},
        }


def check_directory_listing(url: str):
    """Check for obvious directory listing on common paths."""
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    paths = ["/", "/images/", "/img/", "/uploads/", "/files/", "/backup/", "/backups/"]
    found = []

    for p in paths:
        try:
            resp = requests.get(urljoin(base, p), timeout=TIMEOUT)
            if resp.status_code == 200 and (
                "Index of /" in resp.text or "<title>Index of" in resp.text
            ):
                found.append(urljoin(base, p))
        except Exception:
            continue

    if found:
        return {
            "id": "directory_listing",
            "name": "Directory listing",
            "status": "warning",
            "score_delta": -7,
            "message": "Directory listing appears to be enabled on some paths.",
            "description": (
                "Directory listing allows visitors to see the contents of a folder if no index page is present. "
                "This can expose backups, uploads or internal files."
            ),
            "recommendation": (
                "Disable directory listing on production servers, especially for upload, backup and log folders.\n\n"
                "Examples:\n"
                "  • Apache:  Options -Indexes\n"
                "  • Nginx:   autoindex off;\n\n"
                "Also ensure sensitive files (e.g. .sql dumps, .env files, .log files) are not stored in web-accessible directories."
            ),
            "details": {"paths": found},
        }
    else:
        return {
            "id": "directory_listing",
            "name": "Directory listing",
            "status": "ok",
            "score_delta": 3,
            "message": "No obvious directory listings were detected on common paths.",
            "description": (
                "The scanner did not find 'Index of /' pages on common public folders such as /uploads or /backup."
            ),
            "recommendation": (
                "If you use custom folders for uploads or backups, verify that they are not world-browsable "
                "and that sensitive files are not stored in web-accessible locations."
            ),
            "details": {"paths": []},
        }


def check_cms_fingerprint(resp: requests.Response):
    """Try to detect common CMS (WordPress, Joomla, Drupal) and version."""
    html = resp.text
    soup = BeautifulSoup(html, "html.parser")
    generator = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
    cms = None
    version = None
    hints = []

    if generator and generator.has_attr("content"):
        content = generator["content"]
        hints.append(f"meta generator: {content}")
        if "wordpress" in content.lower():
            cms = "WordPress"
        elif "joomla" in content.lower():
            cms = "Joomla"
        elif "drupal" in content.lower():
            cms = "Drupal"
        m = re.search(r"([0-9]+(?:\.[0-9]+)+)", content)
        if m:
            version = m.group(1)

    if "wp-content" in html or "wp-includes" in html:
        cms = cms or "WordPress"
        hints.append("Found wp-content/wp-includes in HTML.")
    if "Joomla!" in html:
        cms = cms or "Joomla"
        hints.append("Found 'Joomla!' string in HTML.")
    if "sites/all/modules" in html:
        cms = cms or "Drupal"
        hints.append("Found 'sites/all/modules' (Drupal path).")

    if cms:
        msg = f"Detected CMS: {cms}" + (f" {version}" if version else "")
        recommendation = (
            f"If you are using {cms}, make sure:\n\n"
            "  • The core CMS is updated to the latest stable release.\n"
            "  • Plugins, themes and extensions are regularly updated.\n"
            "  • Unused plugins/themes are removed, not just disabled.\n"
            "  • The admin area is protected (strong passwords, 2FA, restricted IPs where possible).\n"
        )
        status = "info"
        delta = 0
    else:
        msg = "No obvious CMS fingerprint detected."
        recommendation = (
            "If you are using a CMS, consider hiding version information from meta tags and public pages.\n"
            "Do not rely on 'security through obscurity', but reducing exposed details makes targeted attacks harder."
        )
        status = "info"
        delta = 0

    return {
        "id": "cms_fingerprint",
        "name": "CMS fingerprint",
        "status": status,
        "score_delta": delta,
        "message": msg,
        "description": "Tries to infer if the site runs a popular CMS such as WordPress, Joomla or Drupal.",
        "recommendation": recommendation,
        "details": {
            "cms": cms,
            "version": version,
            "hints": hints,
        },
    }


def check_robots_txt(url: str):
    """Check robots.txt presence and interesting Disallow entries."""
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    robots_url = urljoin(base, "/robots.txt")
    interesting = []
    status_code = None
    try:
        resp = requests.get(robots_url, timeout=TIMEOUT)
        status_code = resp.status_code
        if resp.status_code == 200:
            lines = resp.text.splitlines()
            for line in lines:
                lower = line.strip().lower()
                if lower.startswith("disallow:"):
                    path = lower.split(":", 1)[1].strip()
                    if any(
                        keyword in path
                        for keyword in ("/admin", "/backup", "/config", "/private", "/tmp", "/logs")
                    ):
                        interesting.append(path)
    except Exception:
        pass

    if status_code is None:
        msg = "robots.txt could not be reached."
        recommendation = (
            "Check whether robots.txt is accessible and configured as you expect.\n"
            "Search engines may still crawl pages even without a robots.txt file."
        )
    elif status_code == 404:
        msg = "robots.txt not found."
        recommendation = (
            "Consider adding a robots.txt file if you want to guide search engine crawling and indexing.\n"
            "Example:\n"
            "  User-agent: *\n"
            "  Disallow: /admin\n"
            "  Disallow: /tmp\n"
        )
    else:
        msg = "robots.txt found."
        recommendation = (
            "Review robots.txt to ensure it does not accidentally reveal too many sensitive paths (such as "
            "/backup or /config) and that it does not block pages that you want to be indexed."
        )

    return {
        "id": "robots_txt",
        "name": "robots.txt",
        "status": "info",
        "score_delta": 0,
        "message": msg,
        "description": (
            "Checks whether robots.txt exists and highlights potentially sensitive Disallow paths such as "
            "/admin, /backup, /config, /private, /tmp or /logs."
        ),
        "recommendation": recommendation,
        "details": {
            "url": robots_url,
            "status_code": status_code,
            "interesting_disallows": interesting,
        },
    }


def check_password_forms(resp: requests.Response):
    """Find password forms that might post over HTTP or appear on non-HTTPS pages."""
    url = resp.url
    is_https_page = url.startswith("https://")
    soup = BeautifulSoup(resp.text, "html.parser")
    insecure_forms = []

    forms = soup.find_all("form")
    for f in forms:
        has_password = bool(f.find("input", attrs={"type": "password"}))
        if not has_password:
            continue
        action = f.get("action") or ""
        full_action = urljoin(url, action)
        if full_action.startswith("http://") or (not is_https_page):
            insecure_forms.append(
                {
                    "form_action": full_action,
                    "on_https_page": is_https_page,
                }
            )

    if insecure_forms:
        return {
            "id": "password_forms",
            "name": "Login forms",
            "status": "warning",
            "score_delta": -15,
            "message": "Detected password forms that may send credentials over HTTP or appear on non-HTTPS pages.",
            "description": (
                "Password or login forms should always be served over HTTPS and submit credentials to an HTTPS endpoint."
            ),
            "recommendation": (
                "Move all login, registration and password reset forms onto HTTPS pages and make sure the form's "
                "action attribute points to an HTTPS URL.\n\n"
                "Example:\n"
                "  <form action=\"https://example.com/login\" method=\"post\"> ... </form>\n\n"
                "Avoid mixing HTTP and HTTPS in the authentication flow, as it exposes credentials to interception."
            ),
            "details": {
                "insecure_forms": insecure_forms,
            },
        }
    else:
        return {
            "id": "password_forms",
            "name": "Login forms",
            "status": "ok",
            "score_delta": 5,
            "message": "No obviously insecure password forms detected.",
            "description": (
                "The scanner did not find password forms posting over HTTP or on non-HTTPS pages."
            ),
            "recommendation": (
                "Whenever you add or modify login, registration or password reset forms, verify that the entire "
                "flow runs over HTTPS only."
            ),
            "details": {
                "insecure_forms": [],
            },
        }


def aggregate_score(checks):
    """Aggregate individual check score_deltas into a 0–100 score and a grade label."""
    score = 0
    for c in checks:
        score += c.get("score_delta", 0)
    score = max(0, min(100, score + 50))
    if score >= 80:
        grade = "good"
    elif score >= 60:
        grade = "ok"
        # fallthrough
    else:
        grade = "risky"
    return score, grade

# -----------------------
# Flask routes
# -----------------------

@app.route("/")
def index():
    """Serve the frontend."""
    return send_from_directory(".", "index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    """Main scan endpoint – runs all checks and returns JSON."""
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "")
    if not raw_url:
        return jsonify({"error": "url is required"}), 400
    try:
        url = normalize_url(raw_url)
    except Exception as e:
        return jsonify({"error": f"Invalid URL: {e}"}), 400

    try:
        resp = fetch(url)
    except Exception as e:
        return jsonify({"error": f"Failed to fetch URL: {e}"}), 502

    checks = []
    checks.append(check_https_and_cert(url))
    checks.append(check_security_headers(resp))
    checks.append(check_cookies(resp))
    checks.append(check_mixed_content(resp))
    checks.append(check_server_info(resp))
    checks.append(check_security_txt(url))
    checks.append(check_cors(resp))
    checks.append(check_http_methods(url))
    checks.append(check_directory_listing(url))
    checks.append(check_cms_fingerprint(resp))
    checks.append(check_robots_txt(url))
    checks.append(check_password_forms(resp))

    score, grade = aggregate_score(checks)

    result = {
        "url": url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "score": score,
        "grade": grade,
        "checks": checks,
    }
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
