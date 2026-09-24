"""Check response headers with one explicit, unauthenticated GET request."""

from email.message import Message
from http.client import HTTPException
import ipaddress
import math
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .models import CoverageNote, Finding, RULES, SEVERITIES, ScanReport


_TOKEN = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_QUOTED = r'"(?:[\t\x20-\x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t\x20-\x7e])*"'
_HSTS_DIRECTIVE = re.compile(rf"({_TOKEN})(?:[ \t]*=[ \t]*({_TOKEN}|{_QUOTED}))?")
_COOKIE_VALUE = re.compile(r'[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*')
_MAX_HEADER_LENGTH = 65536


def _has_positive_hsts(value: str) -> bool:
    """Validate RFC 6797 directives, including quoting and duplicate names."""
    if len(value) > _MAX_HEADER_LENGTH:
        return False
    # Semicolons in quoted extension values are data, not new directives.
    directives = []
    start = 0
    quoted = escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == ";" and not quoted:
            directives.append(value[start:index])
            start = index + 1
    if quoted or escaped:
        return False
    directives.append(value[start:])
    seen = set()
    positive_max_age = False
    for directive in directives:
        directive = directive.strip(" \t")
        if not directive:
            continue  # Empty directives are permitted by the header grammar.
        match = _HSTS_DIRECTIVE.fullmatch(directive)
        if match is None:
            return False
        name, argument = match.groups()
        name = name.lower()
        if name in seen:
            return False
        seen.add(name)
        if name == "includesubdomains" and argument is not None:
            return False
        if name == "max-age":
            if argument is None:
                return False
            if argument.startswith('"'):
                argument = re.sub(r"\\(.)", r"\1", argument[1:-1])
            if re.fullmatch(r"[0-9]+", argument) is None:
                return False
            # Avoid converting arbitrarily large server-controlled integers.
            positive_max_age = bool(argument.strip("0"))
    return positive_max_age


def _cookie_protections(value: str) -> tuple[bool, bool, str] | None:
    """Parse one Set-Cookie pair and its relevant attributes, discarding data.

    RFC 6265 separates the initial cookie pair from attributes at the first
    semicolon; unknown attributes are ignored, even when they have values.
    Malformed or unsupported initial pairs return None for incomplete coverage.
    """
    if (len(value) > _MAX_HEADER_LENGTH
            or any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value)):
        return None
    pair, _, attributes = value.partition(";")
    name, separator, cookie_value = pair.partition("=")
    name, cookie_value = name.strip(" \t"), cookie_value.strip(" \t")
    if not separator or re.fullmatch(_TOKEN, name) is None:
        return None
    if cookie_value.startswith('"'):
        if len(cookie_value) < 2 or not cookie_value.endswith('"'):
            return None
        cookie_value = cookie_value[1:-1]
    if _COOKIE_VALUE.fullmatch(cookie_value) is None:
        return None
    secure = http_only = False
    same_site = ""
    for attribute in attributes.split(";"):
        name, _, argument = attribute.partition("=")
        name, argument = name.strip(" \t").lower(), argument.strip(" \t")
        if name == "secure":
            secure = True  # Attribute presence sets the flag, even Secure=no.
        elif name == "httponly":
            http_only = True
        elif name == "samesite":
            same_site = argument.lower()
    return secure, http_only, same_site


class _NoRedirect(HTTPRedirectHandler):
    """Return every redirect as a response without inspecting its destination."""

    def http_error_302(self, request, response, code, message, headers):
        return response

    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302
    http_error_308 = http_error_302


def _normalize_url(url: str) -> str:
    if (not isinstance(url, str) or not url or len(url) > 8192
            or any(ord(char) <= 32 or ord(char) == 127 for char in url)
            or "\\" in url):
        raise ValueError("Provide an HTTP(S) URL without whitespace or control characters.")
    if "?" in url or "#" in url:
        raise ValueError("Probe URLs must not contain query strings or fragments.")
    try:
        parsed = urlsplit(url)
        host, port = parsed.hostname, parsed.port
    except (ValueError, UnicodeError):
        raise ValueError("Provide an HTTP(S) URL with a valid hostname and port.") from None
    if parsed.scheme not in {"http", "https"} or not host:
        raise ValueError("Provide an HTTP(S) URL with a valid hostname.")
    if "@" in parsed.netloc:
        raise ValueError("Probe URLs must not contain credentials.")
    if parsed.netloc.endswith(":") or port == 0:
        raise ValueError("The URL port must be between 1 and 65535.")
    if parsed.netloc.startswith("[") and not re.fullmatch(r"\[[^\]]+\](?::[0-9]+)?", parsed.netloc):
        raise ValueError("Provide a URL with a valid bracketed IPv6 address.")
    if "%" in host:
        raise ValueError("Percent-encoded hostnames and IPv6 zone identifiers are unsupported.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if parsed.netloc.startswith("["):
            raise ValueError("Only IPv6 addresses may use a bracketed URL hostname.") from None
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ValueError("Provide a URL with a valid hostname.") from None
        labels = (host[:-1] if host.endswith(".") else host).split(".")
        if (len(host) > 253 or any(not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
            raise ValueError("Provide a URL with a valid hostname.")
    else:
        host = f"[{address.compressed}]" if address.version == 6 else str(address)
    if port is not None:
        host += f":{port}"
    if re.search(r"%(?![0-9a-fA-F]{2})", parsed.path):
        raise ValueError("URL paths must use valid percent encoding.")
    path = quote(parsed.path or "/", safe="/:@!$&'()*+,;=-._~%")
    return urlunsplit((parsed.scheme, host, path, "", ""))


def _add(report: ScanReport, rule_id: str, severity: str, confidence: str,
         message: str, recommendation: str, cwe: str, **details) -> None:
    report.findings.append(Finding(
        rule_id=rule_id, title=RULES[rule_id], severity=severity,
        confidence=confidence, path=report.root, line=1, column=1,
        message=message, recommendation=recommendation, cwe=cwe, details=details,
    ))


def _inspect_headers(report: ScanReport, headers: Message) -> None:
    https = report.root.startswith("https:")
    hsts = headers.get("Strict-Transport-Security", "")
    if https and not _has_positive_hsts(hsts):
        _add(report, "HTTP002", "medium", "high",
             "The HTTPS response does not advertise HSTS with a positive max-age. "
             "This check cannot observe policies inherited from a parent domain or a browser preload list.",
             "After confirming HTTPS support, configure Strict-Transport-Security with an appropriate "
             "positive max-age; assess subdomains before enabling includeSubDomains.", "CWE-319")

    content_type = headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if content_type in {"text/html", "application/xhtml+xml"}:
        if headers.get("X-Content-Type-Options", "").strip().lower() != "nosniff":
            _add(report, "HTTP003", "low", "high",
                 "The HTML response does not set X-Content-Type-Options to nosniff.",
                 "Return X-Content-Type-Options: nosniff with accurate Content-Type headers.", "CWE-693")
        if not any(value.strip() for value in headers.get_all("Content-Security-Policy", [])):
            _add(report, "HTTP004", "medium", "medium",
                 "The HTML response has no enforcing Content-Security-Policy header. "
                 "The response body is not inspected for a policy in a meta element.",
                 "Develop and test a restrictive Content-Security-Policy for this application's "
                 "script and resource requirements, then enforce it in the response header.", "CWE-693")
    else:
        report.coverage.append(CoverageNote(report.root,
            "HTML-specific header checks were skipped because Content-Type was not HTML.", "skipped"))

    counts = {"HTTP005": 0, "HTTP006": 0, "HTTP007": 0}
    malformed = False
    for value in headers.get_all("Set-Cookie", []):
        protections = _cookie_protections(value)
        if protections is None:
            malformed = True
            continue
        secure, http_only, same_site = protections
        if https and not secure:
            counts["HTTP005"] += 1
        if not http_only:
            counts["HTTP006"] += 1
        if same_site not in {"strict", "lax"}:
            counts["HTTP007"] += 1
    if malformed:
        report.coverage.append(CoverageNote(report.root,
            "At least one Set-Cookie header could not be parsed; cookie checks are incomplete.", "error"))
    cookie_checks = {
        "HTTP005": ("medium", "Secure", "CWE-614",
                    "Set Secure on sensitive cookies so browsers restrict them to HTTPS."),
        "HTTP006": ("medium", "HttpOnly", "CWE-1004",
                    "Set HttpOnly on session and other sensitive cookies that JavaScript does not need."),
        "HTTP007": ("low", "an explicit SameSite=Lax or SameSite=Strict", "CWE-1275",
                    "Use SameSite=Lax or SameSite=Strict where compatible. Cross-site cookies require "
                    "SameSite=None; Secure and appropriate CSRF defenses."),
    }
    for rule_id, count in counts.items():
        if count:
            severity, attribute, cwe, recommendation = cookie_checks[rule_id]
            _add(report, rule_id, severity, "medium",
                 f"{count} response cookie(s) lack {attribute}. Review their purpose: the probe cannot "
                 "determine which cookies contain session state, and some exceptions are intentional.",
                 recommendation, cwe, cookie_count=count)


def probe(url: str, timeout: float = 10.0) -> ScanReport:
    """Inspect one response, without following redirects or downloading its body.

    ``timeout`` is the socket-operation timeout, not a total wall-clock deadline.
    Only the explicitly supplied URL is requested; no credentials, ambient
    cookies, proxy configuration, or application commands are used.
    """
    normalized = _normalize_url(url)
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout < 120):
        raise ValueError("The HTTP timeout must be finite, greater than 0 and less than 120 seconds.")
    report = ScanReport(root=normalized, mode="http", options={
        "timeout_seconds": timeout, "follow_redirects": False,
        "read_response_body": False, "use_environment_proxies": False,
    })
    if normalized.startswith("http:"):
        _add(report, "HTTP001", "medium", "high",
             "The selected URL uses unencrypted HTTP. Data on this connection is not protected by TLS; "
             "a local development endpoint may intentionally use HTTP.",
             "Serve production traffic over HTTPS and redirect ordinary HTTP requests to HTTPS.", "CWE-319")
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    request = Request(normalized, method="GET", headers={
        "User-Agent": "Tobacco-Security-Audit", "Accept": "text/html, */*;q=0.1",
    })
    report.http_requests = 1
    try:
        try:
            response = opener.open(request, timeout=timeout)
        except HTTPError as error:
            # Error responses still carry useful headers. Never render their
            # text, which can contain server-controlled data or credentials.
            response = error
        with response:
            status = response.status
            report.options["response_status"] = status
            _inspect_headers(report, response.headers)
            if 300 <= status < 400:
                report.coverage.append(CoverageNote(normalized,
                    f"HTTP {status} redirect/conditional response; only these headers were inspected. "
                    "Redirect destinations are not followed.", "skipped"))
            elif status >= 400 or status < 200:
                report.coverage.append(CoverageNote(normalized,
                    f"HTTP {status} response; application coverage is incomplete.", "error"))
    except (URLError, OSError, HTTPException) as error:
        reason = error.reason if isinstance(error, URLError) else error
        if isinstance(reason, ssl.SSLCertVerificationError):
            _add(report, "HTTP008", "high", "high",
                 "TLS certificate validation failed for the selected endpoint. No unverified retry was made.",
                 "Check the certificate hostname, expiry, and trust chain. For private development "
                 "certificates, configure an appropriate trusted CA instead of disabling verification.", "CWE-295")
            explanation = "TLS certificate validation failed; response-header checks could not run."
        else:
            explanation = "HTTP request failed or timed out; response-header checks could not complete."
        report.coverage.append(CoverageNote(normalized, explanation, "error"))
    report.findings.sort(key=lambda finding: (-SEVERITIES[finding.severity], finding.rule_id))
    report.coverage.sort(key=lambda note: (note.category, note.reason))
    return report
