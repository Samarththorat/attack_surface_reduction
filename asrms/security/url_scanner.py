import os
import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit


MAX_URL_LENGTH = 2048
SHORTENERS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "tinyurl.com",
    "t.co",
    "tiny.cc",
}
BRAND_NAMES = {"apple", "amazon", "google", "microsoft", "paypal"}
DOWNLOAD_SUFFIXES = {".apk", ".bat", ".cmd", ".dll", ".dmg", ".exe", ".iso", ".jar", ".js", ".msi", ".ps1", ".scr", ".vbs"}


class URLValidationError(ValueError):
    pass


class ThreatIntelligenceProvider:
    """Interface for a future reputation adapter; the local scanner never invokes it."""

    def lookup(self, url):
        raise NotImplementedError


def _level(score):
    if score <= 25:
        return "Low"
    if score <= 50:
        return "Medium"
    if score <= 75:
        return "High"
    return "Critical"


def _add_finding(findings, code, severity, points, message):
    findings.append(
        {"code": code, "severity": severity, "points": points, "message": message}
    )


def _destination(hostname, address):
    normalized_host = hostname.lower().rstrip(".")
    if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
        return "LOOPBACK", "Local address detected. This URL points to your own computer and is not an external website."
    if normalized_host.endswith((".local", ".internal", ".test", ".invalid", ".example")):
        return "RESERVED_IP", "Reserved or internal hostname detected; this URL is not established as an external website."
    if address is None and re.fullmatch(
        r"(?:[0-9]+|0x[0-9a-f]+)(?:\.(?:[0-9]+|0x[0-9a-f]+))*",
        normalized_host,
    ):
        return "RESERVED_IP", "Ambiguous non-standard numeric hostname detected; its destination is not treated as a public domain."
    if address is None:
        return "PUBLIC_DOMAIN", "Public domain name detected; its current DNS destination and accessibility were not checked."
    if address.is_loopback:
        return "LOOPBACK", "Local address detected. This URL points to your own computer and is not an external website."
    if address.is_link_local:
        return "LINK_LOCAL", "Link-local destination detected; this address is only meaningful on a local network segment."
    if address.is_reserved:
        return "RESERVED_IP", "Reserved or non-routable IP address detected; no network request was made."
    if address.is_private:
        return "PRIVATE_IP", "Private network destination detected. External accessibility has not been established."
    if address.is_global:
        return "PUBLIC_IP", "Public IP address detected; reachability and reputation were not checked."
    return "RESERVED_IP", "Reserved or non-routable IP address detected; no network request was made."


def _normalize(parsed):
    host = parsed.hostname
    try:
        address = ipaddress.ip_address(host)
        normalized_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    except ValueError:
        try:
            normalized_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise URLValidationError("The URL contains an invalid internationalized domain.") from exc
    try:
        port = parsed.port
    except ValueError as exc:
        raise URLValidationError("The URL contains an invalid port.") from exc
    default_port = (parsed.scheme.lower(), port) in {("http", 80), ("https", 443)}
    authority = normalized_host if port is None or default_port else f"{normalized_host}:{port}"
    if parsed.username is not None:
        userinfo = parsed.username
        if parsed.password is not None:
            userinfo += f":{parsed.password}"
        authority = f"{userinfo}@{authority}"
    return urlunsplit(
        (
            parsed.scheme.lower(),
            authority,
            parsed.path or "/",
            parsed.query,
            parsed.fragment,
        )
    ), normalized_host


def analyze_url(value):
    if not isinstance(value, str) or not value.strip():
        raise URLValidationError("Enter a URL to analyze.")
    submitted = value.strip()
    if len(submitted) > MAX_URL_LENGTH:
        raise URLValidationError(f"URLs must be {MAX_URL_LENGTH} characters or shorter.")
    if any(ord(char) < 32 or ord(char) == 127 or char.isspace() for char in submitted):
        raise URLValidationError("The URL contains whitespace or control characters.")
    if "\\" in submitted:
        raise URLValidationError("Backslashes are not accepted in URLs.")
    try:
        parsed = urlsplit(submitted)
        hostname = parsed.hostname
    except ValueError as exc:
        raise URLValidationError("The URL could not be parsed.") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        raise URLValidationError("Use a complete http:// or https:// URL with a hostname.")

    normalized, domain = _normalize(parsed)
    findings = []
    score = 0
    transport_score = 0
    scheme = parsed.scheme.lower()
    if scheme != "https":
        _add_finding(findings, "NO_HTTPS", "Medium", 10, "The URL uses HTTP, so transport encryption is not indicated.")
        transport_score += 10
    if parsed.username is not None or parsed.password is not None:
        _add_finding(findings, "USERINFO", "High", 25, "Credentials before the @ can disguise the destination hostname.")
        score += 25
    if "%" in submitted:
        _add_finding(findings, "ENCODING", "Low", 8, "Percent-encoded characters can obscure parts of a URL.")
        score += 8
    if any(unicodedata.category(char) in {"Cf", "Cc"} for char in submitted):
        _add_finding(findings, "INVISIBLE_CHARACTER", "High", 20, "The URL contains an invisible or formatting character.")
        score += 20

    address = None
    try:
        address = ipaddress.ip_address(hostname.rstrip("."))
    except ValueError:
        ascii_hostname = domain.lower().rstrip(".")
        labels_ascii = ascii_hostname.split(".")
        if not ascii_hostname or any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels_ascii
        ):
            raise URLValidationError("The URL contains an invalid domain name.")
        labels = hostname.lower().rstrip(".").split(".")
        if any(label.startswith("xn--") for label in labels):
            _add_finding(findings, "PUNYCODE_DOMAIN", "Medium", 18, "The domain contains IDN punycode; verify its displayed characters carefully.")
            score += 18
        if any(ord(char) > 127 for char in hostname):
            _add_finding(findings, "UNICODE_DOMAIN", "Medium", 15, "The domain contains Unicode characters that may resemble other characters.")
            score += 15
        scripts = {
            "CYRILLIC" if "CYRILLIC" in unicodedata.name(char, "")
            else "GREEK" if "GREEK" in unicodedata.name(char, "")
            else "LATIN" if "LATIN" in unicodedata.name(char, "")
            else None
            for char in hostname
            if char.isalpha()
        }
        scripts.discard(None)
        if len(scripts) > 1:
            _add_finding(findings, "MIXED_SCRIPT_DOMAIN", "High", 20, "The domain mixes writing systems, a common lookalike-domain signal.")
            score += 20
        if len(labels) > 4:
            _add_finding(findings, "MANY_SUBDOMAINS", "Low", 8, "The hostname has an unusually large number of subdomains.")
            score += 8
        if domain.lower() in SHORTENERS:
            _add_finding(findings, "URL_SHORTENER", "Medium", 26, "A URL-shortening service hides the eventual destination.")
            score += 26
        is_brand_domain = len(labels) >= 2 and labels[-2] in BRAND_NAMES and labels[-1] == "com"
        if any(label in BRAND_NAMES for label in labels[:-1]) and not is_brand_domain:
            _add_finding(findings, "BRAND_IMPERSONATION_PATTERN", "High", 30, "A recognizable brand name appears in a subdomain rather than as the registered host.")
            score += 30
        if re.search(r"(?:login|verify|secure|account|update)[-.]", hostname.lower()):
            _add_finding(findings, "SUSPICIOUS_DOMAIN_WORDING", "Low", 8, "The hostname contains wording often used to imitate account or sign-in pages.")
            score += 8
        if len(re.findall(r"\d", hostname)) >= 5:
            _add_finding(findings, "DIGIT_HEAVY_DOMAIN", "Low", 8, "The hostname contains an unusually high number of digits.")
            score += 8
        if re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)(?:\.(?:[0-9]+|0x[0-9a-f]+))*", hostname.lower()):
            _add_finding(findings, "NONSTANDARD_NUMERIC_HOST", "High", 30, "The numeric-looking hostname may be interpreted as a nonstandard IP address by some clients.")
            score += 30
    else:
        if address.is_global:
            _add_finding(findings, "IP_ADDRESS_HOST", "Low", 8, "The URL uses a public numeric IP address instead of a domain name.")
            score += 8

    lowered_path = parsed.path.lower()
    if any(lowered_path.endswith(suffix) for suffix in DOWNLOAD_SUFFIXES):
        _add_finding(findings, "DIRECT_DOWNLOAD", "Medium", 15, "The URL path appears to target a directly downloadable executable or script.")
        score += 15
    if len(parsed.query) > 500:
        _add_finding(findings, "LONG_QUERY", "Low", 5, "The URL has an unusually long query string.")
        score += 5

    destination_type, destination_message = _destination(hostname, address)
    structural_score = min(100, score)
    score = min(100, score + transport_score)
    if not findings:
        findings.append(
            {
                "code": "NO_STATIC_INDICATORS",
                "severity": "Info",
                "points": 0,
                "message": "No configured static risk indicators were detected; this does not establish that the URL is safe.",
            }
        )
    return {
        "submitted_url": submitted,
        "normalized_url": normalized,
        "domain": domain,
        "destination_type": destination_type,
        "destination_message": destination_message,
        "risk_score": score,
        "risk_level": _level(score),
        "risk_components": {
            "structural": structural_score,
            "destination": 0,
            "transport": transport_score,
            "threat_reputation": {"status": "UNVERIFIED", "score": None},
            "overall": score,
        },
        "https": scheme == "https",
        "redirect_chain": {
            "status": "NOT_CHECKED",
            "hops": [],
            "reason": "No network request was made; following redirects could expose local services or disclose the submitted URL.",
        },
        "threat_intelligence": {
            "status": "UNVERIFIED",
            "provider_configured": bool(os.environ.get("ASRMS_THREAT_INTEL_PROVIDER")),
            "provider_name": os.environ.get("ASRMS_THREAT_INTEL_PROVIDER") or None,
            "message": "No reputation verdict was obtained. URLs are not sent to third parties.",
        },
        "domain_age": {"status": "NOT_CHECKED"},
        "findings": findings,
        "recommended_action": (
            "Do not open this URL unless you can independently verify its destination."
            if score >= 51
            else "Use caution and verify the destination through a trusted channel before opening."
        ),
        "model": "Deterministic local heuristics; not an AI verdict or a guarantee of safety.",
        "network_requests_made": False,
    }
