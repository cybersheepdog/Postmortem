"""Offline URL extraction and risk analysis.

No DNS, HTTP, redirects, or downloads are ever performed — every function works
purely on the URL string. Depends only on stdlib and postmortem.utils.
"""

import ipaddress
import re
from urllib.parse import urlparse, urlsplit, parse_qsl, unquote

from postmortem.utils import registered_domain_approx

URL_RE = re.compile(
    r"""(?ix)
    \b(?:
        https?://
        |www\.
    )
    [^\s<>"')]+
    """
)

IP_URL_RE = re.compile(
    r"""(?ix)
    https?://
    (?:
        \d{1,3}\.){3}\d{1,3}
    """
)

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.one"}
SUSPICIOUS_URL_TLDS = {".zip", ".mov", ".click", ".top", ".xyz", ".shop", ".live", ".icu", ".buzz", ".cam", ".support", ".work", ".download"}
SUSPICIOUS_URL_PARAMS = {"url", "u", "uri", "redirect", "redirect_url", "redirect_uri", "next", "continue", "dest", "destination", "target", "link", "return", "returnurl", "goto", "to"}
HTML_HREF_RE = re.compile(r'(?is)\b(?:href|src)\s*=\s*(["\'])(.*?)\1')
HTML_LINK_RE = re.compile(r'(?is)<a\b[^>]*\bhref\s*=\s*(["\'])(.*?)\1[^>]*>(.*?)</a>')

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy",
}

REDIRECT_PARAMETER_NAMES = {
    "url", "u", "uri", "target", "dest", "destination", "redirect",
    "redirect_url", "redirect_uri", "next", "continue", "return",
    "returnurl", "link",
}


# Hosts that appear in mail as machine-readable identifiers rather than as
# links. XML namespace declarations, DTD references and schema URIs are
# emitted by Word, Outlook and every OOXML producer; they are present in an
# enormous share of ordinary business mail, no user ever navigates to one, and
# counting them inflates URL totals, IOC exports and the "contains N URL(s)"
# signal alike. Matched on the registrable domain, so subdomains are covered.
NON_NAVIGABLE_HOSTS = frozenset({
    "w3.org",               # xmlns, DTD references, SVG and XHTML namespaces
    "schemas.microsoft.com",     # Office / VML / OMML namespaces
    "schemas.openxmlformats.org",  # docx, xlsx, pptx part namespaces
    "schemas.xmlsoap.org",  # SOAP envelopes
    "openoffice.org",       # ODF namespaces
    "oasis-open.org",       # ODF / DocBook namespaces
    "purl.org",             # Dublin Core and friends
    "ns.adobe.com",         # XMP metadata in embedded images
    "iptc.org",             # XMP photo metadata
    "whatwg.org",           # HTML spec references
})


def is_navigable(url: str) -> bool:
    """False for schema/namespace URIs that are identifiers, not destinations.

    Deliberately narrow: only hosts whose entire purpose is to name a schema.
    A phishing link is never hosted on one of these, and a legitimate link to
    one carries no investigative meaning either, so dropping them loses
    nothing and removes a large and constant source of noise.
    """
    host = (urlparse(normalize_url(url)).hostname or "").lower().rstrip(".")
    if not host:
        return True
    # Suffix match on the full hostname, not the registrable domain: the
    # registrable domain of schemas.microsoft.com is microsoft.com, and
    # filtering that would discard every genuine Microsoft link.
    return not any(
        host == h or host.endswith("." + h) for h in NON_NAVIGABLE_HOSTS
    )


def extract_urls(text: str, navigable_only: bool = True) -> list[str]:
    """URLs appearing in `text`.

    `navigable_only` drops schema and namespace URIs. Pass False when the
    caller genuinely wants every URI-shaped string, such as when reporting on
    what a document declared.
    """
    urls = []
    for match in URL_RE.findall(text or ""):
        url = match.rstrip(".,;:!?)]}>\"'")
        if not url or url in urls:
            continue
        if navigable_only and not is_navigable(url):
            continue
        urls.append(url)
    return urls


def normalize_url(url: str) -> str:
    value = (url or "").strip()
    return "http://" + value if value.lower().startswith("www.") else value


def is_ip_literal(hostname: str) -> bool:
    host = (hostname or "").strip("[]")
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host)) or ":" in host


def analyze_url(url: str, source: str = "text", displayed_url: str = "") -> dict:
    """Offline URL inspection only; no DNS, HTTP, redirects, or downloads."""
    normalized = normalize_url(url)
    result = {"url": url, "normalized": normalized, "source": source, "scheme": "", "hostname": "", "registrable_domain": "", "port": None, "path": "", "query_parameter_names": [], "flags": [], "risk_score": 0, "displayed_url": displayed_url or "", "display_mismatch": False}
    try:
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower().rstrip(".")
        result.update({"scheme": (parsed.scheme or "").lower(), "hostname": host, "registrable_domain": registered_domain_approx(host), "port": parsed.port, "path": parsed.path or ""})
        params = {k.lower() for k, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        result["query_parameter_names"] = sorted(params)
        scheme = result["scheme"]
        if scheme not in {"http", "https"}: result["flags"].append(f"Non-web URL scheme: {scheme or '(missing)'}"); result["risk_score"] += 5
        if scheme == "http": result["flags"].append("Unencrypted HTTP URL"); result["risk_score"] += 2
        if parsed.username is not None or parsed.password is not None: result["flags"].append("URL contains userinfo credentials"); result["risk_score"] += 6
        if is_ip_literal(host): result["flags"].append("URL uses an IP literal instead of a hostname"); result["risk_score"] += 6
        if host.startswith("xn--") or ".xn--" in host: result["flags"].append("Hostname contains IDN/punycode label"); result["risk_score"] += 3
        if host in SHORTENER_DOMAINS: result["flags"].append("Known URL-shortener domain"); result["risk_score"] += 3
        if any(host.endswith(tld) for tld in SUSPICIOUS_URL_TLDS): result["flags"].append("Hostname uses a commonly abused high-risk TLD"); result["risk_score"] += 2
        if len(host) > 60: result["flags"].append("Unusually long hostname"); result["risk_score"] += 2
        if host.count(".") >= 4: result["flags"].append("Deeply nested hostname"); result["risk_score"] += 2
        authority = normalized.split("//", 1)[-1].split("/", 1)[0]
        if "@" in authority: result["flags"].append("Authority contains @ character"); result["risk_score"] += 4
        if params & SUSPICIOUS_URL_PARAMS: result["flags"].append("URL contains redirect/destination-style parameter"); result["risk_score"] += 3
        if any(x in result["path"].lower() for x in ("login", "signin", "sign-in", "verify", "auth", "password", "secure", "account")): result["flags"].append("Path suggests authentication/account workflow"); result["risk_score"] += 2
        if len(normalized) > 180: result["flags"].append("Unusually long URL"); result["risk_score"] += 2
        if displayed_url:
            shown_host = (urlparse(normalize_url(displayed_url)).hostname or "").lower().rstrip(".")
            if shown_host and host and shown_host != host:
                result["display_mismatch"] = True; result["flags"].append("Displayed link hostname differs from actual href hostname"); result["risk_score"] += 7
    except ValueError as exc:
        result["flags"].append(f"Malformed URL: {exc}"); result["risk_score"] += 4
    except Exception as exc:
        result["flags"].append(f"URL parsing error: {type(exc).__name__}"); result["risk_score"] += 3
    result["flags"] = list(dict.fromkeys(result["flags"]))
    return result


def extract_url_domains(urls: list[str]) -> list[str]:
    domains = []
    for url in urls:
        try:
            domain = (urlparse(normalize_url(url)).hostname or "").lower()
        except Exception:
            domain = ""
        if domain and domain not in domains:
            domains.append(domain)
    return domains


def analyze_url_robust(url: str) -> dict[str, object]:
    result = {
        "original": url,
        "normalized": url.strip(),
        "scheme": "",
        "hostname": "",
        "registrable_domain": "",
        "path": "",
        "query": "",
        "is_https": False,
        "is_ip_host": False,
        "is_punycode": False,
        "has_userinfo": False,
        "has_redirect_parameter": False,
        "is_shortener": False,
        "suspicious_score": 0,
        "indicators": [],
    }
    try:
        parsed = urlsplit(url.strip())
        hostname = (parsed.hostname or "").lower().rstrip(".")
        result["scheme"] = parsed.scheme.lower()
        result["hostname"] = hostname
        result["path"] = parsed.path
        result["query"] = parsed.query
        result["is_https"] = parsed.scheme.lower() == "https"

        try:
            ipaddress.ip_address(hostname)
            result["is_ip_host"] = True
            result["suspicious_score"] += 20
            result["indicators"].append("URL uses an IP address as hostname")
        except ValueError:
            pass

        if parsed.username or parsed.password:
            result["has_userinfo"] = True
            result["suspicious_score"] += 25
            result["indicators"].append("URL contains userinfo before hostname")

        if hostname.startswith("xn--") or ".xn--" in hostname:
            result["is_punycode"] = True
            result["suspicious_score"] += 15
            result["indicators"].append("URL hostname uses punycode/IDN")

        if hostname in URL_SHORTENERS:
            result["is_shortener"] = True
            result["suspicious_score"] += 12
            result["indicators"].append("URL uses a known shortening service")

        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            result["suspicious_score"] += 15
            result["indicators"].append("URL uses an unusual scheme")
        elif scheme == "http":
            result["suspicious_score"] += 8
            result["indicators"].append("URL is not HTTPS")

        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if key.lower() in REDIRECT_PARAMETER_NAMES:
                result["has_redirect_parameter"] = True
                result["suspicious_score"] += 10
                result["indicators"].append(
                    f"URL contains redirect/destination parameter: {key}"
                )
            if "@" in unquote(value):
                result["suspicious_score"] += 5

        if len(hostname) > 80:
            result["suspicious_score"] += 8
            result["indicators"].append("Unusually long URL hostname")
        if len(parsed.path) > 120:
            result["suspicious_score"] += 5
            result["indicators"].append("Unusually long URL path")

        result["registrable_domain"] = registered_domain_approx(hostname)
    except Exception as exc:
        result["suspicious_score"] += 5
        result["indicators"].append(f"URL parsing error: {type(exc).__name__}")
    return result
