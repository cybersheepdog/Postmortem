"""Email (.eml) parsing and offline content extraction.

Turns a raw message into an EmailRecord: headers, body, URLs (incl. HTML hrefs
and attachment-embedded links), attachment fingerprints + inspection, and
SPF/DKIM/DMARC parsing. Never executes attachments or fetches anything.
"""

import base64
import binascii
import hashlib
import io
import quopri
import re
import sys
import zipfile
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

from postmortem.models import EmailRecord
from postmortem.utils import (
    normalize_email, domain_of, normalize_message_id, clean_text,
)
from postmortem.urls import (
    extract_urls, extract_url_domains, analyze_url, HTML_LINK_RE,
)

EMAIL_RE = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.I,
)

# BeautifulSoup gives more robust HTML handling (malformed markup, entities,
# attribute quirks) than regex. Optional: fall back to regex when it is absent.
try:
    from bs4 import BeautifulSoup as _BeautifulSoup
except Exception:
    _BeautifulSoup = None


def html_to_text(html: str) -> str:
    """HTML -> readable text. Uses BeautifulSoup when available; else strips
    <script>/<style> and tags with regex (the historical behavior)."""
    if _BeautifulSoup is not None:
        try:
            soup = _BeautifulSoup(html, "html.parser")
            for tag in soup(("script", "style")):
                tag.decompose()
            return clean_text(soup.get_text(" "))
        except Exception:
            pass
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", html)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return clean_text(text)


def html_links(html: str):
    """Yield (href, visible_text) for anchors in HTML. BeautifulSoup when
    available (catches links the regex misses); else the regex fallback."""
    if _BeautifulSoup is not None:
        try:
            soup = _BeautifulSoup(html, "html.parser")
            out = []
            for a in soup.find_all("a"):
                href = (a.get("href") or "").strip()
                if href:
                    out.append((unquote(href), a.get_text(" ").strip()))
            return out
        except Exception:
            pass
    out = []
    for match in HTML_LINK_RE.finditer(html):
        href = unquote(match.group(2).strip())
        visible = clean_text(re.sub(r"(?s)<[^>]+>", " ", match.group(3)))
        if href:
            out.append((href, visible))
    return out


def html_has_login_form(html: str) -> bool:
    """True if the HTML contains a form or a password input."""
    if _BeautifulSoup is not None:
        try:
            soup = _BeautifulSoup(html, "html.parser")
            if soup.find("form"):
                return True
            return any((i.get("type") or "").lower() == "password"
                       for i in soup.find_all("input"))
        except Exception:
            pass
    low = html.lower()
    return "<form" in low or bool(re.search(r'type\s*=\s*["\']?\s*password', low))


def safe_decode(payload: bytes, charset: Optional[str]) -> str:
    if not payload:
        return ""
 
    encodings = []
 
    if charset:
        encodings.append(charset)
 
    encodings.extend([
        "utf-8",
        "windows-1252",
        "latin-1",
    ])
 
    for encoding in encodings:
        try:
            return payload.decode(
                encoding,
                errors="replace",
            )
        except (LookupError, UnicodeDecodeError):
            continue
 
    return payload.decode(
        "utf-8",
        errors="replace",
    )
 
 
def extract_body(message) -> str:
    plain_parts = []
    html_parts = []
 
    if message.is_multipart():
 
        for part in message.walk():
 
            content_type = part.get_content_type()
 
            disposition = part.get_content_disposition()
 
            if disposition == "attachment":
                continue
 
            try:
                payload = part.get_payload(
                    decode=True
                )
            except Exception:
                payload = None
 
            if not payload:
                continue
 
            text = safe_decode(
                payload,
                part.get_content_charset(),
            )
 
            if content_type == "text/plain":
                plain_parts.append(text)
 
            elif content_type == "text/html":
                html_parts.append(text)
 
    else:
 
        try:
            payload = message.get_payload(
                decode=True
            )
        except Exception:
            payload = None
 
        if payload:
 
            text = safe_decode(
                payload,
                message.get_content_charset(),
            )
 
            if message.get_content_type() == "text/html":
                html_parts.append(text)
            else:
                plain_parts.append(text)
 
    if plain_parts:
        return clean_text(
            "\n\n".join(plain_parts)
        )
 
    if html_parts:
        return html_to_text("\n\n".join(html_parts))

    return ""
 
 
def extract_addresses(header_value: str) -> list[str]:
    if not header_value:
        return []
 
    results = []
 
    for match in EMAIL_RE.findall(header_value):
 
        address = normalize_email(match)
 
        if address and address not in results:
            results.append(address)
 
    return results
 
 
# A run of base64 alphabet long enough to plausibly hide a URL, bounded so we
# don't try to decode every long token in the body.
_B64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,1024}={0,2}(?![A-Za-z0-9+/=])")
_DATA_URI_RE = re.compile(r"data:[^;\s,]+;base64,[A-Za-z0-9+/=\s]+", re.I)


def decode_base64_urls(text: str) -> list[str]:
    """Find base64-looking blobs in body text, decode them, and return any URLs
    they contain. Inline ``data:...;base64,...`` images are excluded (they are
    the main source of false positives)."""
    if not text:
        return []
    scrubbed = _DATA_URI_RE.sub(" ", text)
    found = []
    for m in _B64_BLOB_RE.finditer(scrubbed):
        blob = m.group(0)
        if len(blob) % 4:
            continue
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", "ignore")
        except ValueError:  # binascii.Error subclasses ValueError
            continue
        for url in extract_urls(decoded):
            if url not in found:
                found.append(url)
    return found


def extract_url_analysis(message, subject: str, body: str) -> tuple[list[str], list[dict]]:
    urls = extract_urls(f"{subject}\n{body}")
    details = [analyze_url(u, "text") for u in urls]
    discovered = list(urls)
    # Base64-obfuscated URLs hidden in the body (evades plain link scans).
    for url in decode_base64_urls(body):
        if url not in discovered:
            discovered.append(url)
            item = analyze_url(url, "base64_body")
            item.setdefault("flags", []).append("URL recovered from base64-encoded body text")
            item["risk_score"] = int(item.get("risk_score", 0)) + 4
            details.append(item)
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.get_content_type() != "text/html" or part.get_content_disposition() == "attachment": continue
        try: payload = part.get_payload(decode=True)
        except Exception: payload = None
        if not payload: continue
        html_text = safe_decode(payload, part.get_content_charset())
        # BeautifulSoup-backed link extraction (falls back to regex). Captures
        # both the href and its visible text, so a displayed-vs-actual hostname
        # mismatch (classic phishing) is surfaced.
        for href, visible in html_links(html_text):
            if not href:
                continue
            displayed = extract_urls(visible)
            if href not in discovered:
                discovered.append(href)
                details.append(analyze_url(href, "html_href",
                                           displayed[0] if displayed else ""))
            elif displayed:
                target = next((item for item in details if item.get("url") == href), None)
                if target:
                    target.update(analyze_url(href, "html_href", displayed[0]))
    return discovered, details
 
 
def get_thread_seed(
    message_id: str,
    in_reply_to: str,
    references: list[str],
) -> str:
 
    if references:
        return references[0]
 
    if in_reply_to:
        return in_reply_to
 
    return message_id
 
 
def iter_decoded_attachment(part, chunk_size: int = 1024 * 1024):
    """Yield decoded attachment bytes incrementally.
 
    Handles the common base64, quoted-printable, and 7bit/8bit/binary
    content-transfer encodings without retaining a second full attachment
    buffer solely for hashing.
    """
    payload = part.get_payload(decode=False)
    if payload is None:
        return
 
    if isinstance(payload, bytes):
        for offset in range(0, len(payload), chunk_size):
            yield payload[offset:offset + chunk_size]
        return
 
    encoding = (part.get("Content-Transfer-Encoding", "") or "").lower().strip()
 
    if encoding == "base64":
        text = re.sub(r"\s+", "", str(payload))
        usable = len(text) - (len(text) % 4)
        for offset in range(0, usable, chunk_size - (chunk_size % 4)):
            block = text[offset:offset + chunk_size - (chunk_size % 4)]
            if block:
                try:
                    yield base64.b64decode(block, validate=False)
                except (binascii.Error, ValueError):
                    # Fall back to the email package for malformed payloads.
                    decoded = part.get_payload(decode=True) or b""
                    for pos in range(0, len(decoded), chunk_size):
                        yield decoded[pos:pos + chunk_size]
                    return
        if usable < len(text):
            try:
                yield base64.b64decode(text[usable:], validate=False)
            except (binascii.Error, ValueError):
                pass
        return
 
    if encoding in {"quoted-printable", "quopri"}:
        raw = str(payload).encode("utf-8", errors="ignore")
        decoded = quopri.decodestring(raw)
        for offset in range(0, len(decoded), chunk_size):
            yield decoded[offset:offset + chunk_size]
        return
 
    raw = str(payload).encode(
        part.get_content_charset() or "utf-8",
        errors="replace",
    )
    for offset in range(0, len(raw), chunk_size):
        yield raw[offset:offset + chunk_size]
 
 
def hash_attachment_streaming(part):
    digest = hashlib.sha256()
    size = 0
    for chunk in iter_decoded_attachment(part):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size
 
 
# A benign-looking extension immediately followed by an executable one.
_DOUBLE_EXT_RE = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|html?|zip)\s*"
    r"\.(?:exe|scr|js|jse|vbs|vbe|bat|cmd|com|pif|ps1|hta|lnk|iso|img)\b",
    re.I,
)
_MACRO_EXTENSIONS = (".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".xlam")
# Attachments larger than this are hashed but not content-inspected.
_ATTACH_INSPECT_MAX = 30 * 1024 * 1024


# Magic-byte signatures -> a coarse content category. Order matters only in that
# more specific signatures are listed; matching is by longest-prefix intent.
_MAGIC_SIGNATURES = (
    (b"MZ", "pe_executable"),
    (b"\x7fELF", "elf_executable"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"PK\x07\x08", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"GIF87a", "gif"), (b"GIF89a", "gif"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"BM", "bmp"),
)

# Content categories that are executable/script-like regardless of extension.
_EXECUTABLE_KINDS = {"pe_executable", "elf_executable", "script"}

# Extension -> the content category (or categories) it should confidently be.
# Extensions without a confident mapping are never flagged (conservative).
_EXT_EXPECTED_KIND = {
    ".pdf": {"pdf"},
    ".zip": {"zip"}, ".jar": {"zip"}, ".apk": {"zip"},
    ".docx": {"zip"}, ".xlsx": {"zip"}, ".pptx": {"zip"},
    ".docm": {"zip"}, ".xlsm": {"zip"}, ".pptm": {"zip"},
    ".doc": {"ole"}, ".xls": {"ole"}, ".ppt": {"ole"}, ".msg": {"ole"},
    ".png": {"png"}, ".jpg": {"jpeg"}, ".jpeg": {"jpeg"},
    ".gif": {"gif"}, ".bmp": {"bmp"},
    ".rar": {"rar"}, ".7z": {"7z"}, ".gz": {"gzip"}, ".tgz": {"gzip"},
    ".exe": {"pe_executable"}, ".dll": {"pe_executable"}, ".scr": {"pe_executable"},
}


# Extensions that are dangerous to find *inside* an archive attachment.
_ARCHIVE_DANGEROUS_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".wsh", ".hta", ".lnk", ".ps1", ".jar", ".msi", ".dll",
    ".cpl", ".reg",
}
_NESTED_ARCHIVE_EXT = {".zip", ".7z", ".rar", ".gz", ".iso", ".img", ".cab"}


def _inspect_archive_names(names, info, flags):
    """Flag dangerous / nested entries listed inside an archive (no extraction)."""
    entries = [n for n in names if not n.endswith("/")]
    info["archive_entries"] = entries[:50]
    danger = sorted({Path(n).suffix.lower() for n in entries
                     if Path(n).suffix.lower() in _ARCHIVE_DANGEROUS_EXT})
    nested = sorted({Path(n).suffix.lower() for n in entries
                     if Path(n).suffix.lower() in _NESTED_ARCHIVE_EXT})
    if danger:
        info["archive_threat"] = True
        flags.append("archive contains executable/script files: " + ", ".join(danger))
    if nested:
        flags.append("archive contains nested archive(s): " + ", ".join(nested))


def _inspect_archive_generic(lower_name, payload, info, flags):
    """Peek inside .7z/.rar when the optional reader is installed; else note it."""
    names = None
    try:
        if lower_name.endswith(".7z"):
            import py7zr
            with py7zr.SevenZipFile(io.BytesIO(payload)) as archive:
                names = archive.getnames()
        elif lower_name.endswith(".rar"):
            import rarfile
            with rarfile.RarFile(io.BytesIO(payload)) as archive:
                names = archive.namelist()
    except Exception:
        names = None
    if names:
        _inspect_archive_names(names, info, flags)
    else:
        flags.append(f"archive ({Path(lower_name).suffix}) not inspected "
                     "(install py7zr/rarfile to peek inside)")


def sniff_file_type(payload: bytes) -> str:
    """Return a coarse content category from the leading magic bytes, or "".

    A lightweight, dependency-free alternative to `python-magic` covering the
    formats that matter for attachment triage (executables, archives, Office
    containers, PDFs, common images, and HTML/scripts). Never executes anything.
    """
    if not payload:
        return ""
    head = payload[:16]
    for sig, kind in _MAGIC_SIGNATURES:
        if head.startswith(sig):
            return kind
    stripped = payload[:512].lstrip()
    if stripped[:2] == b"#!":
        return "script"
    low = stripped[:256].lower()
    if low.startswith(b"<!doctype html") or low.startswith(b"<html") or b"<script" in low:
        return "html"
    return ""


def inspect_attachment(part, filename):
    """Offline content inspection of one attachment: macros, HTML login forms,
    embedded links, forwarded messages, deceptive filenames, and content that
    does not match its extension (magic-byte sniff). No execution."""
    info = {
        "macro": False, "html_form": False, "forwarded_email": False,
        "suspicious_name": False, "embedded_urls": [], "attachment_flags": [],
        "sniffed_type": "", "ext_mismatch": False,
        "archive_entries": [], "archive_threat": False,
    }
    flags = info["attachment_flags"]
    name = filename or ""
    lower_name = name.lower()
    ctype = part.get_content_type()

    if "‮" in name:
        info["suspicious_name"] = True
        flags.append("right-to-left-override character in filename")
    if _DOUBLE_EXT_RE.search(name):
        info["suspicious_name"] = True
        flags.append("double extension disguising an executable")

    if ctype == "message/rfc822":
        info["forwarded_email"] = True
        flags.append("forwarded email (message/rfc822)")
        try:
            nested = part.get_payload()
            if isinstance(nested, list) and nested:
                sub = nested[0]
                body = extract_body(sub)
                info["embedded_urls"] = extract_urls(
                    f"{sub.get('Subject', '')}\n{body}"
                )[:20]
        except Exception:
            pass
        return info

    try:
        payload = part.get_payload(decode=True) or b""
    except Exception:
        payload = b""
    if len(payload) > _ATTACH_INSPECT_MAX:
        return info

    # Magic-byte vs extension: flag content that isn't what its name claims.
    sniffed = sniff_file_type(payload)
    info["sniffed_type"] = sniffed
    ext = Path(lower_name).suffix
    expected = _EXT_EXPECTED_KIND.get(ext)
    if sniffed and expected and sniffed not in expected:
        info["ext_mismatch"] = True
        if sniffed in _EXECUTABLE_KINDS:
            flags.append(f"content is {sniffed} but the extension is {ext} "
                         "(executable disguised as a document)")
        else:
            flags.append(f"content ({sniffed}) does not match the {ext} extension")

    if lower_name.endswith(_MACRO_EXTENSIONS):
        info["macro"] = True
        flags.append("macro-enabled Office document")
    elif payload[:2] == b"PK":  # OOXML / zip container
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                names = archive.namelist()
                if any("vbaproject.bin" in n.lower() for n in names):
                    info["macro"] = True
                    flags.append("embedded VBA macro project")
                # For a plain .zip attachment (not an Office container), list the
                # entries and flag dangerous payloads inside without extracting.
                if lower_name.endswith((".zip",)):
                    _inspect_archive_names(names, info, flags)
        except Exception:
            pass
    elif lower_name.endswith((".zip", ".7z", ".rar")):
        _inspect_archive_generic(lower_name, payload, info, flags)

    if ctype in ("text/html", "application/xhtml+xml") or lower_name.endswith((".html", ".htm", ".shtml")):
        html_text = safe_decode(payload, part.get_content_charset())
        if html_has_login_form(html_text):
            info["html_form"] = True
            flags.append("HTML attachment contains a login/credential form")
        info["embedded_urls"] = extract_urls(html_text)[:20]
        if info["embedded_urls"] and not info["html_form"]:
            flags.append("HTML attachment contains links")

    return info


def iter_attachment_payloads(path):
    """Yield (filename, content_type, bytes) for each attachment in a .eml.

    Used by the optional YARA/QR post-passes, which need the raw bytes that the
    normal parse deliberately discards. Re-reads the file so nothing is retained
    in memory across the whole corpus."""
    try:
        with open(path, "rb") as fh:
            message = BytesParser(policy=policy.default).parse(fh)
    except Exception:
        return
    if not message.is_multipart():
        return
    for part in message.walk():
        if part.get_content_disposition() != "attachment":
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        yield (part.get_filename() or "(unnamed)", part.get_content_type(), payload)


def extract_attachment_details(message):
    details = []
    names = []
    if not message.is_multipart():
        return names, details

    for part in message.walk():
        if part.get_content_disposition() != "attachment":
            continue
        filename = part.get_filename() or "(unnamed)"
        try:
            sha, size = hash_attachment_streaming(part)
        except Exception:
            payload = part.get_payload(decode=True) or b""
            sha = hashlib.sha256(payload).hexdigest()
            size = len(payload)

        detail = {
            "filename": filename,
            "content_type": part.get_content_type(),
            "size": size,
            "sha256": sha,
        }
        try:
            detail.update(inspect_attachment(part, filename))
        except Exception:
            pass
        details.append(detail)
        if filename not in names:
            names.append(filename)

    return names, details
 
 
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
 
 
def attachment_fingerprint(part) -> dict[str, object]:
    payload = part.get_payload(decode=True) or b""
    return {
        "filename": part.get_filename() or "",
        "content_type": part.get_content_type(),
        "size": len(payload),
        "sha256": sha256_bytes(payload),
        "content_id": str(part.get("Content-ID", "")).strip("<>"),
        "disposition": part.get_content_disposition() or "",
    }
 
 
_AR_MECH_RE = re.compile(
    r"^(spf|dkim|dmarc|compauth|arc)\s*=\s*([A-Za-z]+)\b(.*)$", re.I
)
# Per-mechanism results that count as a failure/anomaly for scoring.
_AR_FAIL_RESULTS = {"fail", "softfail", "permerror", "temperror", "none"}


def parse_authentication_results(values) -> dict:
    """Split Authentication-Results into per-mechanism {result, reason}.

    The header is a semicolon-delimited list of ``mechanism=result`` clauses,
    each optionally followed by an explanatory reason (a parenthetical, a
    ``reason=...``, or ``header.d=``/``smtp.mailfrom=`` context). The leading
    authserv-id clause has no ``=mechanism`` and is skipped. First result per
    mechanism wins. Also captures Microsoft 365's ``compauth`` verdict.
    """
    detail = {}
    for header in (values or []):
        for clause in str(header).split(";"):
            m = _AR_MECH_RE.match(clause.strip())
            if not m:
                continue
            mech = m.group(1).lower()
            if mech in detail:
                continue
            detail[mech] = {
                "result": m.group(2).lower(),
                "reason": m.group(3).strip()[:200],
            }
    return detail


def parse_authentication_headers(message) -> dict[str, object]:
    auth = {
        "authentication_results": message.get_all("Authentication-Results", []),
        "arc_authentication_results": message.get_all(
            "ARC-Authentication-Results", []
        ),
        "received_spf": message.get_all("Received-SPF", []),
        "dkim_signatures": message.get_all("DKIM-Signature", []),
        "return_path": message.get("Return-Path", ""),
        "reply_to": message.get("Reply-To", ""),
        "received": message.get_all("Received", []),
        "x_originating_ip": message.get_all("X-Originating-IP", []),
        "list_unsubscribe": message.get_all("List-Unsubscribe", []),
        "precedence": message.get("Precedence", ""),
    }
    # Bulk/marketing markers: a mild NEGATIVE signal for FP reduction.
    auth["bulk_mail"] = bool(auth["list_unsubscribe"]) or (
        str(auth["precedence"]).strip().lower() in ("bulk", "list", "junk")
    )
    text = " ".join(
        str(v)
        for values in auth.values()
        for v in (values if isinstance(values, list) else [values])
    ).lower()
    auth["spf_fail"] = bool(
        re.search(r"\bspf\s*=\s*(fail|softfail|neutral)", text)
    )
    auth["dkim_fail"] = bool(
        re.search(r"\bdkim\s*=\s*(fail|temperror|permerror)", text)
    )
    auth["dmarc_fail"] = bool(
        re.search(r"\bdmarc\s*=\s*(fail|temperror|permerror)", text)
    )
    # Explicit passes are needed to baseline each sender: a domain that normally
    # passes and then fails is anomalous, while a domain that never passes
    # (chronically misconfigured) failing is expected, not suspicious.
    auth["spf_pass"] = bool(re.search(r"\bspf\s*=\s*pass\b", text))
    auth["dkim_pass"] = bool(re.search(r"\bdkim\s*=\s*pass\b", text))
    auth["dmarc_pass"] = bool(re.search(r"\bdmarc\s*=\s*pass\b", text))
    # Detailed per-mechanism results + reasons, and the M365 compauth verdict.
    detail = parse_authentication_results(
        list(auth["authentication_results"]) + list(auth["arc_authentication_results"])
    )
    auth["auth_detail"] = detail
    auth["compauth_fail"] = detail.get("compauth", {}).get("result", "") == "fail"
    return auth


def parse_eml(path: Path, deep: bool = False) -> Optional[EmailRecord]:
 
    try:
 
        with path.open("rb") as fh:
 
            message = BytesParser(
                policy=policy.default
            ).parse(fh)
 
    except Exception as exc:
 
        print(
            f"[!] Could not parse {path}: {exc}",
            file=sys.stderr,
        )
 
        return None
 
    sender_header = message.get(
        "From",
        "",
    )
 
    sender_name, sender_address = parseaddr(
        sender_header
    )
 
    sender_address = normalize_email(
        sender_address
    )
 
    recipients = extract_addresses(
        message.get("To", "")
    )
 
    cc = extract_addresses(
        message.get("Cc", "")
    )
 
    message_id = normalize_message_id(
        message.get("Message-ID", "")
    )
 
    in_reply_to = normalize_message_id(
        message.get("In-Reply-To", "")
    )
 
    references = []
 
    for value in message.get_all(
        "References",
        [],
    ):
 
        for ref in re.findall(
            r"<[^>]+>",
            value,
        ):
 
            normalized = normalize_message_id(
                ref
            )
 
            if (
                normalized
                and normalized not in references
            ):
                references.append(normalized)
 
    body = extract_body(message)
 
    subject = str(
        message.get(
            "Subject",
            "",
        )
        or ""
    )
 
    # First pass: URL extraction is cheap; URL risk analysis and attachment
    # hashing are deliberately deferred until the message is a candidate.
    urls = extract_urls(f"{subject}\n{body}")
    url_analysis = []
    if deep:
        _, url_analysis = extract_url_analysis(message, subject, body)

    # Authentication (SPF/DKIM/DMARC) parsing is cheap header inspection and
    # is consumed by the interactive report, so populate it on every record.
    authentication = parse_authentication_headers(message)
 
    url_domains = extract_url_domains(urls)
 
    if deep:
        attachments, attachment_details = extract_attachment_details(message)
    else:
        attachments = []
        for part in message.walk() if message.is_multipart() else []:
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename() or "(unnamed)"
                if filename not in attachments:
                    attachments.append(filename)
        attachment_details = []
 
    return EmailRecord(
        path=str(path),
        filename=path.name,
        message_id=message_id,
        in_reply_to=in_reply_to,
        references=references,
        sender_name=sender_name,
        sender_email=sender_address,
        sender_domain=domain_of(
            sender_address
        ),
        recipients=recipients,
        cc=cc,
        date=str(
            message.get(
                "Date",
                "",
            )
            or ""
        ),
        subject=subject,
        body=body,
        urls=urls,
        url_domains=url_domains,
        attachments=attachments,
        attachment_details=attachment_details,
        url_analysis=url_analysis,
        authentication_results=authentication,
        thread_id=get_thread_seed(
            message_id,
            in_reply_to,
            references,
        ),
    )
