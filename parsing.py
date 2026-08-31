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

from bechunt.models import EmailRecord
from bechunt.utils import (
    normalize_email, domain_of, normalize_message_id, clean_text,
)
from bechunt.urls import (
    extract_urls, extract_url_domains, analyze_url, HTML_HREF_RE, HTML_LINK_RE,
)

EMAIL_RE = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.I,
)


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
 
        text = "\n\n".join(html_parts)
 
        text = re.sub(
            r"(?is)<script.*?>.*?</script>",
            " ",
            text,
        )
 
        text = re.sub(
            r"(?is)<style.*?>.*?</style>",
            " ",
            text,
        )
 
        text = re.sub(
            r"(?s)<[^>]+>",
            " ",
            text,
        )
 
        return clean_text(text)
 
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
 
 
def extract_url_analysis(message, subject: str, body: str) -> tuple[list[str], list[dict]]:
    urls = extract_urls(f"{subject}\n{body}")
    details = [analyze_url(u, "text") for u in urls]
    discovered = list(urls)
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.get_content_type() != "text/html" or part.get_content_disposition() == "attachment": continue
        try: payload = part.get_payload(decode=True)
        except Exception: payload = None
        if not payload: continue
        html_text = safe_decode(payload, part.get_content_charset())
        for match in HTML_HREF_RE.finditer(html_text):
            href = unquote(match.group(2).strip())
            if not href: continue
            if href not in discovered:
                discovered.append(href); details.append(analyze_url(href, "html_href"))
 
        for match in HTML_LINK_RE.finditer(html_text):
            href = unquote(match.group(2).strip())
            visible_text = clean_text(re.sub(r"(?s)<[^>]+>", " ", match.group(3)))
            displayed = extract_urls(visible_text)
            if href and displayed:
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


def inspect_attachment(part, filename):
    """Offline content inspection of one attachment: macros, HTML login forms,
    embedded links, forwarded messages, and deceptive filenames. No execution."""
    info = {
        "macro": False, "html_form": False, "forwarded_email": False,
        "suspicious_name": False, "embedded_urls": [], "attachment_flags": [],
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

    if lower_name.endswith(_MACRO_EXTENSIONS):
        info["macro"] = True
        flags.append("macro-enabled Office document")
    elif payload[:2] == b"PK":  # OOXML / zip container
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                if any("vbaproject.bin" in n.lower() for n in archive.namelist()):
                    info["macro"] = True
                    flags.append("embedded VBA macro project")
        except Exception:
            pass

    if ctype in ("text/html", "application/xhtml+xml") or lower_name.endswith((".html", ".htm", ".shtml")):
        html_text = safe_decode(payload, part.get_content_charset())
        low = html_text.lower()
        if "<form" in low or re.search(r'type\s*=\s*["\']?\s*password', low):
            info["html_form"] = True
            flags.append("HTML attachment contains a login/credential form")
        info["embedded_urls"] = extract_urls(html_text)[:20]
        if info["embedded_urls"] and not info["html_form"]:
            flags.append("HTML attachment contains links")

    return info


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
    }
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
