"""Pure, dependency-light helpers shared across bec_hunt.

Address/domain normalization and date parsing. No dependency on other bec_hunt
modules, so this is a safe leaf that everything else can import.
"""

import re
from datetime import datetime, timezone
from email.utils import parseaddr, parsedate_to_datetime
from functools import lru_cache
from typing import Optional


def normalize_email(value: str) -> str:
    if not value:
        return ""
    _, address = parseaddr(value)
    if not address:
        address = value
    return address.strip().lower()


def domain_of(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].lower()


def normalize_message_id(value: str) -> str:
    if not value:
        return ""
    value = value.strip()
    if not value.startswith("<"):
        value = "<" + value
    if not value.endswith(">"):
        value += ">"
    return value.lower()


@lru_cache(maxsize=262144)
def parse_date(value: str) -> Optional[datetime]:
    # Cached because the same Date/Received strings are re-parsed many times
    # across the numerous chronological sorts (timeline, graph, clustering,
    # summary) — the dominant redundant cost on large mailboxes.
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def date_sort_key(record):
    """Sort key over an object's ``.date`` string; unparseable dates sort last."""
    dt = parse_date(record.date)
    if dt is None:
        return datetime.max.replace(tzinfo=timezone.utc)
    return dt


def registered_domain_approx(hostname: str) -> str:
    host = (hostname or "").lower().strip(".")
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2:] in (["co", "uk"], ["com", "au"], ["co", "jp"], ["co", "nz"]):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def to_utc_fields(raw_date: str) -> tuple[str, str]:
    """Convert an email Date header (any timezone, e.g. EST) to UTC.

    Returns (iso_utc_timestamp, utc_day). Because the conversion is to UTC, a
    late-evening EST message correctly rolls into the next UTC day. Empty strings
    are returned when the date cannot be parsed.
    """
    dt = parse_date(raw_date)
    if dt is None:
        return "", ""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), dt.strftime("%Y-%m-%d")


# --- text helpers shared by parsing, scoring and clustering ---------------
def clean_text(text: str) -> str:
    text = text.replace("\x00", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def normalize_subject(subject: str) -> str:
    subject = subject or ""
    subject = re.sub(r"(?i)^\s*((re|fw|fwd)\s*:\s*)+", "", subject)
    subject = re.sub(r"\s+", " ", subject)
    return subject.strip().lower()


def tokenize(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9]{3,}", text.lower())
    stop_words = {
        "the", "and", "for", "this", "that", "with", "from", "your", "you",
        "are", "was", "has", "have", "will", "can", "please", "hello",
        "thanks", "thank", "regards",
    }
    return {word for word in words if word not in stop_words}


def jaccard_similarity(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)
