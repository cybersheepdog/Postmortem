"""Indicator-of-compromise extraction and export.

Aggregates pivot-ready indicators (domains, URLs, IPs, attachment hashes) from
the Tier 1/2 suspects into a deduplicated list for blocklisting and pivoting.
"""

import csv
from pathlib import Path

from bechunt.utils import to_utc_fields, normalize_email, domain_of


def _record_iocs(record):
    """Yield (ioc_type, value, context) indicators observed on one message."""
    out = []
    if record.sender_domain:
        out.append(("sender_domain", record.sender_domain, ""))
    if record.sender_email:
        out.append(("sender_email", record.sender_email, ""))
    if record.lookalike_of and record.sender_domain:
        out.append(("lookalike_domain", record.sender_domain, f"mimics {record.lookalike_of}"))
    auth = record.authentication_results or {}
    reply_to_domain = domain_of(normalize_email(str(auth.get("reply_to", "") or "")))
    if record.reply_to_mismatch and reply_to_domain:
        out.append(("reply_to_domain", reply_to_domain, ""))
    if record.origin_ip:
        out.append(("origin_ip", record.origin_ip, ""))
    for url in (record.urls or []):
        out.append(("url", url, ""))
    for analysis in (record.url_analysis or []):
        domain = analysis.get("registrable_domain") or analysis.get("hostname")
        if domain:
            out.append(("url_domain", domain, ""))
    for att in (record.attachment_details or []):
        if isinstance(att, dict) and att.get("sha256"):
            out.append(("attachment_sha256", att["sha256"], att.get("filename", "")))
    return out


def extract_iocs(records, min_tier: int = 2):
    """Aggregate pivot-ready indicators of compromise from the review suspects
    (Tier 1 and 2 by default), deduplicated across messages."""
    aggregated = {}
    for record in records:
        if record.tier > min_tier:
            continue
        iso, _ = to_utc_fields(record.date)
        for ioc_type, value, context in _record_iocs(record):
            if not value:
                continue
            norm = value if ioc_type == "url" else str(value).lower()
            key = (ioc_type, norm)
            entry = aggregated.get(key)
            if entry is None:
                entry = aggregated[key] = {
                    "type": ioc_type, "value": value, "occurrences": 0,
                    "first_seen": iso, "last_seen": iso,
                    "best_tier": record.tier, "max_priority_score": record.score,
                    "context": context, "examples": [],
                }
            entry["occurrences"] += 1
            if iso:
                if not entry["first_seen"] or iso < entry["first_seen"]:
                    entry["first_seen"] = iso
                if iso > entry["last_seen"]:
                    entry["last_seen"] = iso
            entry["best_tier"] = min(entry["best_tier"], record.tier)
            entry["max_priority_score"] = max(entry["max_priority_score"], record.score)
            if context and not entry["context"]:
                entry["context"] = context
            if len(entry["examples"]) < 3 and record.path not in entry["examples"]:
                entry["examples"].append(record.path)
    iocs = list(aggregated.values())
    iocs.sort(key=lambda e: (e["best_tier"], -e["occurrences"], e["type"], e["value"]))
    return iocs


def write_iocs_csv(iocs, output: Path):
    columns = [
        "type", "value", "occurrences", "best_tier", "max_priority_score",
        "first_seen_utc", "last_seen_utc", "context", "example_paths",
    ]
    with output.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        for e in iocs:
            writer.writerow([
                e["type"], e["value"], e["occurrences"], e["best_tier"],
                e["max_priority_score"], e["first_seen"], e["last_seen"],
                e["context"], " | ".join(e["examples"]),
            ])
