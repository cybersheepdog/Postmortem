"""Tunable configuration for postmortem.

Thresholds, clustering caps, baseline minimums, and scenario scoring weights.
Override any subset per engagement with ``--config <file.json>``; the effective
values are recorded in the run manifest for reproducibility.

``CONFIG`` is a shared, mutable singleton: ``load_config`` merges overrides into
it *in place* so every module that imported the object sees the change.
"""

import json
from pathlib import Path

CONFIG = {
    "tier1_threshold": 12,          # min initial-email score for Tier 1
    "cluster_strong_cap": 400,      # max members compared per strong bucket
    "cluster_weak_skip": 80,        # skip weak buckets larger than this
    "cluster_strongest_sample": 25,  # sample size for per-message similarity
    "baseline_domain_min": 3,       # msgs for a domain to be "frequent"
    "baseline_sender_min": 3,       # msgs for a sender to be "frequent"
    "baseline_established_min": 5,  # msgs for a domain to be "established"
    "baseline_enforce_min": 3,      # auth observations to judge enforcement
    # Weights folded into the general priority score (annotate_forensic_signals).
    "priority_weights": {
        "self_spoofing": 10, "auth_anomaly": 6, "auth_fail_chronic": 1,
        "reply_to_mismatch": 5, "lookalike": 9, "sending_ip_anomaly": 4,
        "thread_injection": 7, "display_name_spoof": 6, "deleted": 4,
        "moved": 2, "rule_target": 3, "attachment_threat": 6, "anchor": 12,
        # Header-hygiene signals: weak/corroborating (legit ESP mail can trip
        # the alignment checks), so kept low to avoid promoting benign senders.
        "received_anomaly": 2, "message_id_mismatch": 1, "date_anomaly": 2,
        "dkim_misalignment": 2, "return_path_mismatch": 2,
        # A random-looking sender local-part (corroboration-gated); a small
        # NEGATIVE for legit bulk/marketing mail; a strong newly-registered
        # sender-domain signal (online, opt-in).
        "random_local_part": 3, "bulk_penalty": -3, "newly_registered": 8,
        # Geolocation-derived (opt-in, --geoip-db): an unexpected-country hop is
        # circumstantial; a high-abuse hosting ASN is a stronger corroborator.
        "suspicious_geo": 2, "high_abuse_host": 4,
    },
    # ASN organization keywords commonly associated with abuse/bulletproof
    # hosting. Heuristic and non-exhaustive; overridable via --config.
    "high_abuse_asn_keywords": [
        "bulletproof", "bpo", "flokinet", "ded", "stark industries",
        "railnet", "chang way", "pq hosting", "mivocloud", "aeza",
    ],
    # Weights for the "is this THE initial email" score (score_initial_email).
    "initial_weights": {
        "self_spoofing": 6, "auth_anomaly_corroborated": 4, "auth_anomaly": 1,
        "lookalike": 7, "reply_to_mismatch": 4, "sending_ip_anomaly": 3,
        "display_name_spoof": 5, "thread_injection": 6, "deleted": 4, "moved": 2,
        "rule_target": 2, "attachment_credential": 6, "attachment_other": 4,
        "cred_lure": 4, "credential_link": 6, "has_url": 1,
        "post_compromise_penalty": 8, "pay_lure": 4, "bank_change": 5,
        "urgency": 2, "impersonation_extra": 2, "impersonation_login_url": 2,
        "anchor": 8, "established_downweight": 3, "first_contact_ask": 3,
    },
}

# Version identifiers recorded in cache rows and the run manifest.
V7_PARSER_VERSION = "8.2-attachment-inspection"
TOOL_VERSION = "8.2"


def load_config(path):
    """Deep-merge a user JSON config over the defaults in CONFIG (in place)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for key, value in data.items():
        if isinstance(value, dict) and isinstance(CONFIG.get(key), dict):
            CONFIG[key].update(value)
        else:
            CONFIG[key] = value
    return CONFIG


# --- term/domain reference lists used by scoring and clustering ---------
PHISHING_TERMS = {
    "verify your account": 5,
    "verify your identity": 5,
    "confirm your identity": 5,
    "confirm your account": 5,
    "verify your email": 4,
    "account verification": 4,
    "password": 2,
    "reset your password": 5,
    "change your password": 4,
    "login": 2,
    "sign in": 2,
    "log in": 2,
    "authenticate": 3,
    "authentication": 3,
    "security alert": 4,
    "suspicious activity": 4,
    "unusual activity": 4,
    "account suspended": 5,
    "account locked": 5,
    "action required": 3,
    "urgent": 2,
    "immediately": 2,
    "within 24 hours": 4,
    "click here": 4,
    "click the link": 4,
    "open the link": 3,
    "secure message": 3,
    "secure document": 3,
    "shared document": 3,
    "document has been shared": 4,
    "invoice": 1,
    "payment": 1,
    "wire transfer": 5,
    "bank account": 3,
    "bank details": 4,
    "change bank": 5,
    "change banking": 5,
    "new bank account": 5,
    "updated bank details": 5,
    "gift card": 5,
    "confidential": 2,
    "keep this confidential": 4,
    "do not call": 5,
    "do not tell": 5,
    "don't tell": 5,
}
 
 
COMMON_FREE_EMAIL = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "aol.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
}
 
 
BUSINESS_TERMS = {
    "invoice",
    "payment",
    "purchase order",
    "po number",
    "accounts payable",
    "accounts receivable",
    "remittance",
    "bank",
    "wire",
    "transfer",
    "vendor",
    "supplier",
    "payroll",
    "executive",
    "ceo",
    "cfo",
    "president",
    "director",
}
 
 
RISKY_EXTENSIONS = {
    ".html",
    ".htm",
    ".hta",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".wsf",
    ".iso",
    ".img",
    ".lnk",
    ".zip",
    ".rar",
    ".7z",
    ".xlsm",
    ".docm",
    ".xlsb",
}
