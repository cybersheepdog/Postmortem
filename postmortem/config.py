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
    # C1/C3 modifier bounds. Each is a ceiling on how far the corpus baseline
    # may move a message-level score, so a familiar sender can never be
    # discounted into invisibility and a new one can never be convicted on
    # novelty alone.
    "auth_suppression_cap": 8,      # max discount for aligned + established
    "familiarity_discount_cap": 4,  # max discount for established alone
    "novelty_bump_cap": 6,          # max uplift for a first-and-only sender
    "baseline_enforce_min": 3,      # auth observations to judge enforcement
    # Weights folded into the general priority score (annotate_forensic_signals).
    "priority_weights": {
        "self_spoofing": 10, "auth_anomaly": 6, "auth_fail_chronic": 1,
        # A hard alignment failure for a domain without an
        # established passing history. Measured at 11.8x the Tier 1
        # base rate on a 117k corpus, the highest lift of any
        # high-volume signal, and previously hardcoded at 3.
        "auth_fail_hard": 5,
        "reply_to_mismatch": 5, "lookalike": 9, "sending_ip_anomaly": 4,
        "thread_injection": 7, "display_name_spoof": 6, "deleted": 4,
        "moved": 2, "rule_target": 3, "attachment_threat": 6, "anchor": 12,
        # What the file IS, as opposed to what it is called. Renaming an
        # executable is the cheapest evasion there is, and until now it
        # worked completely against the priority score.
        "attach_disguised_exe": 8,
        "attach_content_mismatch": 6,
        "attach_credential_form": 6,
        "attach_macro_found": 4,
        "attach_double_extension": 5,
        # A rule keyword matching more than this share of the corpus is
        # not selecting anything. Measured at 0.871 on a real case, where
        # it contributed 44% of all score mass at a lift of 1.16x -- i.e.
        # indistinguishable from marking messages at random. Reported as
        # a fact at weight 0 above the cap, never silently dropped.
        "rule_keyword_corpus_cap": 0.25,
        # Header-hygiene signals: weak/corroborating (legit ESP mail can trip
        # the alignment checks), so kept low to avoid promoting benign senders.
        "received_anomaly": 2, "message_id_mismatch": 1, "date_anomaly": 2,
        # Two header-hygiene variants measured at zero information on a
        # 117k corpus: a missing Date header fired 20,985 times with ~47
        # Tier 1 hits expected and zero observed, and out-of-order
        # Received timestamps 4,001 times with ~9 expected and zero
        # observed. Both are still reported -- they are true facts about
        # the message -- but they no longer move the score. The other
        # variants of each check keep their weight.
        "date_anomaly_missing": 0,
        "received_anomaly_out_of_order": 0,
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
#
# BUMPED from "8.2-attachment-inspection". The previous value was held stale
# deliberately -- it is the analysis cache key, and bumping it invalidates
# every cached record and forces a full re-parse -- on the standing condition
# that it "should be bumped, and must be, the next time the EmailRecord schema
# or the analysis semantics change in a way that makes a cached record wrong".
#
# That condition is now met. URL extraction changed at PARSE time, not at
# scoring time: extract_urls() drops schema/namespace hosts, html hrefs are
# filtered through is_navigable(), and decode_base64_urls() no longer mines
# encoded attachments (and no longer truncates what it recovers). `urls`,
# `url_domains` and `url_analysis` are all built in parse_eml() and stored in
# the cache, so a record cached under 8.2 still carries w3.org and
# schemas.microsoft.com entries and the malformed half-URLs the old decoder
# produced. Reusing those rows would feed the new scoring stale input and put
# malformed URLs back into the IOC export.
#
# Scoring changes alone never require a bump: calculate_score() rebuilds
# indicators on every run and is not cached. This bump is specifically about
# the parse-time URL semantics.
#
# Extraction is unaffected: mailbox_ingest does not key on PARSER_VERSION, so
# this costs a re-parse of the extracted .eml files, not a re-extraction from
# the source containers.
PARSER_VERSION = "8.3-url-extraction"
TOOL_VERSION = "8.3"


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
    "sign in": 4,
    "log in": 2,
    "authenticate": 3,
    "authentication": 3,
    "security alert": 4,
    "suspicious activity": 4,
    "unusual activity": 4,
    "account suspended": 5,
    "account locked": 5,
    "action required": 3,
    "urgent": 3,
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
 
 
# B5 split the flat risky list into families that carry very different
# weight. RISKY_EXTENSIONS is kept as their union so anything still reading it
# behaves as before.
EXECUTABLE_EXTENSIONS = {
    ".hta", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".lnk", ".scr", ".exe",
    ".com", ".pif", ".cpl", ".msi", ".jar", ".ps1", ".bat", ".cmd",
}
# Mountable containers: used to smuggle an executable past mark-of-the-web.
EXECUTABLE_EXTENSIONS |= {".iso", ".img", ".vhd"}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".xlsb", ".pptm", ".dotm", ".xltm"}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".ace"}

WEB_DOC_EXTENSIONS = {".html", ".htm", ".shtml", ".mht", ".mhtml"}

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
RISKY_EXTENSIONS |= (EXECUTABLE_EXTENSIONS | MACRO_EXTENSIONS
                     | ARCHIVE_EXTENSIONS | WEB_DOC_EXTENSIONS)
