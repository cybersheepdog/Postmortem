"""Core data structures for postmortem.

These dataclasses are the shared vocabulary between parsing, scoring, clustering
and reporting. EmailRecord instances are pickled across the process pool and
serialized to the SQLite cache, so keep every field JSON- and pickle-friendly
(plain str/int/bool/float/list/dict).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class AttackTimelineEvent:
    timestamp: str = ""
    path: str = ""
    message_id: str = ""
    sender: str = ""
    subject: str = ""
    stage: str = ""
    score: int = 0
    campaign_id: str = ""
    precursor: bool = False
    evidence: list[str] = field(default_factory=list)


@dataclass
class CampaignInfo:
    campaign_id: str = ""

    campaign_score: int = 0

    message_count: int = 0

    first_seen: str = ""
    last_seen: str = ""

    senders: list[str] = field(default_factory=list)
    sender_domains: list[str] = field(default_factory=list)

    recipients: list[str] = field(default_factory=list)

    subjects: list[str] = field(default_factory=list)

    url_domains: list[str] = field(default_factory=list)

    attachment_names: list[str] = field(default_factory=list)
    attachment_types: list[str] = field(default_factory=list)
    attachment_sha256: list[str] = field(default_factory=list)

    shared_indicators: list[str] = field(default_factory=list)

    likely_origin: str = ""

    confidence: str = "low"


@dataclass
class EmailRecord:
    path: str
    filename: str

    message_id: str = ""
    in_reply_to: str = ""
    references: list[str] = field(default_factory=list)

    sender_name: str = ""
    sender_email: str = ""
    sender_domain: str = ""

    recipients: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)

    date: str = ""
    subject: str = ""

    body: str = ""

    urls: list[str] = field(default_factory=list)
    url_domains: list[str] = field(default_factory=list)

    attachments: list[str] = field(default_factory=list)
    attachment_details: list[dict] = field(default_factory=list)
    url_analysis: list[dict] = field(default_factory=list)

    score: int = 0

    indicators: list[str] = field(default_factory=list)

    thread_id: str = ""

    likely_precursor: bool = False

    campaign_id: str = ""

    campaign_score: int = 0

    campaign_similarity: float = 0.0

    attack_stage: str = ""

    precursor_evidence: list[str] = field(default_factory=list)

    deep_analyzed: bool = False

    authentication_results: dict = field(default_factory=dict)

    # Forensic signals populated by the scenario/anchor analysis pass. These are
    # recomputed every run (they depend on CLI anchors), never trusted from cache.
    authentication_failed: bool = False
    auth_anomaly: bool = False
    self_spoofing: bool = False
    sender_established: bool = False
    sender_first_contact: bool = False
    reply_to_mismatch: bool = False
    lookalike_of: str = ""
    origin_ip: str = ""
    sending_ip_anomaly: bool = False
    is_pre_compromise: bool = False
    is_inbound: bool = True
    deleted_or_moved: bool = False
    hidden_folder: str = ""
    thread_injection: bool = False
    display_name_spoof: bool = False
    rule_target: bool = False
    attachment_threat: bool = False
    attachment_threat_note: str = ""
    anchor_matches: list[str] = field(default_factory=list)
    scenario_score: int = 0
    scenario_reasons: list[str] = field(default_factory=list)
    tier: int = 3

    # Header-hygiene / spoofing-alignment signals, computed from parsed headers.
    # Deliberately weak (low weight): legitimate ESP-relayed mail trips the
    # alignment checks, so these corroborate rather than convict on their own.
    received_chain_anomaly: bool = False
    received_chain_note: str = ""
    message_id_mismatch: bool = False
    date_anomaly: bool = False
    date_anomaly_note: str = ""
    dkim_domain_mismatch: bool = False
    return_path_mismatch: bool = False
    random_local_part: bool = False       # high-entropy sender local-part
    bulk_mail: bool = False               # List-Unsubscribe / Precedence:bulk
    newly_registered_domain: bool = False  # RDAP: sender domain registered recently
    sender_domain_age_days: int = -1      # -1 = unknown/not checked

    # Geolocation / ASN of the originating IP (populated only with --geoip-db).
    origin_country: str = ""
    origin_asn: str = ""
    origin_org: str = ""
    suspicious_geo: bool = False          # hop in an unexpected country
    high_abuse_host: bool = False         # ASN/org matches a high-abuse hoster

    # Evidence provenance (chain of custody per finding). One dict per named
    # finding: {signal, category, source, matched, weight, severity}. Rebuilt
    # every run alongside `indicators`, never trusted from cache.
    provenance: list[dict] = field(default_factory=list)


@dataclass
class Anchors:
    """Ground-truth facts the investigator already knows about the incident."""
    compromise_date: Optional[datetime] = None
    impersonated: list[str] = field(default_factory=list)      # names or emails
    fraud_accounts: list[str] = field(default_factory=list)    # account #s / IBANs
    attacker_domains: list[str] = field(default_factory=list)  # known-bad domains
    attacker_ips: list[str] = field(default_factory=list)      # attacker sending IPs
    attacker_addresses: list[str] = field(default_factory=list)  # attacker emails
    rule_keywords: list[str] = field(default_factory=list)     # malicious-rule terms
    victim_domains: list[str] = field(default_factory=list)    # victim org's domains
    scenario: str = "auto"                                     # auto|ato|impersonation

    def active(self) -> bool:
        return bool(
            self.compromise_date
            or self.impersonated
            or self.fraud_accounts
            or self.attacker_domains
            or self.attacker_ips
            or self.attacker_addresses
            or self.rule_keywords
        )
