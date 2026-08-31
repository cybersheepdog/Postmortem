"""Scoring and analysis over EmailRecord objects.

Candidate screening (v8), the heuristic priority score, thread/temporal/
impersonation analysis, attack-stage classification, per-sender auth
baselining, investigator anchoring, initial-email scoring, tiering, the
evidence graph, timeline and precursor verdict. No I/O or orchestration.
"""

import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Optional

from postmortem.config import (
    CONFIG, PHISHING_TERMS, COMMON_FREE_EMAIL, RISKY_EXTENSIONS,
)
from postmortem.models import EmailRecord, AttackTimelineEvent, Anchors
from postmortem.utils import (
    parse_date, date_sort_key, normalize_email, normalize_subject,
    domain_of, clean_text,
)
from postmortem.urls import IP_URL_RE
from pathlib import Path


def _severity_for(weight: int) -> str:
    """Map a finding's score weight to a coarse severity band."""
    weight = int(weight)
    return "high" if weight >= 6 else "medium" if weight >= 3 else "low"


def make_finding(signal, *, category, source, matched="", weight=0, severity=None):
    """Build one evidence-provenance record for a single named finding.

    Each finding an analyst reads back is tied to *where* its evidence was
    observed (chain of custody), so a conclusion can be independently verified:

      signal    - the human-readable finding (mirrors the `indicators` string)
      category  - signal family: sender|language|url|attachment|auth|identity|
                  concealment|anchor|thread
      source    - the field/artifact the evidence came from, e.g. "header:From",
                  "subject", "body", "header:Reply-To", "authentication_results",
                  "attachment", "origin_ip", "mailbox_metadata",
                  "investigator_anchor", "thread"
      matched   - the concrete value/excerpt that triggered the finding
      weight    - points this finding contributed to the priority score
      severity  - low|medium|high (derived from weight unless given)
    """
    return {
        "signal": signal,
        "category": category,
        "source": source,
        "matched": (str(matched)[:200] if matched not in ("", None) else ""),
        "weight": int(weight),
        "severity": severity or _severity_for(weight),
    }


def _dedupe_provenance(entries):
    """Drop duplicate findings by signal, keeping first occurrence (mirrors the
    dict.fromkeys() dedupe applied to `indicators`)."""
    seen = set()
    out = []
    for e in entries:
        sig = e.get("signal")
        if sig in seen:
            continue
        seen.add(sig)
        out.append(e)
    return out


def classify_attack_stage(record: EmailRecord) -> str:
    text = clean_text(f"{record.subject}\n{record.body}").lower()
    payment = (
        "wire", "payment", "invoice", "bank account", "bank details",
        "routing number", "beneficiary", "gift card", "transfer funds",
    )
    credential = (
        "verify your account", "sign in", "login", "password", "credential",
        "mfa", "multi-factor", "authentication", "account security",
    )
    attachment = ("attached", "attachment", "document", "invoice")
    social = (
        "are you available", "quick question", "urgent", "confidential",
        "let me know when", "can you help",
    )
    if any(x in text for x in payment):
        return "payment_request"
    if record.attachments and any(x in text for x in attachment):
        return "attachment_delivery"
    if record.urls and any(x in text for x in credential):
        return "credential_harvest"
    if any(x in text for x in social):
        return "social_engineering"
    if record.urls:
        return "suspicious_link"
    return "initial_contact"
 
 
def build_evidence_graph(records: list[EmailRecord]) -> dict[str, object]:
    nodes, edges = [], []
    groups = {}
 
    for i, record in enumerate(records):
        node_id = f"email-{i:06d}"
        nodes.append({
            "id": node_id,
            "path": record.path,
            "date": record.date,
            "sender": record.sender_email,
            "subject": record.subject,
            "score": record.score,
            "stage": getattr(record, "attack_stage", None),
        })
 
        for a in record.attachment_details:
            if isinstance(a, dict) and a.get("sha256"):
                groups.setdefault(("attachment_sha256", a["sha256"]), []).append(node_id)
        for a in record.url_analysis:
            if a.get("registrable_domain"):
                groups.setdefault(("url_domain", a["registrable_domain"]), []).append(node_id)
        if record.sender_domain:
            groups.setdefault(("sender_domain", record.sender_domain), []).append(node_id)
 
    for (relation, indicator), ids in groups.items():
        ids = list(dict.fromkeys(ids))
        for left, right in zip(ids, ids[1:]):
            edges.append({
                "source": left,
                "target": right,
                "relation": relation,
                "indicator": indicator,
                "strength": "strong",
            })
 
    ordered = sorted(range(len(records)), key=lambda i: date_sort_key(records[i]))
    for left, right in zip(ordered, ordered[1:]):
        edges.append({
            "source": f"email-{left:06d}",
            "target": f"email-{right:06d}",
            "relation": "temporal_sequence",
            "indicator": "chronological order",
            "strength": "contextual",
        })
    return {"nodes": nodes, "edges": edges}
 
 
def earliest_malicious_precursor(records: list[EmailRecord]) -> dict[str, object]:
    ordered = sorted(records, key=date_sort_key)
    suspicious = [
        r for r in ordered
        if r.score >= 35 or r.attack_stage in {
            "credential_harvest", "payment_request",
            "attachment_delivery", "suspicious_link",
        }
    ]
    candidates = []
 
    for record in ordered:
        evidence = list(record.precursor_evidence)
        if not evidence:
            evidence = list(record.indicators)
 
        evidence = [
            x for x in evidence
            if any(
                word in x.lower()
                for word in (
                    "credential", "login", "phishing", "suspicious url",
                    "impersonat", "attachment", "payment", "redirect",
                    "punycode", "userinfo", "ip address",
                )
            )
        ]
        if not evidence:
            continue
 
        record_domains = {
            a.get("registrable_domain")
            for a in record.url_analysis
            if a.get("registrable_domain")
        }
        record_hashes = {
            a.get("sha256")
            for a in record.attachment_details
            if isinstance(a, dict) and a.get("sha256")
        }
        later = []
 
        for future in suspicious:
            if future is record:
                continue
            future_domains = {
                a.get("registrable_domain")
                for a in future.url_analysis
                if a.get("registrable_domain")
            }
            future_hashes = {
                a.get("sha256")
                for a in future.attachment_details
                if isinstance(a, dict) and a.get("sha256")
            }
            if (
                record.campaign_id
                and future.campaign_id == record.campaign_id
            ) or record_domains & future_domains or record_hashes & future_hashes:
                later.append(future)
 
        if later:
            candidates.append((date_sort_key(record), record, evidence, later))
 
    if not candidates:
        return {
            "verdict": "NO DEFENSIBLE MALICIOUS PRECURSOR IDENTIFIED",
            "confidence": "low",
            "path": "", "date": "", "sender": "", "subject": "", "stage": "",
            "evidence": [], "supporting_messages": [],
        }
 
    _, record, evidence, later = sorted(candidates, key=lambda x: x[0])[0]
    return {
        "verdict": "LIKELY MALICIOUS PRECURSOR",
        "confidence": "high" if len(set(evidence)) >= 2 else "medium",
        "path": record.path,
        "date": record.date,
        "sender": record.sender_email,
        "subject": record.subject,
        "stage": getattr(record, "attack_stage", None),
        "evidence": list(dict.fromkeys(evidence))[:12],
        "supporting_messages": [
            {
                "date": r.date,
                "path": r.path,
                "subject": r.subject,
                "stage": r.attack_stage,
            }
            for r in later[:10]
        ],
    }
 
 
# ============================================================================
# SCENARIO / ANCHOR ANALYSIS
#
# Different BEC scenarios put the "initial malicious email" in a different
# place. Account-takeover (ATO) starts with a credential phish delivered to the
# victim *before* the first attacker action (e.g. a new mailbox rule).
# Impersonation / vendor-compromise (VEC) starts with the fraudulent inbound
# request itself. This section lets an investigator anchor on what they already
# know, classifies the scenario, scores each message as a candidate "initial"
# email under the matching profile, and traces to the earliest malicious touch.
# ============================================================================

_CREDENTIAL_LURES = (
    "verify your account", "verify your identity", "confirm your account",
    "sign in", "log in", "login", "password", "reset your password",
    "mfa", "multi-factor", "two-factor", "authentication", "account security",
    "unusual sign", "unusual activity", "suspicious sign", "re-validate",
    "revalidate", "reactivate", "mailbox", "quota", "storage full",
    "storage limit", "voicemail", "new voicemail", "missed call", "fax",
    "shared document", "document has been shared", "view document",
    "review the document", "secure message", "encrypted message", "docusign",
    "sharepoint", "onedrive", "adobe", "expire", "session expired",
)

_PAYMENT_TERMS = (
    "wire", "wire transfer", "payment", "invoice", "bank account",
    "bank details", "banking details", "routing number", "beneficiary",
    "gift card", "transfer funds", "remittance", "ach", "direct deposit",
)

_BANK_CHANGE_TERMS = (
    "change bank", "changed bank", "new bank account", "updated bank details",
    "update our bank", "new account details", "bank details have changed",
    "update your records", "new banking details", "change of bank",
    "update payment", "revised invoice",
)

_URGENCY_TERMS = (
    "urgent", "immediately", "as soon as possible", "asap", "today",
    "right away", "confidential", "do not call", "do not tell", "don't tell",
    "keep this between",
)

_LOGIN_PATH_HINTS = (
    "login", "signin", "sign-in", "verify", "auth", "account", "secure",
    "validate", "mfa", "office365", "owa", "webmail",
)

_HOMOGLYPHS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t",
    "8": "b", "$": "s", "@": "a",
})

# Score at or above which a candidate is considered a defensible initial email
# (configurable via CONFIG["tier1_threshold"]).
def _initial_strong_floor():
    return CONFIG["tier1_threshold"]


def parse_anchor_datetime(value: str) -> Optional[datetime]:
    if not value:
        return None
    value = value.strip()
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        dt = parse_date(value)
    if dt is not None and dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def build_anchors(args) -> Anchors:
    def flatten(values):
        out = []
        for value in (values or []):
            out.extend(part.strip() for part in str(value).split(",") if part.strip())
        return out

    return Anchors(
        compromise_date=parse_anchor_datetime(getattr(args, "compromise_date", "") or ""),
        impersonated=flatten(getattr(args, "impersonated", None)),
        fraud_accounts=flatten(getattr(args, "fraud_account", None)),
        attacker_domains=[d.lower() for d in flatten(getattr(args, "attacker_domain", None))],
        attacker_ips=flatten(getattr(args, "attacker_ip", None)),
        attacker_addresses=[normalize_email(a) for a in flatten(getattr(args, "attacker_address", None))],
        rule_keywords=[k.lower() for k in flatten(getattr(args, "rule_keyword", None))],
        victim_domains=[d.lower() for d in flatten(getattr(args, "victim_domain", None))],
        scenario=getattr(args, "scenario", "auto") or "auto",
    )


def _canon_domain(domain: str) -> str:
    canon = domain.lower().translate(_HOMOGLYPHS)
    return canon.replace("rn", "m").replace("vv", "w")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (ca != cb),
            ))
        previous = current
    return previous[-1]


def find_lookalike(domain: str, known_domains: set[str], max_distance: int = 1) -> str:
    """Return a known domain that `domain` confusably resembles, else ""."""
    if not domain or len(domain) < 5 or domain in known_domains:
        return ""
    canon = _canon_domain(domain)
    for known in known_domains:
        if not known or known == domain or len(known) < 5:
            continue
        canon_known = _canon_domain(known)
        if canon == canon_known:
            return known  # differs only by homoglyph substitution
        if abs(len(canon) - len(canon_known)) <= max_distance:
            if 0 < _levenshtein(canon, canon_known) <= max_distance:
                return known
    return ""


def extract_origin_ip(auth: dict) -> str:
    ip_re = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    for value in (auth.get("x_originating_ip", []) or []):
        match = ip_re.search(str(value))
        if match:
            return match.group(0)
    received = auth.get("received", []) or []
    if received:
        # The earliest hop (submission) is conventionally last in the list.
        match = ip_re.search(str(received[-1]))
        if match:
            return match.group(0)
    return ""


def _norm_account(value: str) -> str:
    return re.sub(r"[\s\-]", "", str(value)).lower()


def attachment_threat_summary(record):
    """Return (notes, has_credential_form) describing dangerous attachments on a
    record, from the offline attachment inspection performed at parse time."""
    notes, credential = [], False
    for a in (record.attachment_details or []):
        if not isinstance(a, dict):
            continue
        fn = a.get("filename", "") or "(unnamed)"
        if a.get("html_form"):
            notes.append(f"credential form in attachment {fn}")
            credential = True
        if a.get("macro"):
            notes.append(f"macro-enabled attachment {fn}")
        if a.get("suspicious_name"):
            notes.append(f"deceptively named attachment {fn}")
        if a.get("forwarded_email"):
            notes.append(f"forwarded message attached ({fn})")
    return notes, credential


# Folder markers, inferred from the .eml file path when the export preserves
# folder structure. Hard-deletion (Recoverable Items) is a strong concealment
# signal; a rule moving mail to a low-visibility folder is a weaker one.
_FOLDER_DELETED = (
    "recoverable items", "recoverableitems", "deletions", "purges",
    "deleted items", "deleted messages", "trash",
)
_FOLDER_MOVED = (
    "rss feeds", "rss subscriptions", "junk email", "junk e-mail", "junk",
    "conversation history", "archive",
)


def folder_hint(path: str) -> tuple[str, str]:
    """Infer ('deleted'|'moved'|'', marker) from a message's file path."""
    low = (path or "").replace("\\", "/").lower()
    for marker in _FOLDER_DELETED:
        if marker in low:
            return "deleted", marker
    for marker in _FOLDER_MOVED:
        if marker in low:
            return "moved", marker
    return "", ""


def message_arrival_dt(record) -> Optional[datetime]:
    """Best-effort arrival time. Prefers the topmost (final-hop) Received header,
    stamped by the receiving mail servers and hard for a sender to forge, and
    falls back to the forgeable Date header."""
    received = (record.authentication_results or {}).get("received", []) or []
    if received:
        parts = str(received[0]).rsplit(";", 1)
        if len(parts) == 2:
            dt = parse_date(parts[1].strip())
            if dt is not None:
                return dt
    return parse_date(record.date)


def build_thread_participants(records):
    """Group messages into conversations by their shared Message-ID / In-Reply-To
    / References graph, then map each message path -> the set of sender domains
    that appeared EARLIER in its conversation. Used to spot a reply injected
    from a domain that was not part of the prior exchange."""
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for r in records:
        ids = [i for i in ([r.message_id, r.in_reply_to] + list(r.references or [])) if i]
        for i in ids:
            find(i)
        for i in ids[1:]:
            union(ids[0], i)

    conversations = defaultdict(list)
    for r in records:
        anchor = r.message_id or r.in_reply_to or (r.references[0] if r.references else None) or r.path
        conversations[find(anchor)].append(r)

    far_future = datetime.max.replace(tzinfo=timezone.utc)
    earlier_domains = {}
    for members in conversations.values():
        members.sort(key=lambda r: message_arrival_dt(r) or far_future)
        seen = set()
        for r in members:
            earlier_domains[r.path] = set(seen)
            if r.sender_domain:
                seen.add(r.sender_domain)
    return earlier_domains


def build_contact_names(records):
    """Map normalized display name -> set of email addresses that have used it,
    to detect display-name impersonation of a known contact."""
    names = defaultdict(set)
    for r in records:
        name = (r.sender_name or "").strip().lower()
        if name and r.sender_email:
            names[name].add(r.sender_email)
    return names


def build_baselines(records, domain_min=None, sender_min=None,
                    established_min=None, enforce_min=None):
    domain_min = CONFIG["baseline_domain_min"] if domain_min is None else domain_min
    sender_min = CONFIG["baseline_sender_min"] if sender_min is None else sender_min
    established_min = CONFIG["baseline_established_min"] if established_min is None else established_min
    enforce_min = CONFIG["baseline_enforce_min"] if enforce_min is None else enforce_min
    domain_counts = Counter(r.sender_domain for r in records if r.sender_domain)
    sender_counts = Counter(r.sender_email for r in records if r.sender_email)
    frequent_domains = {d for d, c in domain_counts.items() if c >= domain_min}
    frequent_senders = {s for s, c in sender_counts.items() if c >= sender_min}
    sender_ip_counts = defaultdict(Counter)

    # Per-domain authentication outcomes, so we can score DEVIATION from each
    # sender's own norm rather than absolute pass/fail (many legitimate small
    # senders are chronically misconfigured and always fail).
    auth_pass = Counter()
    auth_seen = Counter()   # messages where any explicit pass/fail was observed
    for r in records:
        if r.sender_email and r.origin_ip:
            sender_ip_counts[r.sender_email][r.origin_ip] += 1
        a = r.authentication_results or {}
        dom = r.sender_domain
        if not dom:
            continue
        passed = bool(a.get("dmarc_pass") or a.get("spf_pass") or a.get("dkim_pass"))
        failed = bool(a.get("spf_fail") or a.get("dkim_fail") or a.get("dmarc_fail"))
        if passed or failed:
            auth_seen[dom] += 1
            if passed:
                auth_pass[dom] += 1

    # A domain "enforces"/authenticates if, with enough observations, it passes
    # the majority of the time. Failures from such a domain are anomalous.
    enforce_domains = {
        dom for dom, seen in auth_seen.items()
        if seen >= enforce_min and auth_pass[dom] / seen >= 0.5
    }
    established_domains = {d for d, c in domain_counts.items() if c >= established_min}
    first_contact_domains = {d for d, c in domain_counts.items() if c <= 1}

    baselines = {
        "domain_counts": domain_counts,
        "enforce_domains": enforce_domains,
        "established_domains": established_domains,
        "first_contact_domains": first_contact_domains,
    }
    return frequent_domains, frequent_senders, sender_ip_counts, baselines


def detect_scenario(records, anchors: Anchors):
    if anchors.scenario in ("ato", "impersonation"):
        return anchors.scenario, f"forced by --scenario {anchors.scenario}"
    if anchors.compromise_date:
        return "ato", "compromise timestamp supplied (mailbox takeover anchor)"
    recipient_counts = Counter()
    for r in records:
        for address in r.recipients:
            if address:
                recipient_counts[address.lower()] += 1
    total = len(records)
    dominant = recipient_counts.most_common(1)
    if dominant and total and dominant[0][1] >= 0.6 * total:
        return "ato", f"corpus dominated by one mailbox ({dominant[0][0]})"
    if anchors.fraud_accounts or anchors.impersonated:
        return "impersonation", "financial/identity anchor without takeover markers"
    return "impersonation", "default profile (no account-takeover markers detected)"


def annotate_forensic_signals(
    records, internal_domains, frequent_domains, lookalike_map,
    sender_ip_counts, frequent_senders, anchors, baselines, victim_domains,
    victim_address, thread_participants, contact_names,
):
    """Wire the parsed-but-unused signals (auth, Reply-To, look-alike domain,
    sending-IP anomaly) into the record's indicators/score, and record which
    investigator anchors each message matches. Scenario-independent.

    Authentication is scored by DEVIATION from each sender's baseline, not by
    absolute failure, so chronically-misconfigured legitimate senders do not
    flood the results."""
    enforce_domains = baselines["enforce_domains"]
    established_domains = baselines["established_domains"]
    first_contact_domains = baselines["first_contact_domains"]

    for r in records:
        auth = r.authentication_results or {}
        failed = bool(auth.get("spf_fail") or auth.get("dkim_fail") or auth.get("dmarc_fail"))
        r.authentication_failed = failed
        # Deviation: this message failed but the domain normally authenticates.
        r.auth_anomaly = bool(failed and r.sender_domain in enforce_domains)
        # Self-spoofing: fails while claiming the VICTIM's own domain, which is
        # known/asserted to authenticate. Strongest impersonation signal.
        r.self_spoofing = bool(
            failed and r.sender_domain
            and r.sender_domain in victim_domains
            and r.sender_domain in enforce_domains
        )
        r.sender_established = bool(r.sender_domain in established_domains)
        r.sender_first_contact = bool(r.sender_domain in first_contact_domains)

        reply_to_addr = normalize_email(str(auth.get("reply_to", "") or ""))
        reply_to_domain = domain_of(reply_to_addr)
        r.reply_to_mismatch = bool(
            reply_to_domain and r.sender_domain and reply_to_domain != r.sender_domain
        )
        r.lookalike_of = lookalike_map.get(r.sender_domain, "")
        if r.sender_email in frequent_senders and r.origin_ip:
            counts = sender_ip_counts.get(r.sender_email)
            if counts and counts.get(r.origin_ip, 0) <= 1 and len(counts) > 1:
                r.sending_ip_anomaly = True

        # Direction: the initial malicious email is delivered TO the victim; the
        # victim's own sent mail (and attacker outbound in ATO) is not the entry.
        r.is_inbound = not (victim_address and r.sender_email == victim_address)

        # Folder concealment (only meaningful when the export encodes folders).
        kind, marker = folder_hint(r.path)
        r.deleted_or_moved = bool(kind)
        r.hidden_folder = marker

        # Thread injection: a reply in an existing conversation from a domain
        # that was not part of the earlier exchange, gated on a corroborating
        # suspicious property so legitimately-added participants don't trip it.
        if r.in_reply_to or r.references:
            earlier = thread_participants.get(r.path, set())
            if earlier and r.sender_domain and r.sender_domain not in earlier:
                if (
                    r.authentication_failed or r.reply_to_mismatch
                    or r.lookalike_of or find_lookalike(r.sender_domain, earlier)
                ):
                    r.thread_injection = True

        # Display-name impersonation: this display name is used elsewhere in the
        # corpus by a DIFFERENT address (someone else's identity being borrowed).
        name = (r.sender_name or "").strip().lower()
        if name and r.sender_email:
            known = contact_names.get(name, set())
            others = {a for a in known if a != r.sender_email}
            if others and (
                r.sender_domain not in {domain_of(a) for a in others}
            ):
                r.display_name_spoof = True

        if anchors.compromise_date:
            dt = message_arrival_dt(r)
            r.is_pre_compromise = bool(dt and dt <= anchors.compromise_date)

        # Anchor matching.
        text = f"{r.subject}\n{r.body}".lower()
        norm_text = _norm_account(text)
        matches = []
        for account in anchors.fraud_accounts:
            if account and len(_norm_account(account)) >= 6 and _norm_account(account) in norm_text:
                matches.append(f"fraud account {account}")
        for name in anchors.impersonated:
            needle = name.lower().strip()
            if needle and (needle in (r.sender_name or "").lower() or needle in text):
                matches.append(f"impersonated party '{name}'")
        for dom in anchors.attacker_domains:
            if dom and (
                dom == r.sender_domain
                or dom == reply_to_domain
                or any(dom in (ud or "") for ud in r.url_domains)
            ):
                matches.append(f"attacker domain {dom}")
        for ip in anchors.attacker_ips:
            if ip and r.origin_ip == ip:
                matches.append(f"attacker IP {ip}")
        sender_norm = normalize_email(r.sender_email)
        for addr in anchors.attacker_addresses:
            if addr and (addr == sender_norm or addr == reply_to_addr):
                matches.append(f"attacker address {addr}")
        # Concealment-rule keywords: what the malicious rule filtered on. Messages
        # the rule would have hidden are worth surfacing but are noisier than
        # infrastructure anchors, so they get a lighter, separate boost.
        rule_hits = [kw for kw in anchors.rule_keywords if kw and kw in text]
        r.rule_target = bool(rule_hits)

        # Dangerous attachments (macros, HTML login forms, forwarded phish,
        # deceptive filenames) surfaced by offline attachment inspection.
        attach_notes, _ = attachment_threat_summary(r)
        r.attachment_threat = bool(attach_notes)
        r.attachment_threat_note = "; ".join(attach_notes[:4])

        r.anchor_matches = matches

        # Fold the hard-to-spoof signals into the general priority score.
        # Config-independent, attacker-controlled signals (look-alike domain,
        # Reply-To divergence, self-spoofing) are weighted highest; raw auth
        # failure counts only as a DEVIATION from the sender's norm, so
        # chronically-misconfigured legitimate senders are not promoted.
        pw = CONFIG["priority_weights"]
        bump = 0
        new_indicators = []
        new_prov = []

        def nf(signal, points, *, category, source, matched=""):
            """Record a scenario/anchor finding with its provenance."""
            nonlocal bump
            bump += points
            new_indicators.append(signal)
            new_prov.append(make_finding(
                signal, category=category, source=source,
                matched=matched, weight=points,
            ))

        if r.self_spoofing:
            nf("Authentication fails while claiming an authenticating domain (possible self-spoofing)",
               pw["self_spoofing"], category="auth", source="authentication_results",
               matched=r.sender_domain)
        elif r.auth_anomaly:
            nf(f"Authentication failure deviates from {r.sender_domain}'s norm (usually authenticates)",
               pw["auth_anomaly"], category="auth", source="authentication_results",
               matched=r.sender_domain)
        elif r.authentication_failed:
            nf("Email authentication failed (sender may be misconfigured)",
               pw["auth_fail_chronic"], category="auth", source="authentication_results",
               matched=r.sender_domain)  # chronic/misconfigured sender: weak alone
        if r.reply_to_mismatch:
            nf(f"Reply-To domain ({reply_to_domain}) differs from sender domain",
               pw["reply_to_mismatch"], category="identity", source="header:Reply-To",
               matched=reply_to_domain)
        if r.lookalike_of:
            nf(f"Sender domain resembles a known domain: {r.lookalike_of}",
               pw["lookalike"], category="identity", source="header:From",
               matched=f"{r.sender_domain} ~ {r.lookalike_of}")
        if r.sending_ip_anomaly:
            nf(f"Established sender using an unusual originating IP ({r.origin_ip})",
               pw["sending_ip_anomaly"], category="identity", source="origin_ip",
               matched=r.origin_ip)
        if r.thread_injection:
            nf("Reply injected into an existing thread from a new sender domain",
               pw["thread_injection"], category="thread", source="thread",
               matched=r.thread_id)
        if r.display_name_spoof:
            nf(f"Display name '{r.sender_name}' is used by a different address elsewhere",
               pw["display_name_spoof"], category="identity", source="header:From",
               matched=r.sender_name)
        if r.deleted_or_moved:
            nf(f"Message was deleted/moved to a low-visibility folder ({r.hidden_folder})",
               (pw["deleted"] if r.hidden_folder in _FOLDER_DELETED else pw["moved"]),
               category="concealment", source="mailbox_metadata",
               matched=r.hidden_folder)
        if r.rule_target:
            nf("Matches a keyword the malicious mailbox rule acted on",
               pw["rule_target"], category="anchor", source="investigator_anchor",
               matched=", ".join(rule_hits))
        if r.attachment_threat:
            nf(f"Dangerous attachment: {r.attachment_threat_note}",
               pw["attachment_threat"], category="attachment", source="attachment",
               matched=r.attachment_threat_note)
        if matches:
            bump += pw["anchor"]
            for m in matches:
                sig = f"Matches investigator anchor: {m}"
                new_indicators.append(sig)
                new_prov.append(make_finding(
                    sig, category="anchor", source="investigator_anchor",
                    matched=m, weight=pw["anchor"],
                ))
        if bump:
            r.score += bump
            r.indicators = list(dict.fromkeys(list(r.indicators) + new_indicators))
            r.provenance = _dedupe_provenance(list(r.provenance) + new_prov)


def score_initial_email(record, scenario, anchors: Anchors):
    """Score how likely `record` is THE initial malicious email under the
    active scenario profile. Distinct from the general priority score."""
    # Outbound mail (sent by the mailbox owner, and attacker outbound in ATO) is
    # never the entry point, so it is not an initial-email candidate.
    if not record.is_inbound:
        record.scenario_score = 0
        record.scenario_reasons = []
        return 0

    text = f"{record.subject}\n{record.body}".lower()
    has_url = bool(record.urls)
    cred_lure = any(t in text for t in _CREDENTIAL_LURES)
    pay_lure = any(t in text for t in _PAYMENT_TERMS)
    login_url = any(
        (int(a.get("suspicious_score", 0) or 0) >= 10)
        or any(h in str(a.get("path", "") or "").lower() for h in _LOGIN_PATH_HINTS)
        for a in (record.url_analysis or [])
    )

    # Config-independent, attacker-controlled signals: these do not depend on
    # the sender configuring email authentication correctly, so they are the
    # reliable ones. Auth failure only counts when corroborated by one of them.
    independent = []
    if record.lookalike_of:
        independent.append("lookalike")
    if record.reply_to_mismatch:
        independent.append("reply_to")
    if login_url:
        independent.append("credential_url")
    if record.anchor_matches:
        independent.append("anchor")
    if record.thread_injection:
        independent.append("thread_injection")
    if record.display_name_spoof:
        independent.append("display_name")
    if record.deleted_or_moved:
        independent.append("concealed")
    if record.attachment_threat:
        independent.append("attachment_threat")
    if record.sender_first_contact and (cred_lure or pay_lure):
        independent.append("first_contact_ask")
    corroborated = len(independent) >= 1

    attach_notes, attach_credential = attachment_threat_summary(record)
    iw = CONFIG["initial_weights"]

    score = 0
    reasons = []

    # Authentication by DEVIATION + corroboration, never absolute failure.
    if record.self_spoofing:
        score += iw["self_spoofing"]
        reasons.append("Self-spoofing: fails auth while claiming an authenticating domain")
    elif record.auth_anomaly and corroborated:
        score += iw["auth_anomaly_corroborated"]
        reasons.append("Auth failure deviates from sender norm, corroborated by another signal")
    elif record.auth_anomaly:
        score += iw["auth_anomaly"]
        reasons.append("Auth failure deviates from sender norm (uncorroborated)")
    # Chronic/misconfigured auth failure alone contributes nothing here.

    if record.lookalike_of:
        score += iw["lookalike"]
        reasons.append(f"Look-alike of {record.lookalike_of}")
    if record.reply_to_mismatch:
        score += iw["reply_to_mismatch"]
        reasons.append("Reply-To differs from sender domain")
    if record.sending_ip_anomaly:
        score += iw["sending_ip_anomaly"]
        reasons.append("Unusual originating IP for this sender")
    if record.display_name_spoof:
        score += iw["display_name_spoof"]
        reasons.append("Display-name impersonation of a known contact")
    if record.thread_injection:
        score += iw["thread_injection"]
        reasons.append("Thread hijack: reply from a new domain in an existing thread")
    if record.deleted_or_moved:
        score += (iw["deleted"] if record.hidden_folder in _FOLDER_DELETED else iw["moved"])
        reasons.append(f"Concealed in a low-visibility folder ({record.hidden_folder})")
    if record.rule_target:
        score += iw["rule_target"]
        reasons.append("Matches a keyword the malicious mailbox rule acted on")
    if record.attachment_threat:
        # A credential-form attachment is an entry vector like a login link;
        # macros/deceptive names are weaker but still material.
        score += iw["attachment_credential"] if attach_credential else iw["attachment_other"]
        reasons.append(f"Dangerous attachment ({attach_notes[0]})")

    if scenario == "ato":
        if cred_lure:
            score += iw["cred_lure"]
            reasons.append("Credential-harvest lure language")
        if has_url and (login_url or cred_lure or attach_credential):
            score += iw["credential_link"]
            reasons.append("Link to a credential/login page")
        elif has_url:
            score += iw["has_url"]
        # The compromise date is a filter (see the verdict pool), not a scorer:
        # being in the pre-compromise window is only meaningful for a message
        # that already carries a malicious signal, so it adds no points here.
        if anchors.compromise_date:
            if record.is_pre_compromise:
                reasons.append("Received before the compromise timestamp")
            else:
                score -= iw["post_compromise_penalty"]  # attacker activity, not entry
                reasons.append("Received after the compromise timestamp (post-compromise)")
    else:  # impersonation / VEC
        if pay_lure:
            score += iw["pay_lure"]
            reasons.append("Payment/banking instruction language")
        if any(t in text for t in _BANK_CHANGE_TERMS):
            score += iw["bank_change"]
            reasons.append("Bank-detail change request")
        if any(t in text for t in _URGENCY_TERMS):
            score += iw["urgency"]
            reasons.append("Urgency/secrecy pressure")
        if record.self_spoofing or record.auth_anomaly:
            score += iw["impersonation_extra"]
        if login_url:
            score += iw["impersonation_login_url"]

    for match in record.anchor_matches:
        score += iw["anchor"]
        reasons.append(f"Matches investigator anchor: {match}")

    # Sender history (item 5): a long-established correspondent is unlikely to be
    # the entry point; a first-contact sender making a risky ask is more likely.
    # But never down-weight when the sender's own identity is being abused
    # (self-spoofing, auth anomaly, or a look-alike domain) — that is the attack.
    impersonating = record.self_spoofing or record.auth_anomaly or record.lookalike_of
    if (record.sender_established and not record.anchor_matches
            and not impersonating and score > 0):
        score -= min(score, iw["established_downweight"])
        reasons.append("Established long-term correspondent (down-weighted)")
    elif record.sender_first_contact and (cred_lure or pay_lure):
        score += iw["first_contact_ask"]
        reasons.append("First-contact sender making a credential/payment request")

    record.scenario_score = max(0, score)
    record.scenario_reasons = list(dict.fromkeys(reasons))
    return record.scenario_score


def assign_tiers(records, scenario, anchors: Anchors):
    """Sort every message into review tiers so the analyst works a small, high-
    precision set first instead of thousands of candidates.

    Tier 1 (prime suspects): inbound, strong scenario signal, and — in ATO with
    a compromise date — received before it; any investigator-anchor match is
    always Tier 1. Tier 2: inbound with some scenario signal. Tier 3: the rest.
    """
    counts = Counter()
    for r in records:
        window_ok = True
        if scenario == "ato" and anchors.compromise_date:
            window_ok = r.is_pre_compromise

        if r.is_inbound and r.anchor_matches:
            r.tier = 1
        elif r.is_inbound and window_ok and r.scenario_score >= _initial_strong_floor():
            r.tier = 1
        elif r.is_inbound and r.scenario_score > 0:
            r.tier = 2
        else:
            r.tier = 3
        counts[r.tier] += 1
    return counts


def anchored_initial_email_verdict(records, scenario, anchors: Anchors, scenario_reason: str):
    def entry(r):
        return {
            "path": r.path,
            "timestamp": r.date,
            "sender": r.sender_email,
            "subject": r.subject,
            "initial_score": r.scenario_score,
            "priority_score": r.score,
            "stage": classify_attack_stage(r),
            "reasons": r.scenario_reasons,
            "anchor_matches": r.anchor_matches,
        }

    scored = [r for r in records if r.scenario_score > 0]

    if scenario == "ato" and anchors.compromise_date:
        pool = [r for r in scored if r.is_pre_compromise] or scored
    else:
        pool = scored

    base = {
        "scenario": scenario,
        "scenario_reason": scenario_reason,
        "anchors_supplied": anchors.active(),
    }

    if not pool:
        base.update({
            "verdict": "NO_INITIAL_EMAIL_IDENTIFIED",
            "confidence": "low",
            "reason": "No message accumulated enough scenario-specific signal to be a defensible initial email.",
            "initial_email": None,
            "shortlist": [],
        })
        return base

    pool.sort(key=lambda r: (-r.scenario_score, date_sort_key(r)))

    if scenario == "ato":
        # The initial email is the EARLIEST defensibly-malicious credential phish.
        strong = [r for r in pool if r.scenario_score >= _initial_strong_floor()]
        chosen = min(strong, key=date_sort_key) if strong else pool[0]
    else:
        # The initial fraudulent instruction is the strongest scenario match.
        chosen = pool[0]

    anchored = bool(chosen.anchor_matches)
    if anchored and chosen.scenario_score >= 16:
        confidence = "high"
    elif chosen.scenario_score >= _initial_strong_floor():
        confidence = "medium"
    else:
        confidence = "low"

    base.update({
        "verdict": "LIKELY_INITIAL_EMAIL",
        "confidence": confidence,
        "reason": (
            "Highest-ranked message under the "
            f"{scenario} profile"
            + (" and confirmed against an investigator anchor" if anchored else "")
            + "; an investigative lead, not proof of attacker control."
        ),
        "initial_email": entry(chosen),
        "shortlist": [entry(r) for r in pool[:10]],
    })
    return base


def _narrative_entry(record):
    return {
        "path": record.path,
        "timestamp": record.date,
        "sender": record.sender_email,
        "subject": record.subject,
        "stage": classify_attack_stage(record),
        "reasons": list(record.scenario_reasons or record.indicators)[:5],
    }


def _narrative_summary(scenario, phases):
    if not phases:
        return "Insufficient signal to reconstruct an attack narrative."
    family = "account-takeover" if scenario == "ato" else "impersonation / vendor-compromise"
    by_phase = {p["phase"]: p for p in phases}
    bits = [f"This has the shape of an {family} business email compromise."]
    if "initial_access" in by_phase:
        p = by_phase["initial_access"]
        m = p["messages"][0]
        bits.append(f"Likely entry point: {m['sender']} - \"{m['subject']}\" ({p['timestamp']}).")
    for key in ("compromise", "persistence", "fraud"):
        if key in by_phase:
            bits.append(by_phase[key]["description"])
    return " ".join(bits)


def reconstruct_attack_narrative(records, scenario, anchors, initial_verdict,
                                 audit_summary=None):
    """Assemble the analyzed signals into a chronological attack narrative:
    initial access -> compromise/takeover -> persistence/concealment -> fraud.

    An investigative reconstruction from message signals. When an M365 audit-log
    summary is supplied, the takeover and persistence phases are upgraded to
    *confirmed* facts (sign-ins from the attacker IP, the actual malicious rule).
    """
    audit_summary = audit_summary or {}
    far = datetime.max.replace(tzinfo=timezone.utc)
    by_path = {r.path: r for r in records}
    phases = []
    timeline = []

    def add_event(record, phase, label):
        dt = message_arrival_dt(record)
        timeline.append({
            "timestamp_utc": dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else "",
            "phase": phase,
            "label": label,
            "path": record.path,
            "sender": record.sender_email,
            "subject": record.subject,
        })

    comp_iso = (
        anchors.compromise_date.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if anchors.compromise_date else ""
    )

    # -- 1. Initial access --------------------------------------------------
    chosen = (initial_verdict or {}).get("initial_email")
    entry_rec = by_path.get(chosen["path"]) if chosen else None
    if entry_rec is not None:
        label = ("credential-phishing email" if scenario == "ato"
                 else "fraudulent inbound request")
        phases.append({
            "phase": "initial_access",
            "title": f"Initial access - {label}",
            "timestamp": entry_rec.date,
            "confidence": (initial_verdict or {}).get("confidence", "low"),
            "description": (
                f"The likely entry point is a {label} from "
                f"{entry_rec.sender_email} (\"{entry_rec.subject}\")."
            ),
            "messages": [_narrative_entry(entry_rec)],
        })
        add_event(entry_rec, "initial_access", label)

    # -- 2. Account compromise / takeover markers ---------------------------
    takeover = sorted(
        (r for r in records
         if r.self_spoofing or r.sending_ip_anomaly
         or any("attacker IP" in m or "attacker address" in m for m in r.anchor_matches)),
        key=lambda r: message_arrival_dt(r) or far,
    )
    audit_logins = audit_summary.get("attacker_logins") or []
    if takeover or anchors.compromise_date or audit_logins:
        desc = []
        confirmed = bool(audit_logins)
        if audit_logins:
            first = audit_logins[0]
            desc.append(
                f"CONFIRMED (M365 audit log): sign-in from attacker IP {first['ip']} "
                f"at {first['time']}"
                + (f" ({len(audit_logins)} attacker sign-ins total)." if len(audit_logins) > 1 else ".")
            )
        elif anchors.compromise_date:
            desc.append(f"The earliest known attacker action is dated {comp_iso}.")
        if takeover:
            markers = set()
            for r in takeover[:5]:
                if r.self_spoofing:
                    markers.add("a message spoofing an authenticating internal domain")
                if r.sending_ip_anomaly:
                    markers.add("an established sender using an unfamiliar originating IP")
                if any("attacker IP" in m for m in r.anchor_matches):
                    markers.add("traffic from the known attacker IP")
                if any("attacker address" in m for m in r.anchor_matches):
                    markers.add("use of a known attacker address")
            if markers:
                desc.append("Mail-signal takeover markers: " + "; ".join(sorted(markers)) + ".")
        if desc:
            phases.append({
                "phase": "compromise",
                "title": "Account compromise / takeover",
                "timestamp": (audit_logins[0]["time"] if audit_logins
                              else comp_iso or (takeover[0].date if takeover else "")),
                "confidence": "high" if (confirmed or anchors.compromise_date) else "medium",
                "description": " ".join(desc),
                "messages": [_narrative_entry(r) for r in takeover[:5]],
            })
            for lg in audit_logins[:5]:
                timeline.append({
                    "timestamp_utc": lg["time"], "phase": "compromise",
                    "label": f"attacker sign-in from {lg['ip']}",
                    "path": "", "sender": lg.get("user", ""), "subject": "(M365 audit log)",
                })
            for r in takeover[:5]:
                add_event(r, "compromise", "takeover marker")

    # -- 3. Persistence & concealment ---------------------------------------
    concealed = [r for r in records if r.deleted_or_moved]
    rule_target = [r for r in records if r.rule_target]
    audit_rules = audit_summary.get("malicious_rules") or []
    audit_fwd = audit_summary.get("forwarding_rules") or []
    audit_deletions = audit_summary.get("deletions") or 0
    if anchors.compromise_date or concealed or rule_target or audit_rules or audit_fwd:
        parts = []
        for ru in (audit_rules + audit_fwd)[:3]:
            bits = [f"CONFIRMED (M365 audit log): {ru['operation']} at {ru['time']}"]
            if ru.get("client_ip"):
                bits.append(f"from {ru['client_ip']}")
            actions = []
            if ru.get("forwards"):
                actions.append("forwards to " + ", ".join(ru["forwards"]))
            if ru.get("move_to"):
                actions.append(f"moves to '{ru['move_to']}'")
            if ru.get("delete"):
                actions.append("deletes matching mail")
            if ru.get("keywords"):
                actions.append("keywords: " + ", ".join(ru["keywords"][:8]))
            parts.append(" ".join(bits) + (" - " + "; ".join(actions) if actions else "") + ".")
        if audit_deletions:
            parts.append(f"CONFIRMED: {audit_deletions} deletion event(s) in the audit log.")
        if not audit_rules and not audit_fwd and anchors.compromise_date:
            parts.append(f"A malicious mailbox rule was created ({comp_iso}).")
        if concealed:
            parts.append(f"{len(concealed)} message(s) were deleted or moved to low-visibility folders.")
        if rule_target:
            parts.append(f"{len(rule_target)} message(s) match keywords the concealment rule acted on.")
        if parts:
            phases.append({
                "phase": "persistence",
                "title": "Persistence & concealment",
                "timestamp": (audit_rules[0]["time"] if audit_rules else comp_iso),
                "confidence": "high" if (audit_rules or audit_fwd or anchors.compromise_date) else "medium",
                "description": " ".join(parts),
                "messages": [_narrative_entry(r) for r in (concealed or rule_target)[:5]],
            })
            for ru in (audit_rules + audit_fwd)[:3]:
                timeline.append({
                    "timestamp_utc": ru["time"], "phase": "persistence",
                    "label": f"{ru['operation']} (attacker)",
                    "path": "", "sender": ru.get("client_ip", ""), "subject": "(M365 audit log)",
                })
            for r in concealed[:5]:
                add_event(r, "persistence", "concealed message")

    # -- 4. Fraudulent objective --------------------------------------------
    def is_fraud(r):
        text = f"{r.subject}\n{r.body}".lower()
        pay = any(t in text for t in _PAYMENT_TERMS) or any(t in text for t in _BANK_CHANGE_TERMS)
        anchored = any("fraud account" in m for m in r.anchor_matches)
        post = bool(anchors.compromise_date) and not r.is_pre_compromise
        return anchored or (pay and (post or not r.is_inbound or r.thread_injection))

    fraud = sorted((r for r in records if is_fraud(r)),
                   key=lambda r: message_arrival_dt(r) or far)
    if fraud:
        anchored = any(
            "fraud account" in m for r in fraud for m in r.anchor_matches
        )
        desc = "The fraudulent objective appears to be a payment or bank-detail-change request"
        if anchored:
            desc += " matching the known fraudulent account"
        desc += "."
        phases.append({
            "phase": "fraud",
            "title": "Fraudulent objective",
            "timestamp": fraud[0].date,
            "confidence": "high" if anchored else "medium",
            "description": desc,
            "messages": [_narrative_entry(r) for r in fraud[:5]],
        })
        for r in fraud[:5]:
            add_event(r, "fraud", "fraudulent instruction")

    timeline.sort(key=lambda e: e["timestamp_utc"] or "9999")
    return {
        "scenario": scenario,
        "summary": _narrative_summary(scenario, phases),
        "phases": phases,
        "timeline": timeline,
        "disclaimer": (
            "Investigative reconstruction inferred from message signals; "
            "corroborate with mailbox audit and sign-in logs."
        ),
    }


def run_scenario_analysis(records, internal_domains, anchors: Anchors,
                          audit_summary=None):
    """Full scenario/anchor pipeline. Returns (scenario, reason, verdict)."""
    for r in records:
        r.origin_ip = extract_origin_ip(r.authentication_results or {})

    frequent_domains, frequent_senders, sender_ip_counts, baselines = build_baselines(records)

    # Domains the victim's own org uses (for self-spoofing detection): explicit
    # --victim-domain anchors, otherwise inferred from the internal domains.
    victim_domains = set(anchors.victim_domains) or set(internal_domains)
    # An explicitly-declared victim domain is trusted to authenticate even if
    # the corpus did not happen to record a passing message for it.
    baselines["enforce_domains"] = (
        set(baselines["enforce_domains"]) | set(anchors.victim_domains)
    )

    compare_set = set(frequent_domains) | set(internal_domains)
    lookalike_map = {}
    for domain in {r.sender_domain for r in records if r.sender_domain}:
        if domain in compare_set:
            continue
        match = find_lookalike(domain, compare_set)
        if match:
            lookalike_map[domain] = match

    # Infer the victim mailbox address (dominant recipient in a single mailbox).
    recipient_counts = Counter()
    for r in records:
        for address in r.recipients:
            if address:
                recipient_counts[address.lower()] += 1
    victim_address = recipient_counts.most_common(1)[0][0] if recipient_counts else None

    thread_participants = build_thread_participants(records)
    contact_names = build_contact_names(records)

    scenario, reason = detect_scenario(records, anchors)
    annotate_forensic_signals(
        records, internal_domains, frequent_domains, lookalike_map,
        sender_ip_counts, frequent_senders, anchors, baselines, victim_domains,
        victim_address, thread_participants, contact_names,
    )
    for r in records:
        score_initial_email(r, scenario, anchors)
    tier_counts = assign_tiers(records, scenario, anchors)
    verdict = anchored_initial_email_verdict(records, scenario, anchors, reason)
    verdict["tier_counts"] = {t: tier_counts.get(t, 0) for t in (1, 2, 3)}
    verdict["victim_address"] = victim_address
    verdict["attack_narrative"] = reconstruct_attack_narrative(
        records, scenario, anchors, verdict, audit_summary
    )
    return scenario, reason, verdict


# ==========================================================================
# Candidate screening, priority scoring, and basic thread/temporal analysis
# ==========================================================================

V8_HIGH_SIGNAL_PATTERNS = (
    re.compile(r"\b(?:wire|wiring|wire transfer|bank transfer|ach|routing number|account number)\b", re.I),
    re.compile(r"\b(?:gift card|itunes|google play|prepaid card|voucher)\b", re.I),
    re.compile(r"\b(?:password reset|verify your account|confirm your account|credential|login|sign in)\b", re.I),
    re.compile(r"\b(?:invoice|payment due|payment request|remittance|accounts payable)\b", re.I),
    re.compile(r"\b(?:urgent|confidential|immediately|asap|today only)\b", re.I),
)
 
V8_SOCIAL_ENGINEERING_PATTERNS = (
    re.compile(r"\b(?:ceo|cfo|director|president|executive|boss)\b", re.I),
    re.compile(r"\b(?:new bank|new account|changed bank|updated account|change.*payment)\b", re.I),
    re.compile(r"\b(?:keep this confidential|do not call|don't call|do not reply)\b", re.I),
)
 
V8_URL_RISK_PATTERNS = (
    re.compile(r"https?://", re.I),
    re.compile(r"\b(?:login|signin|verify|secure|account|update|payment)\b", re.I),
)
 
V8_ATTACHMENT_PATTERNS = (
    re.compile(r"\.(?:exe|scr|js|jse|vbs|vbe|bat|cmd|ps1|hta|iso|img|lnk|zip|rar|7z)$", re.I),
    re.compile(r"\.(?:docm|xlsm|pptm)$", re.I),
    re.compile(r"\.(?:html?|shtml)$", re.I),
)


def v8_candidate_score(record, screen_chars: int = 16000):
    """
    Conservative first-pass classifier.
 
    The old scorer effectively made almost every message containing a normal
    URL or attachment a candidate. V8 requires either a strong signal or a
    combination of weaker signals, while preserving authentication failures
    and suspicious structural indicators.
    """
    subject = str(getattr(record, "subject", "") or "")
    sender = str(getattr(record, "sender", "") or "")
    body = str(getattr(record, "body", "") or "")
    # Screening scans only the first `screen_chars` of the body: BEC/phishing
    # asks appear in the subject and early body, and deep analysis re-examines
    # every candidate. Lowering this speeds up pass 1 on long-body mail.
    text = f"{subject}\n{sender}\n{body[:screen_chars]}"
 
    score = 0
    reasons = []
 
    high = sum(bool(p.search(text)) for p in V8_HIGH_SIGNAL_PATTERNS)
    social = sum(bool(p.search(text)) for p in V8_SOCIAL_ENGINEERING_PATTERNS)
    url_risk = sum(bool(p.search(text)) for p in V8_URL_RISK_PATTERNS)
 
    attachment_names = list(getattr(record, "attachments", []) or [])
    risky_attachments = sum(
        bool(p.search(str(name)))
        for name in attachment_names
        for p in V8_ATTACHMENT_PATTERNS
    )
 
    auth = getattr(record, "authentication", {}) or {}
    auth_failures = 0
    for key in ("spf", "dkim", "dmarc"):
        value = str(auth.get(key, "") or "").lower().strip()
        if value in {"fail", "softfail", "neutral", "temperror", "permerror"}:
            auth_failures += 1
 
    url_count = len(getattr(record, "urls", []) or [])
    attachment_count = len(attachment_names)
 
    # Strong signals are sufficient on their own.
    if high >= 2:
        score += 5
        reasons.append("multiple high-signal terms")
    elif high == 1:
        score += 2
        reasons.append("high-signal term")
 
    # Social engineering becomes meaningful when combined with a transactional
    # or URL signal.
    if social and (high or url_count):
        score += 3
        reasons.append("social-engineering combination")
 
    if risky_attachments:
        score += 5
        reasons.append("risky attachment type")
 
    if auth_failures:
        score += min(4, auth_failures * 2)
        reasons.append("authentication anomaly")
 
    # A URL by itself is deliberately NOT enough anymore.
    if url_count and url_risk and (high or social):
        score += 2
        reasons.append("suspicious URL context")
 
    # Generic attachments are weak evidence; don't promote them alone.
    if attachment_count and not risky_attachments and (high or social):
        score += 1
        reasons.append("attachment with suspicious context")
 
    # Very long recipient/action text with transactional language is useful,
    # but remains a secondary signal.
    if len(text) > 12000 and high:
        score += 1
        reasons.append("large transactional body")
 
    # Conservative threshold: strong evidence or at least two independent
    # signal families. This should materially reduce the 96.8% candidate rate
    # seen in the prior run.
    candidate = (
        score >= 5
        or (score >= 4 and (high or social or risky_attachments or auth_failures))
        or (high and social)
    )
 
    return candidate, score, reasons
 
 
def v8_candidate_statistics(records):
    stats = {
        "total": len(records),
        "candidates": 0,
        "by_reason": {},
    }
    for record in records:
        candidate, _, reasons = v8_candidate_score(record)
        if candidate:
            stats["candidates"] += 1
            for reason in reasons:
                stats["by_reason"][reason] = stats["by_reason"].get(reason, 0) + 1
    return stats


def identify_internal_domains(
    records: list[EmailRecord],
) -> set[str]:
 
    sender_domains = Counter(
        r.sender_domain
        for r in records
        if r.sender_domain
    )
 
    recipient_domains = Counter()
 
    for record in records:
 
        for address in (
            record.recipients
            + record.cc
        ):
 
            domain = domain_of(address)
 
            if domain:
                recipient_domains[domain] += 1
 
    domains = set()
 
    for domain, count in sender_domains.items():
 
        if count >= 2:
            domains.add(domain)
 
    for domain, count in recipient_domains.items():
 
        if count >= 3:
            domains.add(domain)
 
    return domains
 
 
def identify_known_contacts(
    records: list[EmailRecord],
) -> set[str]:
 
    contacts = set()
 
    for record in records:
 
        if record.sender_email:
            contacts.add(
                record.sender_email
            )
 
    return contacts
 
 
def calculate_score(
    record: EmailRecord,
    internal_domains: set[str],
    known_contacts: set[str],
):
 
    score = 0

    indicators = []
    provenance = []

    def add(signal, points, *, category, source, matched=""):
        """Record a named finding: score it, list it, and log its provenance."""
        nonlocal score
        score += points
        indicators.append(signal)
        provenance.append(make_finding(
            signal, category=category, source=source,
            matched=matched, weight=points,
        ))

    text = (
        f"{record.subject}\n"
        f"{record.body}"
    ).lower()

    sender = record.sender_email

    sender_domain = record.sender_domain

    # ------------------------------------------------------------------
    # Sender
    # ------------------------------------------------------------------

    if (
        sender_domain
        and internal_domains
        and sender_domain not in internal_domains
    ):
        add(f"External sender: {sender_domain}", 2,
            category="sender", source="header:From", matched=sender_domain)

    if sender_domain in COMMON_FREE_EMAIL:
        add(f"Free-mail sender domain: {sender_domain}", 3,
            category="sender", source="header:From", matched=sender_domain)

    if (
        sender
        and sender not in known_contacts
    ):
        add("Sender is not otherwise observed in the email corpus", 2,
            category="sender", source="corpus:sender_history", matched=sender)

    # ------------------------------------------------------------------
    # Phishing language
    # ------------------------------------------------------------------

    for phrase, points in PHISHING_TERMS.items():

        if phrase in text:
            add(f"Contains phrase: {phrase!r}", points,
                category="language", source="subject+body", matched=phrase)

    # ------------------------------------------------------------------
    # URLs
    # ------------------------------------------------------------------

    if record.urls:
        add(f"Contains {len(record.urls)} URL(s)", 2,
            category="url", source="body",
            matched=", ".join(record.urls[:3]))

    if record.url_domains:
        # Per-domain volume bump; reflected in the total, not a named finding.
        score += len(
            record.url_domains
        )

    if IP_URL_RE.search(text):
        add("URL uses an IP address instead of a domain name", 6,
            category="url", source="body",
            matched=IP_URL_RE.search(text).group(0))

    if record.url_analysis:
        url_risk = sum(int(x.get("risk_score", 0)) for x in record.url_analysis)
        if url_risk:
            add(f"Offline URL analysis identified {url_risk} URL risk point(s)",
                min(12, url_risk), category="url", source="url_analysis",
                matched=f"{url_risk} risk points")
        for item in record.url_analysis:
            for flag in item.get("flags", []):
                add(f"URL: {flag}", 0, category="url", source="url_analysis",
                    matched=item.get("url", flag))

    # ------------------------------------------------------------------
    # Attachments
    # ------------------------------------------------------------------

    if record.attachments:
        add(f"Contains {len(record.attachments)} attachment(s)", 2,
            category="attachment", source="attachment",
            matched=", ".join(record.attachments[:3]))

        for filename in record.attachments:

            extension = (
                Path(filename)
                .suffix
                .lower()
            )

            if extension in RISKY_EXTENSIONS:
                add(f"Potentially risky attachment type: {filename}", 4,
                    category="attachment", source="attachment",
                    matched=filename)

    # ------------------------------------------------------------------
    # BEC combinations
    # ------------------------------------------------------------------

    has_payment_language = any(
        term in text
        for term in (
            "wire transfer",
            "bank account",
            "bank details",
            "change bank",
            "new bank account",
            "updated bank details",
            "remittance",
            "payment",
        )
    )

    has_urgency = any(
        term in text
        for term in (
            "urgent",
            "immediately",
            "as soon as possible",
            "action required",
            "today",
        )
    )

    has_secrecy = any(
        term in text
        for term in (
            "confidential",
            "do not call",
            "do not tell",
            "don't tell",
            "keep this confidential",
        )
    )

    if (
        has_payment_language
        and has_urgency
    ):
        add("Combines payment/banking language with urgency", 5,
            category="language", source="subject+body",
            matched="payment language + urgency cue")

    if (
        has_payment_language
        and has_secrecy
    ):
        add("Combines payment/banking language with secrecy", 5,
            category="language", source="subject+body",
            matched="payment language + secrecy cue")

    # ------------------------------------------------------------------
    # Subject
    # ------------------------------------------------------------------

    subject_hit = re.search(
        r"(?i)"
        r"(urgent|action required|payment|wire|"
        r"invoice|security|verify|password)",
        record.subject,
    )
    if subject_hit:
        add("Subject contains a high-interest BEC/phishing term", 2,
            category="language", source="subject",
            matched=subject_hit.group(0))

    record.score = score

    record.indicators = list(
        dict.fromkeys(indicators)
    )
    record.provenance = _dedupe_provenance(provenance)
 
 
# ============================================================================
# THREAD ANALYSIS
# ============================================================================
 
def calculate_thread_ids(
    records: list[EmailRecord],
):
 
    by_message_id = {
        r.message_id: r
        for r in records
        if r.message_id
    }
 
    for record in records:
 
        if not record.message_id:
 
            normalized_subject = normalize_subject(
                record.subject
            )
 
            record.thread_id = (
                "subject:"
                + normalized_subject
                if normalized_subject
                else
                "file:"
                + record.filename
            )
 
            continue
 
        current = record.message_id
 
        visited = set()
 
        while current in by_message_id:
 
            if current in visited:
                break
 
            visited.add(current)
 
            current_record = by_message_id[
                current
            ]
 
            parent_id = ""
 
            if current_record.references:
 
                parent_id = (
                    current_record.references[0]
                )
 
            elif current_record.in_reply_to:
 
                parent_id = (
                    current_record.in_reply_to
                )
 
            if (
                not parent_id
                or parent_id not in by_message_id
            ):
                break
 
            current = parent_id
 
        record.thread_id = current
 
 
def analyze_temporal_signals(
    records: list[EmailRecord],
):
 
    threads = defaultdict(list)
 
    for record in records:
 
        threads[
            record.thread_id
        ].append(record)
 
    for thread_records in threads.values():
 
        thread_records.sort(
            key=date_sort_key
        )
 
        for index, record in enumerate(
            thread_records
        ):
 
            later = (
                thread_records[index + 1:]
            )
 
            if not later:
                continue
 
            later_max = max(
                (
                    r.score
                    for r in later
                ),
                default=0,
            )
 
            if (
                record.score >= 5
                and later_max
                >= record.score + 4
            ):
 
                record.score += 5

                _sig = "Precedes a later, more suspicious message in the same thread"
                record.indicators.append(_sig)
                record.provenance.append(make_finding(
                    _sig, category="thread", source="thread", weight=5,
                    matched=record.thread_id,
                ))

                record.likely_precursor = True

            record_text = (
                record.subject
                + "\n"
                + record.body
            ).lower()
 
            if (
                record.urls
                and any(
                    term in record_text
                    for term in (
                        "login",
                        "sign in",
                        "password",
                        "verify",
                        "authenticate",
                    )
                )
            ):
 
                for later_record in later:
 
                    later_text = (
                        later_record.subject
                        + "\n"
                        + later_record.body
                    ).lower()
 
                    if any(
                        term in later_text
                        for term in (
                            "wire transfer",
                            "bank account",
                            "change bank",
                            "payment",
                        )
                    ):
 
                        record.score += 8

                        _sig = "Possible phishing/login precursor to later payment or banking activity"
                        record.indicators.append(_sig)
                        record.provenance.append(make_finding(
                            _sig, category="thread", source="thread", weight=8,
                            matched=record.thread_id,
                        ))

                        record.likely_precursor = True

                        break
 
 
def detect_possible_impersonation(
    records: list[EmailRecord],
):
 
    for record in records:
 
        if (
            not record.sender_name
            or not record.sender_email
        ):
            continue
 
        name_words = re.findall(
            r"[A-Za-z]{3,}",
            record.sender_name.lower(),
        )
 
        email_local = (
            record.sender_email
            .split("@")[0]
            .lower()
        )
 
        if len(name_words) >= 2:
 
            meaningful = [
                word
                for word in name_words
                if word not in {
                    "the",
                    "and",
                    "company",
                    "inc",
                    "llc",
                    "ltd",
                }
            ]
 
            if meaningful:
 
                matches = sum(
                    word in email_local
                    for word in meaningful
                )
 
                if matches == 0:

                    record.score += 2

                    _sig = "Display name does not obviously correspond to sender address"
                    record.indicators.append(_sig)
                    record.provenance.append(make_finding(
                        _sig, category="identity", source="header:From", weight=2,
                        matched=f"{record.sender_name} <{record.sender_email}>",
                    ))


def build_attack_timeline(records: list[EmailRecord]) -> list[AttackTimelineEvent]:
    events = []
    for r in sorted(records, key=date_sort_key):
        evidence = []
        if r.likely_precursor: evidence.append("Heuristic precursor relationship to later activity")
        evidence.extend(r.indicators[:5])
        events.append(AttackTimelineEvent(r.date, r.path, r.message_id, r.sender_email, r.subject, classify_attack_stage(r), r.score, r.campaign_id, r.likely_precursor, list(dict.fromkeys(evidence))))
    return events
 
 
def earliest_malicious_precursor_verdict(records: list[EmailRecord]) -> dict:
    ordered = sorted(records, key=date_sort_key)
    candidates = []
    for i, r in enumerate(ordered):
        if not r.date or not r.likely_precursor: continue
        later = [x for x in ordered[i+1:] if x.score >= max(10, r.score - 1)]
        stage = classify_attack_stage(r)
        if later and stage in {"credential_harvest", "delivery_or_credential_harvest", "social_engineering", "attachment_delivery"}:
            evidence = [x for x in r.indicators if any(k in x.lower() for k in ("precursor", "phishing", "login", "url"))]
            candidates.append((r, later, evidence))
    if not candidates:
        return {"verdict": "NO_EARLIEST_MALICIOUS_PRECURSOR_IDENTIFIED", "confidence": "low", "message_path": "", "timestamp": "", "reason": "No earlier message met the heuristic precursor criteria and was followed by a materially suspicious event in the available corpus.", "follow_on_messages": []}
    candidates.sort(key=lambda x: (date_sort_key(x[0]), -x[0].score))
    r, later, evidence = candidates[0]
    confidence = "high" if r.score >= 18 and any(x.score >= 20 for x in later) else "medium"
    return {"verdict": "EARLIEST_MALICIOUS_PRECURSOR", "confidence": confidence, "message_path": r.path, "timestamp": r.date, "message_id": r.message_id, "sender": r.sender_email, "subject": r.subject, "stage": classify_attack_stage(r), "score": r.score, "reason": "Earliest chronologically observed message satisfying precursor heuristics before a later materially suspicious event; this is an investigation verdict, not proof of attacker control.", "evidence": evidence[:10], "follow_on_messages": [{"path": x.path, "timestamp": x.date, "subject": x.subject, "score": x.score, "stage": classify_attack_stage(x)} for x in later[:5]]}
