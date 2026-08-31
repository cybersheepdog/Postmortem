"""Ingest and analyze a Microsoft 365 Unified Audit Log (UAL) export.

Accepts the three common shapes an investigator ends up with:
  * Purview portal CSV  (columns incl. an ``AuditData`` JSON string)
  * ``Search-UnifiedAuditLog`` JSON / JSONL (records with an ``AuditData`` string)
  * Office 365 Management Activity / Graph JSON (records that ARE the audit data,
    optionally wrapped in ``{"value": [...]}``)

From the log it derives investigator anchors automatically — the compromise
date, attacker IP(s), attacker address/domain, and rule keywords — and surfaces
the concrete attacker actions (malicious inbox rule, forwarding, sign-ins,
deletions) as *confirmed* evidence for the attack narrative.

Everything is offline: it parses an exported file and performs no live queries.
No Entra sign-in log is required — attacker IPs are taken from the ClientIP that
created the malicious rule/forwarding, then any UserLoggedIn from that IP is
treated as an attacker session.
"""

import csv
import json
import re
from datetime import datetime, timezone

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[0-9A-Fa-f:]{3,}:[0-9A-Fa-f:]+\b")

# Inbox-rule / forwarding operations that establish attacker persistence.
_RULE_OPS = {"new-inboxrule", "set-inboxrule", "updateinboxrules", "set-mailbox"}
_LOGIN_OPS = {"userloggedin"}
_DELETE_OPS = {"harddelete", "softdelete", "movetodeleteditems"}
# Rule conditions that hide mail; matching these marks a rule as concealment.
_KEYWORD_PARAMS = {
    "subjectcontainswords", "bodycontainswords", "subjectorbodycontainswords",
    "fromaddresscontainswords", "hassenderoverride",
}
_FORWARD_PARAMS = {"forwardto", "redirectto", "forwardasattachmentto"}
_MOVE_PARAMS = {"movetofolder"}
# Low-visibility destinations a concealment rule typically uses.
_HIDDEN_FOLDERS = ("rss feeds", "rss subscriptions", "archive", "junk",
                   "deleted items", "conversation history", "notes")


def _parse_iso(value):
    """Parse a UAL timestamp (ISO 8601, usually UTC) into an aware datetime."""
    if not value:
        return None
    s = str(value).strip().replace("Z", "+00:00")
    # UAL fractional seconds can have 7 digits; trim to 6 for fromisoformat.
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(str(value).strip(), fmt)
                break
            except ValueError:
                dt = None
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _split_words(value):
    if value is None:
        return []
    if isinstance(value, list):
        parts = value
    else:
        parts = re.split(r"[;,]", str(value))
    return [p.strip().strip('"').lower() for p in parts if p and p.strip()]


def _params_to_dict(audit_data):
    """Flatten a UAL ``Parameters`` [{Name,Value}, ...] list into {name: value}."""
    out = {}
    for p in (audit_data.get("Parameters") or []):
        if isinstance(p, dict) and "Name" in p:
            out[str(p["Name"]).lower()] = p.get("Value")
    return out


def _iter_records(path):
    """Yield raw record dicts from any of the supported export shapes."""
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        head = fh.read(4096)
        fh.seek(0)
        stripped = head.lstrip()
        if stripped[:1] in ("[", "{"):
            text = fh.read()
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                # JSONL: one object per line.
                for line in text.splitlines():
                    line = line.strip()
                    if line:
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            continue
                return
            if isinstance(data, dict) and "value" in data:
                data = data["value"]
            if isinstance(data, dict):
                data = [data]
            for rec in data:
                yield rec
        else:
            for row in csv.DictReader(fh):
                yield row


def _normalize(record):
    """Return a normalized event dict from one raw record of any shape."""
    audit = record
    raw_ad = record.get("AuditData") if isinstance(record, dict) else None
    if isinstance(raw_ad, str):
        try:
            audit = json.loads(raw_ad)
        except (json.JSONDecodeError, TypeError):
            audit = record
    elif isinstance(raw_ad, dict):
        audit = raw_ad

    def pick(*keys):
        for src in (audit, record):
            for k in keys:
                if isinstance(src, dict) and src.get(k):
                    return src.get(k)
        return None

    op = pick("Operation", "Operations", "activityDisplayName") or ""
    ts = _parse_iso(pick("CreationTime", "CreationDate", "activityDateTime"))
    user = pick("UserId", "UserIds", "MailboxOwnerUPN")
    if isinstance(user, list):
        user = user[0] if user else ""
    ip = pick("ClientIP", "ClientIPAddress", "ActorIpAddress", "OriginatingServer")
    if ip:
        m = _IP_RE.search(str(ip))
        ip = m.group(0) if m else str(ip).strip("[]")
    return {
        "timestamp": ts,
        "operation": str(op),
        "op_lower": str(op).lower(),
        "user": str(user or ""),
        "client_ip": ip or "",
        "audit": audit if isinstance(audit, dict) else {},
    }


def _rule_findings(event):
    """Extract concealment/forwarding details from an inbox-rule/mailbox event."""
    ad = event["audit"]
    params = _params_to_dict(ad)
    # Set-Mailbox forwarding lives in top-level fields too.
    forwards, keywords, move_to = [], [], ""
    delete = False
    for name, value in params.items():
        if name in _FORWARD_PARAMS and value:
            forwards.extend(_EMAIL_RE.findall(str(value)))
        elif name in _MOVE_PARAMS and value:
            move_to = str(value)
        elif name in _KEYWORD_PARAMS and value:
            keywords.extend(_split_words(value))
        elif name in ("deletemessage",) and str(value).lower() in ("true", "1"):
            delete = True
    for fld in ("ForwardingSmtpAddress", "ForwardingAddress"):
        if ad.get(fld):
            forwards.extend(_EMAIL_RE.findall(str(ad[fld])))
    forwards = list(dict.fromkeys(a.lower() for a in forwards))
    keywords = list(dict.fromkeys(keywords))
    hides = delete or any(h in move_to.lower() for h in _HIDDEN_FOLDERS)
    suspicious = bool(forwards or hides or keywords)
    return {
        "forwards": forwards, "keywords": keywords, "move_to": move_to,
        "delete": delete, "suspicious": suspicious,
    }


def analyze_audit_log(path):
    """Parse a UAL export and derive anchors + confirmed attacker events.

    Returns a summary dict with `derived` anchors and human-readable findings,
    or raises on an unreadable file.
    """
    events = [_normalize(r) for r in _iter_records(path)]
    events = [e for e in events if e["operation"]]

    malicious_rules = []
    forwarding = []
    attacker_ips = set()
    attacker_addresses = set()
    attacker_domains = set()
    rule_keywords = set()
    action_times = []

    for e in events:
        if e["op_lower"] in _RULE_OPS:
            f = _rule_findings(e)
            if not f["suspicious"]:
                continue
            entry = {
                "time": e["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ") if e["timestamp"] else "",
                "operation": e["operation"], "user": e["user"], "client_ip": e["client_ip"],
                "forwards": f["forwards"], "move_to": f["move_to"],
                "delete": f["delete"], "keywords": f["keywords"],
            }
            (forwarding if (f["forwards"] and not f["keywords"] and not f["delete"] and not f["move_to"])
             else malicious_rules).append(entry)
            if e["client_ip"]:
                attacker_ips.add(e["client_ip"])
            for a in f["forwards"]:
                attacker_addresses.add(a)
                if "@" in a:
                    attacker_domains.add(a.rsplit("@", 1)[1])
            rule_keywords.update(f["keywords"])
            if e["timestamp"]:
                action_times.append(e["timestamp"])

    # Any sign-in from an attacker IP is an attacker session.
    attacker_logins = []
    for e in events:
        if e["op_lower"] in _LOGIN_OPS and e["client_ip"] and e["client_ip"] in attacker_ips:
            attacker_logins.append({
                "time": e["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ") if e["timestamp"] else "",
                "ip": e["client_ip"], "user": e["user"],
            })
            if e["timestamp"]:
                action_times.append(e["timestamp"])

    deletions = sum(1 for e in events if e["op_lower"] in _DELETE_OPS)

    compromise_dt = min(action_times) if action_times else None
    derived = {
        "compromise_date": compromise_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if compromise_dt else "",
        "attacker_ips": sorted(attacker_ips),
        "attacker_addresses": sorted(attacker_addresses),
        "attacker_domains": sorted(attacker_domains),
        "rule_keywords": sorted(rule_keywords),
    }
    return {
        "events_parsed": len(events),
        "malicious_rules": malicious_rules,
        "forwarding_rules": forwarding,
        "attacker_logins": sorted(attacker_logins, key=lambda x: x["time"]),
        "deletions": deletions,
        "derived": derived,
        "_compromise_dt": compromise_dt,
    }
