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
from collections import Counter
from datetime import datetime, timezone

from postmortem.utils import normalize_message_id

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
# Inbox-rule forwarding, plus the mailbox-level equivalents. Set-Mailbox
# records the change inside Parameters, not as a top-level field, so omitting
# these names here meant SMTP forwarding -- one of the most common BEC
# persistence mechanisms -- was never detected at all.
_FORWARD_PARAMS = {
    "forwardto", "redirectto", "forwardasattachmentto",
    "forwardingsmtpaddress", "forwardingaddress",
}
# Not a forwarding target itself: it says mail is forwarded *and* kept, which
# is how an attacker avoids the user noticing their mail disappearing.
_FORWARD_CORROBORATION = {"delivertomailboxandforward"}
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
    keeps_copy = False
    # The rule's conditions kept apart by which field they test, so the rule
    # can be re-run as a predicate rather than only mined for keywords. A
    # word that must appear in the subject is a different rule from the same
    # word appearing anywhere in the body.
    conditions = {"subject": [], "body": [], "subject_or_body": [], "from": []}
    _COND_FIELD = {
        "subjectcontainswords": "subject",
        "bodycontainswords": "body",
        "subjectorbodycontainswords": "subject_or_body",
        "fromaddresscontainswords": "from",
        "from": "from",
        "fromaddress": "from",
    }
    for name, value in params.items():
        if name in _FORWARD_PARAMS and value:
            # "smtp:exfil@evil.example" is the usual Set-Mailbox form.
            forwards.extend(_EMAIL_RE.findall(str(value)))
        elif name in _FORWARD_CORROBORATION and str(value).lower() in ("true", "1"):
            keeps_copy = True
        elif name in _MOVE_PARAMS and value:
            move_to = str(value)
        elif name in _KEYWORD_PARAMS and value:
            words = _split_words(value)
            keywords.extend(words)
            field = _COND_FIELD.get(name)
            if field:
                conditions[field].extend(words)
        elif name in _COND_FIELD and value:
            words = _split_words(value)
            conditions[_COND_FIELD[name]].extend(words)
        elif name in ("deletemessage",) and str(value).lower() in ("true", "1"):
            delete = True
    for fld in ("ForwardingSmtpAddress", "ForwardingAddress"):
        if ad.get(fld):
            forwards.extend(_EMAIL_RE.findall(str(ad[fld])))
    forwards = list(dict.fromkeys(a.lower() for a in forwards))
    keywords = list(dict.fromkeys(keywords))
    conditions = {k: list(dict.fromkeys(v)) for k, v in conditions.items() if v}
    hides = delete or any(h in move_to.lower() for h in _HIDDEN_FOLDERS)
    suspicious = bool(forwards or hides or keywords)
    return {
        "forwards": forwards, "keywords": keywords, "move_to": move_to,
        "conditions": conditions,
        "delete": delete, "suspicious": suspicious, "keeps_copy": keeps_copy,
        "mailbox_level": bool(forwards) and event["op_lower"] == "set-mailbox",
    }




# Operations that touch a specific message and carry its InternetMessageId.
# These are the join points between the audit log and the corpus: everything
# else in the log is about the mailbox, not about a message.
_ITEM_OPS = {
    "harddelete": "hard-deleted",
    "softdelete": "soft-deleted",
    "movetodeleteditems": "moved to Deleted Items",
    "movetofolder": "moved to another folder",
    "move": "moved",
    "mailitemsaccessed": "read",
    "messagebind": "opened in the reading pane",
    "send": "sent",
    "sendas": "sent as the mailbox owner",
    "sendonbehalf": "sent on behalf of the mailbox owner",
    "create": "created",
    "update": "modified",
}


# Operations where the attacker *did something to* the message, as opposed to
# merely seeing it. The distinction matters for volume: a single
# MailItemsAccessed sync record can name every item in a folder, so treating a
# read as proof of targeting would promote whole mailboxes. A delete, a move or
# a send is deliberate and specific.
_DELIBERATE_OPS = {
    "harddelete", "softdelete", "movetodeleteditems", "movetofolder", "move",
    "send", "sendas", "sendonbehalf", "update",
}


def _walk_message_ids(node, out, depth=0):
    """Collect (InternetMessageId, subject, folder) triples from audit data.

    The id lives in a different place for each operation family -- ``Item`` for
    a send or a bind, ``AffectedItems[]`` for a delete or a move, and
    ``Folders[].FolderItems[]`` for MailItemsAccessed -- and Microsoft has
    added shapes over time. Rather than encode each one, walk the structure and
    take the ids wherever they appear, keeping the nearest subject and folder
    for context.
    """
    if depth > 6 or not isinstance(node, (dict, list)):
        return
    if isinstance(node, list):
        for item in node:
            _walk_message_ids(item, out, depth + 1)
        return

    mid = ""
    for key in ("InternetMessageId", "internetMessageId", "InternetMessageID"):
        if node.get(key):
            mid = str(node[key])
            break
    if mid:
        folder = ""
        parent = node.get("ParentFolder") or node.get("Folder") or {}
        if isinstance(parent, dict):
            folder = str(parent.get("Path") or parent.get("Name") or "")
        out.append((mid, str(node.get("Subject") or ""), folder))

    for value in node.values():
        if isinstance(value, (dict, list)):
            _walk_message_ids(value, out, depth + 1)


def build_message_index(events, attacker_ips=(), compromise_dt=None):
    """Map normalized Message-ID -> the audit events that touched that message.

    This is the join the tool was missing. Every other audit finding describes
    the mailbox; these describe a *specific message*, which is what lets the
    report say "hard-deleted by the attacker at 14:32 from 203.0.113.9" of a
    named item rather than inferring anything from its wording.
    """
    attacker_ips = set(attacker_ips or ())
    index = {}
    matched_events = 0

    for e in events:
        verb = _ITEM_OPS.get(e["op_lower"])
        if not verb:
            continue
        found = []
        _walk_message_ids(e["audit"], found)
        if not found:
            continue
        matched_events += 1

        ip = e["client_ip"]
        ts = e["timestamp"]
        # Attribution is by IP, not by operation: a user reading or deleting
        # their own mail is routine, and the same operation from the address
        # that built the malicious rule is not.
        by_attacker = bool(ip and ip in attacker_ips)
        post = bool(ts and compromise_dt and ts >= compromise_dt)

        for mid, subject, folder in found:
            key = normalize_message_id(mid)
            if not key:
                continue
            index.setdefault(key, []).append({
                "time": ts.strftime("%Y-%m-%dT%H:%M:%SZ") if ts else "",
                "operation": e["operation"],
                "verb": verb,
                "user": e["user"],
                "client_ip": ip,
                "subject": subject,
                "folder": folder,
                "by_attacker": by_attacker,
                "deliberate": e["op_lower"] in _DELIBERATE_OPS,
                "post_compromise": post,
            })

    for key in index:
        index[key].sort(key=lambda x: x["time"])
    return {
        "by_message_id": index,
        "messages_referenced": len(index),
        "events_with_message_id": matched_events,
    }



def _ip_activity(events, attacker_ips):
    """Per-client-IP operation profile, for attribution and geolocation.

    Attribution previously stopped at UserLoggedIn: an attacker could create a
    rule, read a hundred messages and delete a dozen from the same address and
    only the sign-in was ever attributed to them. Every operation from a known
    attacker address is attacker activity.
    """
    attacker_ips = set(attacker_ips or ())
    profile = {}
    for e in events:
        ip = e["client_ip"]
        if not ip:
            continue
        p = profile.setdefault(ip, {
            "ip": ip, "events": 0, "operations": Counter(),
            "users": set(), "first": None, "last": None,
            "is_attacker": ip in attacker_ips,
        })
        p["events"] += 1
        p["operations"][e["operation"]] += 1
        if e["user"]:
            p["users"].add(e["user"])
        ts = e["timestamp"]
        if ts:
            if p["first"] is None or ts < p["first"]:
                p["first"] = ts
            if p["last"] is None or ts > p["last"]:
                p["last"] = ts

    out = []
    for p in profile.values():
        out.append({
            "ip": p["ip"],
            "events": p["events"],
            "operations": p["operations"].most_common(8),
            "users": sorted(p["users"])[:5],
            "first_seen": p["first"].strftime("%Y-%m-%dT%H:%M:%SZ") if p["first"] else "",
            "last_seen": p["last"].strftime("%Y-%m-%dT%H:%M:%SZ") if p["last"] else "",
            "is_attacker": p["is_attacker"],
            # Filled in later by the GeoIP pass, when a database is supplied.
            "country": "", "asn": "", "org": "", "unexpected_country": False,
        })
    out.sort(key=lambda x: (not x["is_attacker"], -x["events"]))
    return out


def annotate_audit_geoip(audit_summary, resolver, expected_countries=()):
    """Geolocate audit client IPs and flag sessions outside the expected set.

    ``--geoip-db`` was already wired for message headers and never applied to
    the audit log, even though a mailbox operation from an unexpected country
    is among the clearest signals in the whole dataset -- and unlike a header,
    a ClientIP is recorded by the service rather than asserted by the sender.
    """
    if not audit_summary or not resolver or not resolver.available():
        return {"resolved": 0, "unexpected": 0}
    expected = {c.strip().upper() for c in (expected_countries or []) if c.strip()}
    resolved = unexpected = 0
    for entry in audit_summary.get("ip_activity") or []:
        info = resolver.lookup(entry["ip"])
        if not info.get("country") and not info.get("asn"):
            continue
        resolved += 1
        entry["country"] = info.get("country", "")
        entry["asn"] = info.get("asn", "")
        entry["org"] = info.get("org", "")
        if expected and entry["country"] and entry["country"].upper() not in expected:
            entry["unexpected_country"] = True
            unexpected += 1
    return {"resolved": resolved, "unexpected": unexpected}


def _coverage(events):
    """What this export can and cannot speak to.

    A finding drawn from an audit log is bounded by the log. If the export
    covers thirty days and the intrusion began sixty days ago, every conclusion
    downstream is wrong and nothing in the report would previously have said
    so -- the run would simply report the earliest attacker action it could
    see, which is an artifact of where the export begins.
    """
    stamped = [e["timestamp"] for e in events if e["timestamp"]]
    ops = Counter(e["operation"] for e in events if e["operation"])
    first = min(stamped) if stamped else None
    last = max(stamped) if stamped else None
    return {
        "first_event": first.strftime("%Y-%m-%dT%H:%M:%SZ") if first else "",
        "last_event": last.strftime("%Y-%m-%dT%H:%M:%SZ") if last else "",
        "span_days": (last - first).days if (first and last) else 0,
        "events_parsed": len(events),
        "events_without_timestamp": len(events) - len(stamped),
        "distinct_operations": len(ops),
        "operations": ops.most_common(),
        "mailboxes": len({e["user"] for e in events if e["user"]}),
        "client_ips": len({e["client_ip"] for e in events if e["client_ip"]}),
        "_first_dt": first,
        "_last_dt": last,
    }


def coverage_warnings(audit_summary, corpus_first=None, corpus_last=None,
                      lookback_days=None):
    """Where this log's answers stop being trustworthy.

    Returns a list of ``{"severity": "high"|"medium", "text": ...}``. Each one
    names a specific thing the export cannot support, rather than a general
    caution -- an investigator can act on "the log begins 41 days after the
    oldest message" and cannot act on "coverage may be incomplete".
    """
    if not audit_summary:
        return []
    cov = audit_summary.get("coverage") or {}
    first = cov.get("_first_dt")
    last = cov.get("_last_dt")
    out = []

    def add(sev, text):
        out.append({"severity": sev, "text": text})

    if not cov.get("events_parsed"):
        add("high", "No audit events were parsed from the export.")
        return out

    if not first:
        add("high",
            "No event in the export carries a parseable timestamp, so the log "
            "cannot bound anything in time and no compromise date can be "
            "derived from it.")
        return out

    missing = cov.get("events_without_timestamp") or 0
    if missing:
        add("medium",
            f"{missing} of {cov['events_parsed']} events carry no parseable "
            "timestamp and are absent from every time-bounded conclusion.")

    # The export beginning after the corpus does is the failure mode that
    # silently invalidates an entry-point finding.
    if corpus_first and corpus_first < first:
        gap = (first - corpus_first).days
        add("high",
            f"The corpus begins {gap} day(s) before the audit log does "
            f"(oldest message {corpus_first:%Y-%m-%d}, first log event "
            f"{first:%Y-%m-%d}). Attacker activity in that period would not "
            "appear here, so an absence of evidence before "
            f"{first:%Y-%m-%d} is not evidence of absence.")

    if corpus_last and last and corpus_last > last:
        gap = (corpus_last - last).days
        add("medium",
            f"The audit log ends {gap} day(s) before the corpus does "
            f"(last log event {last:%Y-%m-%d}, newest message "
            f"{corpus_last:%Y-%m-%d}). Attacker actions after "
            f"{last:%Y-%m-%d} are not covered.")

    # A compromise date sitting on the first day of the export is the single
    # most misleading output this tool can produce: it looks like a finding
    # and is indistinguishable from the export simply starting there.
    compromise = audit_summary.get("_compromise_dt")
    if compromise and first and (compromise - first).total_seconds() <= 86400:
        add("high",
            f"The earliest attacker action ({compromise:%Y-%m-%d %H:%M}) falls "
            f"within the first day of the export ({first:%Y-%m-%d}). The real "
            "compromise may predate the log entirely -- this date is a lower "
            "bound set by the export, not a finding. Re-export further back "
            "before treating it as the start of the intrusion.")

    if lookback_days and cov.get("span_days", 0) < lookback_days:
        add("medium",
            f"The entry-point search reaches back {lookback_days} days but the "
            f"log spans only {cov['span_days']}. The earlier part of that "
            "window rests on message content alone, with no audit log to "
            "confirm or contradict it.")

    return out


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
                "conditions": f["conditions"],
                "keeps_copy": f["keeps_copy"],
                "mailbox_level": f["mailbox_level"],
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

    # Any sign-in from an attacker IP is an attacker session -- and so is
    # every other operation from it. Stopping at UserLoggedIn meant an
    # attacker could create a rule, read a hundred messages and delete a dozen
    # from one address, and only the sign-in was ever attributed to them.
    attacker_logins = []
    attacker_operations = []
    for e in events:
        if not (e["client_ip"] and e["client_ip"] in attacker_ips):
            continue
        stamp = e["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ") if e["timestamp"] else ""
        entry = {"time": stamp, "ip": e["client_ip"], "user": e["user"],
                 "operation": e["operation"]}
        attacker_operations.append(entry)
        if e["op_lower"] in _LOGIN_OPS:
            attacker_logins.append({
                "time": stamp, "ip": e["client_ip"], "user": e["user"],
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
    # Built last: it needs the attacker IPs and the compromise date derived
    # above in order to say who did each thing, not merely that it happened.
    message_index = build_message_index(
        events, attacker_ips=attacker_ips, compromise_dt=compromise_dt)

    return {
        "events_parsed": len(events),
        # What the export can speak to. Every finding below is bounded by it.
        "coverage": _coverage(events),
        # message-id -> the audit events that touched that specific message.
        "message_index": message_index,
        "malicious_rules": malicious_rules,
        "forwarding_rules": forwarding,
        "attacker_logins": sorted(attacker_logins, key=lambda x: x["time"]),
        # Every operation attributable to a known attacker address, and the
        # per-IP profile the GeoIP pass annotates.
        "attacker_operations": sorted(attacker_operations, key=lambda x: x["time"]),
        "attacker_operation_counts": Counter(
            x["operation"] for x in attacker_operations).most_common(),
        "ip_activity": _ip_activity(events, attacker_ips),
        "deletions": deletions,
        "derived": derived,
        "_compromise_dt": compromise_dt,
    }
