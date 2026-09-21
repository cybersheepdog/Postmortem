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

from postmortem.utils import normalize_message_id, normalize_subject

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[0-9A-Fa-f:]{3,}:[0-9A-Fa-f:]+\b")

# Inbox-rule / forwarding operations that establish attacker persistence.
_RULE_OPS = {"new-inboxrule", "set-inboxrule", "updateinboxrules", "set-mailbox"}

# Cleanup. A rule that was created and then removed or disabled inside the
# window was used and tidied away -- stronger evidence than one still there,
# and invisible to a check that only reads the current configuration.
_RULE_CLEANUP_OPS = {"remove-inboxrule", "disable-inboxrule"}

# Rule names attackers actually use. Ten years of these and the name is the
# single most damning artefact more often than the action: a rule called "."
# or "," or " " is there to be overlooked in the Outlook rules dialog, and one
# named after the victim's own existing rule is there to be mistaken for it.
_THROWAWAY_RULE_NAMES = {".", "..", "...", ",", ";", ":", "-", "_", "*", "a",
                         "aa", "1", "11", "x", "xx", "z", "s", "rule", "new rule",
                         "test", "temp", "1111", "asdf", "qwe"}
_RULE_NAME_LEGIT_HINTS = ("junk", "spam", "newsletter", "archive", "cleanup",
                          "clean up", "move", "filter")
_LOGIN_OPS = {"userloggedin"}

# SharePoint and OneDrive. These carry no InternetMessageId, so they never
# reach the message index -- which is why an attacker who synced the victim's
# entire OneDrive was invisible to a tool that only walked the mail verbs. On
# a real 117k-message corpus: 803 FileDownloaded, 889 FileAccessed, 234
# FileSyncUploadedFull, none of them attributed.
_FILE_OPS = {
    "fileaccessed", "fileaccessedextended", "filepreviewed", "filedownloaded",
    "filesyncdownloadedfull", "filesyncdownloadedpartial", "fileuploaded",
    "filesyncuploadedfull", "filesyncuploadedpartial", "filemodified",
    "filemodifiedextended", "filecopied", "filemoved", "filedeleted",
    "filerecycled", "filerenamed", "sharingset", "sharinglinkcreated",
    "anonymouslinkcreated", "anonymouslinkused", "companylinkcreated",
    "secureLinkCreated".lower(), "addedtosecurelink",
}
# The subset that means data left the tenant's control.
_EXFIL_OPS = {"filedownloaded", "filesyncdownloadedfull",
              "filesyncdownloadedpartial"}
# The subset that means data was made reachable from outside.
_SHARE_OPS = {"sharingset", "sharinglinkcreated", "anonymouslinkcreated",
              "companylinkcreated", "securelinkcreated", "addedtosecurelink"}

# Turning the log off. The loudest thing an attacker can do, and until this
# was modelled the tool did not notice.
_AUDIT_DISABLE_OPS = {"set-mailboxauditbypassassociation"}
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
    ad = audit if isinstance(audit, dict) else {}

    # MailItemsAccessed carries its meaning in OperationProperties, not in
    # the operation name. MailAccessType=Sync means the client pulled the
    # whole folder, so every item in it is exposed rather than the ones
    # enumerated; IsThrottled=True means Exchange STOPPED RECORDING after a
    # thousand accesses in a day, and everything after it is invisible. A
    # count of read events that ignores both is not a scope, it is a floor
    # presented as a ceiling.
    props = {}
    for p in (ad.get("OperationProperties") or []):
        if isinstance(p, dict) and p.get("Name"):
            props[str(p["Name"]).lower()] = p.get("Value")
    access_type = str(props.get("mailaccesstype") or "").strip().lower()
    throttled = str(props.get("isthrottled") or "").strip().lower() in ("true", "1")
    folders = []
    for f in (ad.get("Folders") or []):
        if isinstance(f, dict) and f.get("Path"):
            folders.append(str(f["Path"]))

    logon = ad.get("LogonType")
    try:
        logon = int(logon) if logon not in (None, "") else None
    except (TypeError, ValueError):
        logon = None

    return {
        "timestamp": ts,
        "operation": str(op),
        "op_lower": str(op).lower(),
        "user": str(user or ""),
        "client_ip": ip or "",
        "audit": ad,
        # Ties every operation in one authenticated session together, even
        # when a residential proxy rotated the address between them.
        "session_id": str(ad.get("SessionId") or ""),
        "client_info": str(ad.get("ClientInfoString") or ad.get("ClientAppId")
                           or ad.get("UserAgent") or ""),
        # 0 owner, 1 admin, 2 delegate. A delegate logon by a principal that
        # holds no delegation is persistence being USED.
        "logon_type": logon,
        "mailbox_owner": str(ad.get("MailboxOwnerUPN") or ""),
        "access_type": access_type,
        "throttled": throttled,
        "folders": folders,
        # File workloads name the object rather than a message.
        "object_id": str(ad.get("ObjectId") or ""),
        "file_name": str(ad.get("SourceFileName") or ad.get("DestinationFileName")
                         or ""),
        "site_url": str(ad.get("SiteUrl") or ""),
        "workload": str(ad.get("Workload") or ""),
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
    rule_name = str(params.get("name") or params.get("identity") or "").strip()
    mark_read = str(params.get("markasread") or "").lower() in ("true", "1")
    stop_processing = str(params.get("stopprocessingrules") or "").lower() \
        in ("true", "1")

    # Why the NAME looks wrong, on its own. Reported as a separate list from
    # the action so a reader can see that a rule which merely moves mail to
    # Archive was called "." -- the action alone would not have flagged it.
    name_tells = []
    low = rule_name.lower()
    if rule_name and low in _THROWAWAY_RULE_NAMES:
        name_tells.append("throwaway name %r" % rule_name)
    elif rule_name and len(rule_name) <= 2 and not rule_name.isalnum():
        name_tells.append("punctuation-only name %r" % rule_name)
    elif rule_name and rule_name != rule_name.strip():
        name_tells.append("name padded with whitespace")
    elif rule_name and not rule_name.strip():
        name_tells.append("whitespace-only name")
    elif rule_name and len(rule_name) == 1:
        name_tells.append("single-character name %r" % rule_name)

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
    # MarkAsRead on its own is how an attacker's reply lands already read, so
    # the victim never notices a new message; StopProcessingRules put first
    # is how the victim's own filing rules are kept off the hijacked thread.
    # Either makes an otherwise-innocent rule worth a look; either plus a
    # throwaway name is not innocent.
    quiet = mark_read or stop_processing
    suspicious = bool(forwards or hides or keywords or name_tells
                      or (quiet and (move_to or keywords)))
    return {
        "forwards": forwards, "keywords": keywords, "move_to": move_to,
        "conditions": conditions,
        "delete": delete, "suspicious": suspicious, "keeps_copy": keeps_copy,
        "mailbox_level": bool(forwards) and event["op_lower"] == "set-mailbox",
        "name": rule_name,
        "name_tells": name_tells,
        "mark_as_read": mark_read,
        "stop_processing": stop_processing,
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


# Operations that mean this account SENT the message, as opposed to reading or
# filing one that carries the same subject. A known attacker subject only
# attributes an address when it appears on one of these.
_SEND_OPS = {"send", "sendas", "sendonbehalf"}


def attacker_ips_from_subjects(events, subjects, compromise_dt=None):
    """Addresses that SENT a message the investigator says was the attacker's.

    attacker_ips is otherwise seeded only from malicious rule operations, so
    an intruder who mass-mailed but never built a rule contributes nothing and
    every attribution downstream inherits that silence. A known subject on a
    Send/SendAs event is independent evidence of the same fact.

    Deliberately narrow. A subject is not proof on its own -- attackers reuse
    stolen thread subjects, and the genuine correspondence they were cloned
    from carries the identical string -- so a match only names an address when
    the operation is a send AND, where a compromise date is known, it happened
    after it.
    """
    wanted = {normalize_subject(s) for s in (subjects or ()) if str(s).strip()}
    if not wanted:
        return set(), []

    ips, matches = set(), []
    for e in events:
        if e["op_lower"] not in _SEND_OPS:
            continue
        ts = e["timestamp"]
        if compromise_dt and ts and ts < compromise_dt:
            continue
        found = []
        _walk_message_ids(e["audit"], found)
        for mid, subject, _folder in found:
            if normalize_subject(subject) not in wanted:
                continue
            row = {
                "time": ts.strftime("%Y-%m-%dT%H:%M:%SZ") if ts else "",
                "operation": e["operation"], "user": e["user"],
                "client_ip": e["client_ip"], "subject": subject,
                "message_id": mid,
            }
            matches.append(row)
            if e["client_ip"]:
                ips.add(e["client_ip"])
            break
    matches.sort(key=lambda r: r["time"])
    return ips, matches


def build_message_index(events, attacker_ips=(), compromise_dt=None,
                        known_delegates=()):
    """Map normalized Message-ID -> the audit events that touched that message.

    This is the join the tool was missing. Every other audit finding describes
    the mailbox; these describe a *specific message*, which is what lets the
    report say "hard-deleted by the attacker at 14:32 from 203.0.113.9" of a
    named item rather than inferring anything from its wording.
    """
    attacker_ips = set(attacker_ips or ())
    known = {str(d).lower() for d in (known_delegates or ()) if d}
    index = {}
    matched_events = 0

    for e in events:
        verb = _ITEM_OPS.get(e["op_lower"])
        if not verb:
            continue
        # A send by someone other than the mailbox owner. An executive
        # assistant with SendAs does this all day, and on a shared mailbox
        # so do five people. Whether the actor HOLDS that delegation is what
        # separates staff from an attacker using a permission they granted
        # themselves -- and only a send from an address that is not the
        # attacker's is excused by it.
        actor = str(e["user"] or "").lower()
        owner = str(e.get("mailbox_owner") or "").lower()
        delegate_send = bool(e["op_lower"] in ("sendas", "sendonbehalf")
                             and actor and owner and actor != owner)
        staff_send = bool(delegate_send and actor in known
                          and not (e["client_ip"] and e["client_ip"] in attacker_ips))
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
                "access_type": e.get("access_type", ""),
                "throttled": e.get("throttled", False),
                "session_id": e.get("session_id", ""),
                "client_info": e.get("client_info", "")[:80],
                "logon_type": e.get("logon_type"),
                "delegate_send": delegate_send,
                "staff_send": staff_send,
                "actor": actor,
            })

    for key in index:
        index[key].sort(key=lambda x: x["time"])
    return {
        "by_message_id": index,
        "messages_referenced": len(index),
        "events_with_message_id": matched_events,
    }



def access_profile(events, attacker_ips):
    """How the mailbox was read, not just how many times.

    Sync and Bind are different claims. A Bind is one message opened. A Sync
    is a folder pulled down whole -- every item in that folder is exposed,
    including the ones the event does not enumerate. And a throttled event
    is the log saying it gave up: after roughly a thousand accesses in
    twenty-four hours Exchange stops writing MailItemsAccessed at all, so
    every count from that point is a lower bound and the honest scope is
    "everything the session could reach".
    """
    attacker_ips = set(attacker_ips or ())
    out = {"available": False}
    reads = [e for e in events if e["op_lower"] == "mailitemsaccessed"]
    if not reads:
        return out

    def _bucket(subset):
        sync = [e for e in subset if e.get("access_type") == "sync"]
        bind = [e for e in subset if e.get("access_type") == "bind"]
        thr = [e for e in subset if e.get("throttled")]
        folders = Counter()
        for e in sync:
            for f in e.get("folders") or []:
                folders[f] += 1
        return {
            "events": len(subset),
            "sync": len(sync), "bind": len(bind),
            "untyped": len(subset) - len(sync) - len(bind),
            "throttled": len(thr),
            "throttled_first": min((e["timestamp"] for e in thr if e["timestamp"]),
                                   default=None),
            "synced_folders": folders.most_common(12),
        }

    all_ = _bucket(reads)
    atk = _bucket([e for e in reads if e["client_ip"] in attacker_ips])
    for b in (all_, atk):
        tf = b.pop("throttled_first")
        b["throttled_first"] = tf.strftime("%Y-%m-%dT%H:%M:%SZ") if tf else ""

    out.update({
        "available": True,
        "all": all_,
        "attacker": atk,
        "scope_is_lower_bound": bool(atk["throttled"]),
        "note": (
            "Throttling was recorded on %d attacker read event(s), the first "
            "at %s. Exchange stops logging MailItemsAccessed after about a "
            "thousand accesses in a day, so the count of messages read is a "
            "FLOOR: from that point the honest scope is every message the "
            "session could reach."
            % (atk["throttled"], atk["throttled_first"] or "?")
        ) if atk["throttled"] else (
            "%d of the attacker's read events were folder Syncs, exposing the "
            "whole of each folder named rather than the items enumerated."
            % atk["sync"] if atk["sync"] else ""),
    })
    return out


def file_activity(events, attacker_ips, compromise_dt=None, limit=60):
    """SharePoint and OneDrive operations from attacker addresses.

    The mail verbs answer "what did they read". These answer "what did they
    TAKE" -- a FileSyncDownloadedFull from an attacker address is the entire
    drive leaving in one event, and until this existed the tool did not see
    it because a file has no InternetMessageId to index on.
    """
    attacker_ips = set(attacker_ips or ())
    rows = [e for e in events if e["op_lower"] in _FILE_OPS]
    if not rows:
        return {"available": False}

    mine = [e for e in rows if e["client_ip"] and e["client_ip"] in attacker_ips]
    exfil = [e for e in mine if e["op_lower"] in _EXFIL_OPS]
    shared = [e for e in mine if e["op_lower"] in _SHARE_OPS]

    def _row(e):
        return {
            "time": e["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ") if e["timestamp"] else "",
            "operation": e["operation"],
            "file": e.get("file_name") or e.get("object_id", "").rsplit("/", 1)[-1],
            "path": e.get("object_id", ""),
            "site": e.get("site_url", ""),
            "workload": e.get("workload", ""),
            "client_ip": e["client_ip"],
            "user": e["user"],
        }

    exfil_rows = sorted((_row(e) for e in exfil), key=lambda r: r["time"])
    share_rows = sorted((_row(e) for e in shared), key=lambda r: r["time"])
    ops = Counter(e["operation"] for e in mine)
    files = {r["path"] for r in exfil_rows if r["path"]}

    return {
        "available": True,
        "total_file_events": len(rows),
        "attacker_file_events": len(mine),
        "operations": ops.most_common(10),
        "exfil_count": len(exfil),
        "exfil_distinct_files": len(files),
        "exfil": exfil_rows[:limit],
        "shared_count": len(shared),
        "shared": share_rows[:limit],
        "full_sync": sum(1 for e in exfil
                         if e["op_lower"] == "filesyncdownloadedfull"),
    }


def delegate_access(events, known_delegates=(), attacker_ips=()):
    """Mail operations performed as a DELEGATE by a principal that holds none.

    LogonType 2 is someone acting on the mailbox under delegated rights.
    Staff with FullAccess do this all day, so the list of who legitimately
    holds delegation (Get-MailboxPermissions) is what separates an assistant
    from an attacker using a permission they granted themselves.
    """
    known = {str(d).lower() for d in (known_delegates or ()) if d}
    attacker_ips = set(attacker_ips or ())
    by_principal = {}
    for e in events:
        if e.get("logon_type") != 2:
            continue
        actor = str(e["user"] or "").lower()
        owner = str(e.get("mailbox_owner") or "").lower()
        if not actor or actor == owner:
            continue
        p = by_principal.setdefault(actor, {
            "principal": actor, "mailboxes": set(), "events": 0,
            "operations": Counter(), "ips": set(), "first": None, "last": None,
            "known_delegate": actor in known,
            "from_attacker_ip": False,
        })
        p["events"] += 1
        p["operations"][e["operation"]] += 1
        if owner:
            p["mailboxes"].add(owner)
        if e["client_ip"]:
            p["ips"].add(e["client_ip"])
            if e["client_ip"] in attacker_ips:
                p["from_attacker_ip"] = True
        ts = e["timestamp"]
        if ts:
            p["first"] = ts if p["first"] is None or ts < p["first"] else p["first"]
            p["last"] = ts if p["last"] is None or ts > p["last"] else p["last"]

    out = []
    for p in by_principal.values():
        out.append({
            "principal": p["principal"],
            "mailboxes": sorted(p["mailboxes"])[:5],
            "events": p["events"],
            "operations": p["operations"].most_common(6),
            "ips": sorted(p["ips"])[:6],
            "first": p["first"].strftime("%Y-%m-%dT%H:%M:%SZ") if p["first"] else "",
            "last": p["last"].strftime("%Y-%m-%dT%H:%M:%SZ") if p["last"] else "",
            "known_delegate": p["known_delegate"],
            "from_attacker_ip": p["from_attacker_ip"],
        })
    out.sort(key=lambda r: (r["known_delegate"] and not r["from_attacker_ip"],
                            -r["events"]))
    return {
        "available": bool(out),
        "delegates_known": bool(known),
        "principals": out,
        "unknown_count": sum(1 for r in out if not r["known_delegate"]),
    }


# --------------------------------------------------------------------------
# What the attacker searched for
#
# SearchQueryInitiated (Exchange, E5) records the text a user typed into the
# mailbox search box. From an attacker address it is intent, verbatim: no
# other artefact says what they were LOOKING FOR rather than what they
# happened to open. "wire", "W-2", "routing number", "invoice", the CFO's
# name -- the search history is the attacker's own statement of purpose.
# --------------------------------------------------------------------------
_SEARCH_OPS = {"searchqueryinitiated", "searchqueryinitiatedexchange",
               "searchqueryinitiatedsharepoint"}

# Terms that, searched for, say the purpose was money or identity theft.
# Not scored -- a search is reported whatever it says -- but these decide
# which searches lead the list.
_SEARCH_INTENT = (
    "wire", "swift", "iban", "routing", "aba", "ach", "remit", "remittance",
    "invoice", "payment", "bank", "account number", "w-2", "w2", "1099",
    "payroll", "direct deposit", "ssn", "social security", "passport",
    "password", "credential", "vpn", "mfa", "authenticator", "cfo", "ceo",
    "controller", "treasurer", "wire instructions", "beneficiary",
)


def search_queries(events, attacker_ips, compromise_dt=None, limit=60):
    """Mailbox searches, attacker ones first, intent-bearing ones on top."""
    attacker_ips = set(attacker_ips or ())
    rows = []
    for e in events:
        if e["op_lower"] not in _SEARCH_OPS:
            continue
        ad = e["audit"]
        text = str(ad.get("QueryText") or ad.get("SearchQuery")
                   or ad.get("Query") or "").strip()
        if not text:
            # Some exports bury it in OperationProperties.
            for prop in (ad.get("OperationProperties") or []):
                if isinstance(prop, dict) and str(prop.get("Name", "")).lower() \
                        in ("querytext", "searchquery", "query"):
                    text = str(prop.get("Value") or "").strip()
                    break
        if not text:
            continue
        low = text.lower()
        intent = [w for w in _SEARCH_INTENT if w in low]
        ts = e["timestamp"]
        rows.append({
            "time": ts.strftime("%Y-%m-%dT%H:%M:%SZ") if ts else "",
            "user": e["user"], "client_ip": e["client_ip"],
            "session_id": e.get("session_id", ""),
            "query": text[:160],
            "intent": intent,
            "by_attacker": bool(e["client_ip"] and e["client_ip"] in attacker_ips),
            "post_compromise": bool(ts and compromise_dt and ts >= compromise_dt),
            "workload": e.get("workload", ""),
        })
    rows.sort(key=lambda r: (not r["by_attacker"], not bool(r["intent"]),
                             not r["post_compromise"], r["time"]))
    atk = [r for r in rows if r["by_attacker"]]
    return {
        "available": bool(rows),
        "total": len(rows),
        "attacker_searches": len(atk),
        "attacker_intent": sum(1 for r in atk if r["intent"]),
        "terms": Counter(w for r in atk for w in r["intent"]).most_common(10),
        "searches": rows[:limit],
    }


def session_ips(events, attacker_ips, owner_ips=()):
    """Every address that shares an authenticated session with an attacker one.

    Exchange stamps each operation with the SessionId of the logon it ran
    under. A residential-proxy attacker rotates addresses mid-session; keyed
    on IP, the same session fragments into one attributed piece and several
    unattributed ones. Keyed on session, an address seen in a session that
    also contains a known attacker address is the attacker's -- it is the
    same logon.

    Owner addresses are never pulled in this way: if the owner's own machine
    somehow shares a SessionId with an attacker address, that is a finding to
    show, not a reason to relabel the owner.
    """
    attacker_ips = set(attacker_ips or ())
    owner = set(owner_ips or ())
    by_session = {}
    for e in events:
        sid = e.get("session_id")
        if sid and e["client_ip"]:
            by_session.setdefault(sid, set()).add(e["client_ip"])
    found = set()
    for sid, ips in by_session.items():
        if ips & attacker_ips:
            found |= ips
    return (found - attacker_ips) - owner


def session_activity(events, attacker_ips, compromise_dt=None, limit=40):
    """The investigation as an analyst reads it: one row per logon session.

    Five hundred flat audit rows say nothing; "session 3, 14:02-14:47, from
    45.x, read 130, deleted 29, created a rule" says everything. Sessions
    are the unit an intruder actually works in, and the unit a client can
    follow.
    """
    attacker_ips = set(attacker_ips or ())
    groups = {}
    unsessioned = 0
    for e in events:
        sid = e.get("session_id")
        if not sid:
            unsessioned += 1
            continue
        g = groups.setdefault(sid, {
            "session_id": sid, "user": e["user"], "ips": set(), "events": 0,
            "operations": Counter(), "first": None, "last": None,
            "reads": 0, "sync_reads": 0, "throttled": 0, "deletes": 0,
            "sends": 0, "rules": 0, "files": 0, "folders": Counter(),
            "client_info": Counter(),
        })
        g["events"] += 1
        g["operations"][e["operation"]] += 1
        if e["client_ip"]:
            g["ips"].add(e["client_ip"])
        ts = e["timestamp"]
        if ts:
            g["first"] = ts if g["first"] is None or ts < g["first"] else g["first"]
            g["last"] = ts if g["last"] is None or ts > g["last"] else g["last"]
        op = e["op_lower"]
        if op == "mailitemsaccessed":
            g["reads"] += 1
            if e.get("access_type") == "sync":
                g["sync_reads"] += 1
            if e.get("throttled"):
                g["throttled"] += 1
            for f in e.get("folders") or []:
                g["folders"][f] += 1
        elif op in ("harddelete", "softdelete", "movetodeleteditems"):
            g["deletes"] += 1
        elif op in ("send", "sendas", "sendonbehalf"):
            g["sends"] += 1
        elif op in _RULE_OPS:
            g["rules"] += 1
        elif op in _FILE_OPS:
            g["files"] += 1
        if e.get("client_info"):
            g["client_info"][e["client_info"][:60]] += 1

    rows = []
    for g in groups.values():
        atk = bool(g["ips"] & attacker_ips)
        post = bool(g["first"] and compromise_dt and g["first"] >= compromise_dt)
        rows.append({
            "session_id": g["session_id"],
            "user": g["user"],
            "ips": sorted(g["ips"]),
            "rotated": len(g["ips"]) > 1,
            "is_attacker": atk,
            "post_compromise": post,
            "first": g["first"].strftime("%Y-%m-%dT%H:%M:%SZ") if g["first"] else "",
            "last": g["last"].strftime("%Y-%m-%dT%H:%M:%SZ") if g["last"] else "",
            "minutes": int((g["last"] - g["first"]).total_seconds() // 60)
                       if (g["first"] and g["last"]) else 0,
            "events": g["events"],
            "reads": g["reads"], "sync_reads": g["sync_reads"],
            "throttled": g["throttled"], "deletes": g["deletes"],
            "sends": g["sends"], "rules": g["rules"], "files": g["files"],
            "top_operations": g["operations"].most_common(5),
            "folders": g["folders"].most_common(4),
            "client": (g["client_info"].most_common(1) or [("", 0)])[0][0],
        })
    # Attacker sessions first, then anything post-compromise, then by start.
    rows.sort(key=lambda r: (not r["is_attacker"], not r["post_compromise"],
                             r["first"]))
    attacker_rows = [r for r in rows if r["is_attacker"]]
    return {
        "available": bool(groups),
        "sessions_total": len(groups),
        "unsessioned_events": unsessioned,
        "attacker_sessions": len(attacker_rows),
        "rotated_sessions": sum(1 for r in attacker_rows if r["rotated"]),
        "sessions": rows[:limit],
        "attacker": attacker_rows[:limit],
    }


# --------------------------------------------------------------------------
# What kind of client did the reading
#
# ClientInfoString says how the mailbox was reached. Most of its values are a
# person -- Outlook, OWA, a phone. Two are not: Exchange's own background
# processes (RESTSystem, Substrate) and applications reaching the mailbox
# through Graph or EWS on their own credentials -- an archiver, a ticketing
# system, a journaling connector -- which read every message and never sign
# in. Those look exactly like an attacker replaying a token, and until this
# existed the token-replay test flagged them.
#
# This classifies; it does not clear. An application reading through Graph
# is ALSO what an attacker's consent-granted app looks like, so a REST client
# is reported with its app id for the analyst to check against the OAuth
# grants, not excused. Only the service's own background classes are excused
# from replay, and nothing here ever removes an address the rules named.
# --------------------------------------------------------------------------
_CLIENT_CLASSES = (
    # (class, is_person, substrings matched against the lowercased string)
    ("system", False, ("client=restsystem", "restsystem", "client=substrate",
                       "substrate", "client=exchange;", "mailboxassistant",
                       "client=ms-exchange-", "microsoft.exchange.")),
    ("powershell", True, ("powershell", "remoteps", "client=exo",
                          "exchange online powershell")),
    ("ews", True, ("client=webservices", "exchangewebservices", "ews/")),
    ("activesync", True, ("client=activesync", "activesync", "outlook-ios",
                          "outlook-android", "client=outlookservice")),
    ("mobile", True, ("outlook mobile", "client=outlook mobile", "iphone",
                      "android", "ipad")),
    ("owa", True, ("client=owa", "action=viaproxy")),
    ("desktop", True, ("client=msexchangerpc", "msexchangerpc", "client=hx",
                       "mapi", "client=outlookdesktop")),
    ("rest", True, ("client=rest", "graph")),
)


def classify_client(client_info):
    """One of system|powershell|ews|activesync|mobile|owa|desktop|rest|other."""
    s = str(client_info or "").lower()
    if not s:
        return "unknown"
    for cls, _person, needles in _CLIENT_CLASSES:
        if any(n in s for n in needles):
            return cls
    return "other"


def client_profile(events, attacker_ips):
    """Per address: which client classes it used, and whether any is a person.

    An address whose every operation came from a background class is not a
    session anyone sat at. That is what separates a journaling connector
    reading 10,000 messages from an intruder reading 10,000 messages.
    """
    attacker_ips = set(attacker_ips or ())
    prof = {}
    for e in events:
        ip = e["client_ip"]
        if not ip:
            continue
        cls = classify_client(e.get("client_info"))
        p = prof.setdefault(ip, {"ip": ip, "classes": Counter(), "events": 0,
                                 "app_ids": Counter(), "strings": Counter()})
        p["events"] += 1
        p["classes"][cls] += 1
        ad = e.get("audit") or {}
        app = str(ad.get("AppId") or ad.get("ClientAppId") or "").strip()
        if app and cls in ("rest", "ews", "other"):
            p["app_ids"][app] += 1
        if e.get("client_info"):
            p["strings"][str(e["client_info"])[:70]] += 1

    out = []
    for p in prof.values():
        classes = dict(p["classes"])
        person = any(cls not in ("system", "unknown") for cls in classes)
        only_system = bool(classes) and all(cls in ("system", "unknown")
                                            for cls in classes) \
            and classes.get("system", 0) > 0
        out.append({
            "ip": p["ip"], "events": p["events"],
            "classes": p["classes"].most_common(),
            "person_client": person,
            "system_only": only_system,
            "app_ids": p["app_ids"].most_common(3),
            "top_client": (p["strings"].most_common(1) or [("", 0)])[0][0],
            "is_attacker": p["ip"] in attacker_ips,
        })
    out.sort(key=lambda r: (not r["is_attacker"], -r["events"]))
    return {
        "available": any(r["classes"] for r in out),
        "addresses": out[:60],
        "system_only_ips": sorted(r["ip"] for r in out if r["system_only"]),
        "app_access_ips": sorted(r["ip"] for r in out
                                 if any(c in ("rest", "ews") for c, _n in r["classes"])),
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


def annotate_audit_geoip(audit_summary, resolver, expected_countries=(),
                         user_countries=None):
    """Geolocate audit client IPs and flag sessions outside the expected set.

    ``--geoip-db`` was already wired for message headers and never applied to
    the audit log, even though a mailbox operation from an unexpected country
    is among the clearest signals in the whole dataset -- and unlike a header,
    a ClientIP is recorded by the service rather than asserted by the sender.
    """
    if not audit_summary or not resolver or not resolver.available():
        return {"resolved": 0, "unexpected": 0}
    expected = {c.strip().upper() for c in (expected_countries or []) if c.strip()}
    # Per-user history from the sign-in log, keyed by lowercased UPN. A
    # global expected set says where the ORGANISATION is; this says where
    # THIS person is, which is the question a split-tunnel VPN or a remote
    # worker keeps answering differently. Used first; the global set is the
    # fallback for an address whose users have no history.
    per_user = {str(u).lower(): {str(c).upper(): n for c, n in v.items()
                                 if not str(c).startswith("_")}
                for u, v in (user_countries or {}).items()}
    resolved = unexpected = 0
    by_user_baseline = 0
    for entry in audit_summary.get("ip_activity") or []:
        info = resolver.lookup(entry["ip"])
        if not info.get("country") and not info.get("asn"):
            continue
        resolved += 1
        entry["country"] = info.get("country", "")
        entry["asn"] = info.get("asn", "")
        entry["org"] = info.get("org", "")
        country = entry["country"].upper() if entry["country"] else ""
        if not country:
            continue
        users = [str(u).lower() for u in (entry.get("users") or []) if u]
        histories = [per_user[u] for u in users if u in per_user]
        if histories:
            # Unexpected only if NONE of the users on this address has ever
            # signed in from this country. One user's history is enough to
            # explain the address for everyone sharing it.
            known = any(country in h for h in histories)
            entry["baseline"] = "user"
            by_user_baseline += 1
            if not known:
                entry["unexpected_country"] = True
                unexpected += 1
        elif expected and country not in expected:
            entry["baseline"] = "global"
            entry["unexpected_country"] = True
            unexpected += 1
        elif expected:
            entry["baseline"] = "global"
    return {"resolved": resolved, "unexpected": unexpected,
            "by_user_baseline": by_user_baseline}


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


def rule_cleanup(events, attacker_ips, current_rules=None):
    """Rules that were removed or disabled -- and rules that no longer exist.

    Two things, both invisible to a check of the current configuration:

    A Remove-InboxRule or Disable-InboxRule inside the window is the attacker
    tidying up after use. It carries the rule's name, so it can be matched
    back to the New-InboxRule that created it.

    A New-InboxRule whose name is absent from Get-MailboxRules was created
    AND removed, whether or not the removal was logged. That is stronger
    evidence than a rule still present: nobody removes a rule they want.
    """
    attacker_ips = set(attacker_ips or ())
    created, removed = {}, []
    for e in events:
        op = e["op_lower"]
        params = _params_to_dict(e["audit"])
        name = str(params.get("name") or params.get("identity") or "").strip()
        if op == "new-inboxrule" and name:
            created.setdefault(name.lower(), []).append({
                "name": name,
                "time": e["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ")
                if e["timestamp"] else "",
                "client_ip": e["client_ip"], "user": e["user"],
                "by_attacker": e["client_ip"] in attacker_ips,
            })
        elif op in _RULE_CLEANUP_OPS:
            removed.append({
                "name": name or "(unnamed)",
                "operation": e["operation"],
                "time": e["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ")
                if e["timestamp"] else "",
                "client_ip": e["client_ip"], "user": e["user"],
                "by_attacker": e["client_ip"] in attacker_ips,
                "created_earlier": name.lower() in created if name else False,
            })

    # Created in the log, absent from the configuration export now.
    gone = []
    if current_rules is not None:
        present = {str(r.get("name") or "").strip().lower()
                   for r in current_rules if r.get("name")}
        for key, evs in created.items():
            if key and key not in present:
                first = evs[0]
                gone.append({**first, "creations": len(evs),
                             "removal_logged": any(
                                 r["name"].lower() == key for r in removed)})

    gone.sort(key=lambda r: (not r["by_attacker"], r["time"]))
    removed.sort(key=lambda r: (not r["by_attacker"], r["time"]))
    return {
        "available": bool(created or removed),
        "config_checked": current_rules is not None,
        "removed": removed,
        "removed_by_attacker": sum(1 for r in removed if r["by_attacker"]),
        "created_then_gone": gone,
        "gone_by_attacker": sum(1 for r in gone if r["by_attacker"]),
    }


def analyze_audit_log(path, extra_attacker_ips=(), anchor_dt=None,
                      attacker_subjects=(), containment_dt=None,
                      known_delegates=(), owner_ips=(), current_rules=None):
    """Parse a UAL export and derive anchors + confirmed attacker events.

    Returns a summary dict with `derived` anchors and human-readable findings,
    or raises on an unreadable file.

    `extra_attacker_ips` and `anchor_dt` let another source contribute to
    the two facts everything downstream depends on. They are parameters
    rather than a later patch because the message index, the IP profile and
    the operation attribution are all built from those two values inside
    this function; merging afterwards would leave each of them stale.

    Both default to empty, so every existing caller behaves exactly as
    before.
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

    # Everything after containment is, by default, the client's response:
    # the admin creating a quarantine rule, forcing a forward to a review
    # mailbox, resetting things. Without a closing anchor all of it was
    # attributed to the attacker whenever it came from an address the
    # attacker had also touched -- a shared VPN egress or a jump host is
    # enough -- and the report then told the client their own IR was the
    # intrusion.
    response_events = 0
    if containment_dt:
        for e in events:
            e["after_containment"] = bool(e["timestamp"]
                                          and e["timestamp"] >= containment_dt)
            if e["after_containment"]:
                response_events += 1
    else:
        for e in events:
            e["after_containment"] = False

    # Outlook desktop re-publishes the WHOLE rule set as UpdateInboxRules
    # whenever the user opens the Rules dialog or the client resyncs. That is
    # the client restating what already exists, not a person creating a
    # rule -- and it happens from the owner's own machine, so it seeded the
    # owner's address as the attacker's whenever any existing rule looked
    # suspicious. An UpdateInboxRules whose suspicious content matches a rule
    # this log has already recorded is a re-publish: reported, never seeding.
    # One whose content is NEW is a creation in disguise and is treated as
    # one. Events are walked in time order so "already recorded" means
    # earlier, not merely elsewhere.
    def _fingerprint(f):
        return (tuple(sorted(f["forwards"])), (f["move_to"] or "").lower(),
                bool(f["delete"]), tuple(sorted(w.lower() for w in f["keywords"])))
    seen_fingerprints = set()
    republished = []

    for e in sorted(events, key=lambda x: (x["timestamp"] is None, x["timestamp"])):
        if e["op_lower"] in _RULE_OPS:
            if e.get("after_containment"):
                continue
            f = _rule_findings(e)
            if not f["suspicious"]:
                continue
            fp = _fingerprint(f)
            if e["op_lower"] == "updateinboxrules":
                if fp in seen_fingerprints:
                    republished.append({
                        "time": e["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ")
                        if e["timestamp"] else "",
                        "user": e["user"], "client_ip": e["client_ip"],
                        "client": classify_client(e.get("client_info")),
                        "name": f["name"],
                    })
                    continue
            seen_fingerprints.add(fp)
            entry = {
                "time": e["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ") if e["timestamp"] else "",
                "operation": e["operation"], "user": e["user"], "client_ip": e["client_ip"],
                "forwards": f["forwards"], "move_to": f["move_to"],
                "delete": f["delete"], "keywords": f["keywords"],
                "conditions": f["conditions"],
                "keeps_copy": f["keeps_copy"],
                "mailbox_level": f["mailbox_level"],
                "name": f["name"],
                "name_tells": f["name_tells"],
                "mark_as_read": f["mark_as_read"],
                "stop_processing": f["stop_processing"],
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

    # Addresses another source established as the attacker's -- today the
    # Entra sign-in log, where a device code group with the victim in one
    # country and the polling client in another names an address without
    # needing a rule to have been created. Seeded here, before anything
    # below reads the set, so attribution is computed once from the union.
    #
    # This matters more than it looks: without it the attacker set is
    # populated only by malicious rule events, so an intruder who read and
    # exfiltrated but never made a rule leaves it empty -- and every
    # attribution downstream silently reports nothing.
    for _extra in (extra_attacker_ips or ()):
        if _extra:
            attacker_ips.add(str(_extra))

    # Addresses the mailbox owner demonstrably signs in from interactively,
    # per the sign-in log. A rule event from one of these is still a rule
    # event and is still reported -- but it does not seed attribution, or
    # the owner's own laptop labels their whole history as the intruder's.
    # Same principle as the sign-in module's veto, applied to the audit side.
    _owner = {str(i) for i in (owner_ips or ()) if i}
    owner_vetoed = sorted(attacker_ips & _owner)
    attacker_ips -= _owner

    # Fourth route to an attacker address, and the one that defeats address
    # rotation: any other address in a session that already contains an
    # attacker one. Seeded here so the message index, exposure scope and
    # per-address activity below all read the widened set once.
    from_session = session_ips(events, attacker_ips, _owner)
    attacker_ips |= from_session

    # Addresses that sent a message the investigator named as the attacker's.
    # Seeded here for the same reason as the block above: everything below
    # reads the set once, so a late addition would be invisible to it.
    subject_ips, subject_sends = attacker_ips_from_subjects(
        events, attacker_subjects, anchor_dt)
    attacker_ips |= subject_ips

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
    # An externally supplied anchor only ever moves the compromise EARLIER.
    # Token issuance precedes the first action taken with that token, so
    # the sign-in log's T0 is the truer one; taking the minimum also means
    # a later or bogus anchor can never shrink the investigated window.
    if anchor_dt is not None:
        compromise_dt = (anchor_dt if compromise_dt is None
                         else min(compromise_dt, anchor_dt))
    derived = {
        "compromise_date": compromise_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if compromise_dt else "",
        "attacker_ips": sorted(attacker_ips),
        "attacker_addresses": sorted(attacker_addresses),
        "attacker_domains": sorted(attacker_domains),
        "rule_keywords": sorted(rule_keywords),
        # Kept separate from attacker_ips so a reader can tell which addresses
        # the subject established and which the rules did. Two independent
        # derivations of the same fact are worth more than one merged list.
        "attacker_ips_from_subject": sorted(subject_ips),
        "attacker_ips_from_session": sorted(from_session),
        "attacker_sends": subject_sends,
        "attacker_send_count": len(subject_sends),
    }
    # Built last: it needs the attacker IPs and the compromise date derived
    # above in order to say who did each thing, not merely that it happened.
    message_index = build_message_index(
        events, attacker_ips=attacker_ips, compromise_dt=compromise_dt,
        known_delegates=known_delegates)

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
        "client_profile": client_profile(events, attacker_ips),
        "sessions": session_activity(events, attacker_ips, compromise_dt),
        "rule_cleanup": rule_cleanup(events, attacker_ips, current_rules),
        "access_profile": access_profile(events, attacker_ips),
        "file_activity": file_activity(events, attacker_ips, compromise_dt),
        "delegate_access": delegate_access(events, known_delegates,
                                           attacker_ips),
        "containment_date": (containment_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                             if containment_dt else ""),
        "response_events": response_events,
        "owner_vetoed_ips": owner_vetoed,
        "searches": search_queries(events, attacker_ips, compromise_dt),
        "republished_rules": republished,
        "republished_count": len(republished),
        "audit_disabled_events": [
            {"time": e["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ")
             if e["timestamp"] else "",
             "operation": e["operation"], "user": e["user"],
             "client_ip": e["client_ip"],
             "by_attacker": e["client_ip"] in attacker_ips}
            for e in events
            if e["op_lower"] in _AUDIT_DISABLE_OPS
            or (e["op_lower"] == "set-mailbox"
                and "auditenabled" in json.dumps(e["audit"]).lower()
                and "false" in json.dumps(
                    _params_to_dict(e["audit"]).get("auditenabled", "")).lower())
        ],
        "deletions": deletions,
        "derived": derived,
        "_compromise_dt": compromise_dt,
    }
