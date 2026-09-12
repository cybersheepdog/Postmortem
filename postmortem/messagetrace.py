"""Exchange message trace: what left the mailbox that is not in the export.

Every other source here describes messages that are present. The corpus is a
PST, and a PST holds what survived -- an attacker who sent from the account
and then emptied Sent Items leaves a mailbox that looks untouched. The
outbound half of a BEC is routinely the half that was destroyed.

Message trace is retained by the service for 90 days regardless of what
happened to the mailbox copy, so it answers the question the corpus
structurally cannot: who did the attacker write to, as the client, and what
did they say in the subject line. That is the notification list, and it is
usually the most consequential page in the report -- a third party who acted
on a fraudulent instruction is a loss the client will hear about either way.

Three things come out of here:

  third-party recipients   Who received mail from the compromised account
                           during the attacker's window. Grouped by domain,
                           because a list of four hundred addresses is not
                           something anyone reads.

  proven evidence gaps     A trace row whose InternetMessageId has no
                           matching .eml is a message that existed and is
                           gone. E5 infers gaps from deletion events; this
                           observes them directly.

  attacker attribution     Trace carries the submitting IP for outbound mail
                           on many tenants. Where it matches an address the
                           sign-in or audit log already established, the send
                           is confirmed rather than inferred.

Nothing here scores a message. It describes messages the scorer never saw.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from postmortem.persistence import _get, _parse_dt

SCHEMA = "postmortem-messagetrace/1"

# Statuses that mean the message actually reached somebody. A failed or
# quarantined send is still evidence of intent, but it is not exposure, and
# conflating the two would overstate the notification list.
_DELIVERED = {"delivered", "resolved", "expanded"}
_BLOCKED = {"failed", "quarantined", "filteredasspam", "filtered as spam",
            "spam", "blocked"}


def _addr(value):
    return str(value or "").strip().lower()


def _domain(address):
    a = _addr(address)
    return a.rsplit("@", 1)[1] if "@" in a else ""


def parse_trace(rows):
    """Normalise trace rows, whatever the export spelled its columns."""
    out = []
    for row in rows:
        sender = _addr(_get(row, "senderaddress", "sender", "from",
                            "fromaddress", "p1sender"))
        recipient = _addr(_get(row, "recipientaddress", "recipient", "to",
                               "toaddress"))
        if not (sender or recipient):
            continue
        when = _parse_dt(_get(row, "received", "date", "datetime", "timestamp",
                              "starttime", "receivedtime"))
        status = str(_get(row, "status", "deliverystatus", "detail",
                          default="")).strip()
        mid = str(_get(row, "messageid", "internetmessageid",
                       "message_id", default="")).strip()
        out.append({
            "time": when.strftime("%Y-%m-%dT%H:%M:%SZ") if when else "",
            "_dt": when,
            "sender": sender,
            "recipient": recipient,
            "recipient_domain": _domain(recipient),
            "subject": str(_get(row, "subject", default=""))[:200],
            "status": status,
            "status_key": status.lower().replace("-", "").replace(" ", ""),
            "message_id": mid,
            "from_ip": str(_get(row, "fromip", "originalclientip", "clientip",
                                default="")).strip(),
            "size": str(_get(row, "size", default="")),
        })
    return out


def _norm_mid(value):
    v = str(value or "").strip()
    if v.startswith("<") and v.endswith(">"):
        v = v[1:-1]
    return v.lower()


def analyze_message_trace(rows, records=None, victim_addresses=(),
                          attacker_ips=(), compromise_dt=None,
                          internal_domains=()):
    """What the account sent, to whom, and which of it is missing from the corpus.

    `victim_addresses` scopes "outbound": without it the trace's own sender
    column is used, which on a tenant-wide export would describe the whole
    organisation rather than the compromised account.
    """
    rows = list(rows or [])
    if not rows:
        return {"available": False, "reason": "No message trace rows were read."}

    victims = {_addr(v) for v in (victim_addresses or ()) if v}
    attacker_ips = {str(i) for i in (attacker_ips or ()) if i}
    internal = {str(d).lower() for d in (internal_domains or ()) if d}

    # Message ids present in the corpus, to tell destroyed from merely absent.
    in_corpus = set()
    for r in (records or []):
        mid = _norm_mid(getattr(r, "message_id", ""))
        if mid:
            in_corpus.add(mid)

    outbound = [t for t in rows if not victims or t["sender"] in victims]
    # Fall back to the dominant sender when no victim address was supplied:
    # a single-mailbox trace export is the common case and should still work.
    if not victims and outbound:
        dominant = Counter(t["sender"] for t in outbound if t["sender"])
        if dominant:
            top, n = dominant.most_common(1)[0]
            if n >= max(3, 0.5 * len(outbound)):
                victims = {top}
                outbound = [t for t in rows if t["sender"] == top]

    in_window = []
    for t in outbound:
        if compromise_dt is None or (t["_dt"] and t["_dt"] >= compromise_dt):
            in_window.append(t)

    attacker_sent, unattributed = [], []
    for t in in_window:
        if t["from_ip"] and t["from_ip"] in attacker_ips:
            attacker_sent.append(t)
        else:
            unattributed.append(t)

    delivered = [t for t in in_window if t["status_key"] in _DELIVERED]
    blocked = [t for t in in_window if t["status_key"] in _BLOCKED]

    # Recipients grouped by domain: a flat list of every address is the
    # doom-scroll this report has been fighting since the campaign list.
    by_domain = defaultdict(lambda: {"recipients": set(), "messages": 0,
                                     "delivered": 0, "subjects": Counter()})
    for t in delivered:
        if not t["recipient"]:
            continue
        g = by_domain[t["recipient_domain"] or "(no domain)"]
        g["recipients"].add(t["recipient"])
        g["messages"] += 1
        g["delivered"] += 1
        if t["subject"]:
            g["subjects"][t["subject"]] += 1

    recipients = []
    for dom, g in by_domain.items():
        recipients.append({
            "domain": dom,
            "external": bool(dom and dom not in internal),
            "recipients": sorted(g["recipients"])[:40],
            "recipient_count": len(g["recipients"]),
            "messages": g["messages"],
            "top_subjects": g["subjects"].most_common(3),
        })
    recipients.sort(key=lambda x: (not x["external"], -x["messages"]))

    # A trace row with no matching .eml is a message that existed and is gone.
    absent = []
    traced_with_id = 0
    for t in in_window:
        mid = _norm_mid(t["message_id"])
        if not mid:
            continue
        traced_with_id += 1
        if mid not in in_corpus:
            absent.append({k: v for k, v in t.items() if not k.startswith("_")})
    absent.sort(key=lambda e: e.get("time") or "")
    # A failed or quarantined send is still a message that existed and is not
    # here, and it is still evidence of intent -- but it reached nobody, and
    # describing it as delivered would overstate the exposure.
    absent_delivered = sum(1 for e in absent
                           if str(e.get("status", "")).lower()
                           .replace("-", "").replace(" ", "") in _DELIVERED)

    subjects = Counter(t["subject"] for t in in_window if t["subject"])

    warnings = []
    if not victims:
        warnings.append(
            "No victim address was established, so every sender in this "
            "export is treated as outbound. On a tenant-wide trace that "
            "describes the whole organisation, not the compromised account.")
    if compromise_dt is None:
        warnings.append(
            "No compromise date was established, so the whole trace window is "
            "reported rather than the attacker's. Supply an audit or sign-in "
            "log to bound it.")
    if not traced_with_id and in_window:
        warnings.append(
            "This export carries no message ids, so trace rows cannot be "
            "joined to the corpus and evidence gaps cannot be proven. "
            "Get-MessageTraceDetail, or a trace export including MessageId, "
            "is needed for that.")
    if not attacker_ips and in_window:
        warnings.append(
            "No attacker address was established, so outbound mail in the "
            "window is reported as unattributed rather than confirmed. The "
            "account's own legitimate sending is in here too.")

    return {
        "available": True,
        "schema": SCHEMA,
        "rows": len(rows),
        "victim_addresses": sorted(victims),
        "outbound_total": len(outbound),
        "outbound_in_window": len(in_window),
        "delivered": len(delivered),
        "blocked": len(blocked),
        "attacker_sent": [{k: v for k, v in t.items() if not k.startswith("_")}
                          for t in attacker_sent],
        "attacker_sent_count": len(attacker_sent),
        "unattributed_count": len(unattributed),
        "recipient_domains": len(recipients),
        "external_recipient_domains": sum(1 for r in recipients if r["external"]),
        "distinct_recipients": sum(r["recipient_count"] for r in recipients),
        "recipients": recipients,
        "absent_from_corpus": absent,
        "absent_count": len(absent),
        "absent_delivered_count": absent_delivered,
        "traced_with_id": traced_with_id,
        "top_subjects": subjects.most_common(10),
        "warnings": warnings,
    }


def notification_scope(trace):
    """The third-party list, in the shape a client-facing report needs.

    Deliberately separate from the analysis: this is the part someone acts
    on, and it should be possible to read it without reading anything else.
    """
    t = trace or {}
    if not t.get("available"):
        return {}
    external = [r for r in t.get("recipients", []) if r["external"]]
    return {
        "assessed": True,
        "external_domains": len(external),
        "external_recipients": sum(r["recipient_count"] for r in external),
        "messages_delivered": sum(r["messages"] for r in external),
        "domains": external,
        "note": ("Every address here received mail from the compromised "
                 "account inside the attacker's window. Delivery is confirmed "
                 "by the service, not inferred. Whether each message was the "
                 "attacker's or the owner's still needs review, but this is "
                 "the set that has to be reviewed."),
    }
