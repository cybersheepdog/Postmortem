"""The first page: the nine questions a BEC client actually asks, answered.

Every report this tool produced opened with its own statistics -- messages
analysed, tiers assigned, campaigns clustered. Those are the tool's answers.
The client's questions are different, and after ten years of these cases they
are always the same nine:

    how did they get in         when did it start       when did it end
    which accounts              what was exposed        what was taken
    was money moved             who must be notified    what persists

Each answer carries where it came from, because they are not equally strong:

    observed    the service recorded it -- a sign-in, an audit event, a trace
                row. The strongest claim the report can make.
    inferred    the tool derived it -- a lure joined to a token, a lookalike
                domain, a scoring verdict. Defensible; needs the workings.
    assumed     the analyst supplied it -- an anchor. True by assertion.
    not assessed  nothing to answer from. Names the export that would.

"Not assessed" is a real answer and appears on the page. A question that is
silently omitted reads as "nothing found"; one that says which log is missing
reads as a gap, which is what it is.
"""

from __future__ import annotations

import csv
from pathlib import Path

OBSERVED, INFERRED, ASSUMED, NA = "observed", "inferred", "assumed", "not assessed"


def _a(question, answer, provenance, detail="", gap="", hit=False):
    return {"question": question, "answer": answer, "provenance": provenance,
            "detail": detail, "gap": gap, "hit": bool(hit)}


def _entry(v, s):
    """How did they get in."""
    lures = v.get("signin_lures") or {}
    if s.get("attack_groups"):
        n = s["attack_groups"]
        return _a("How did they get in",
                  "Device code flow phishing (%d correlation group%s show a "
                  "location split)" % (n, "" if n == 1 else "s"),
                  OBSERVED,
                  "The victim authenticated on the real Microsoft page and the "
                  "polling client was elsewhere. Recorded by Entra." +
                  (" Lure confirmed in the corpus." if lures.get("confirmed") else ""),
                  hit=True)
    if s.get("indicated_count"):
        n = s["indicated_count"]
        return _a("How did they get in",
                  "Device code flow phishing indicated (%d sign-in%s match the "
                  "single-record profile)" % (n, "" if n == 1 else "s"),
                  INFERRED,
                  "A client with no device code use case, or MFA satisfied by a "
                  "claim rather than by the user. Assessed per record; not "
                  "corroborated by a second leg.",
                  hit=True)
    if s.get("aitm_indicated"):
        n = s["aitm_indicated"]
        L = (lures.get("aitm") or {})
        c = len(L.get("candidates") or [])
        return _a("How did they get in",
                  "Adversary-in-the-middle indicated (%d sign-in%s replayed a "
                  "captured session from a new location)" % (n, "" if n == 1 else "s")
                  + (", %d lure candidate%s in the corpus" % (c, "" if c == 1 else "s")
                     if c else ""),
                  INFERRED,
                  "A successful sign-in that performed no fresh authentication, "
                  "from an ASN or country this account had never used. The "
                  "victim authenticated for real through a proxy; this is the "
                  "attacker replaying the result. Confirm against the lure.",
                  hit=True)
    lg = s.get("legacy_auth") or {}
    if lg.get("indicated_count"):
        return _a("How did they get in",
                  "Legacy authentication: %d successful sign-in%s over a "
                  "protocol that never asks for MFA (%s)"
                  % (lg["indicated_count"], "" if lg["indicated_count"] == 1 else "s",
                     ", ".join(p for p, _n in lg.get("protocols", [])[:2])),
                  OBSERVED, "A password alone was enough. Disable legacy "
                  "authentication tenant-wide.", hit=True)
    lf = s.get("login_failures") or {}
    if lf.get("fatigue_count"):
        f0 = (lf.get("fatigue") or [{}])[0]
        return _a("How did they get in",
                  "MFA fatigue: %d prompt%s pushed to %s until one was approved"
                  % (f0.get("prompts", 0), "" if f0.get("prompts") == 1 else "s",
                     f0.get("user", "the account")),
                  OBSERVED, "The password was already known; approval came at %s "
                  "from %s." % (f0.get("approved_at", "?"), f0.get("location", "?")),
                  hit=True)
    tr = s.get("token_replay") or {}
    if tr.get("replay_count"):
        return _a("How did they get in",
                  "Token replay: %d address%s acted on the mailbox without ever "
                  "authenticating" % (tr["replay_count"],
                                       "" if tr["replay_count"] == 1 else "es"),
                  OBSERVED,
                  "A refreshed token leaves no sign-in record. The access is in "
                  "the audit log; the authentication is not.", hit=True)
    li = v.get("lookalike_infrastructure") or {}
    if li.get("indicated_count"):
        g = (li.get("domains") or [{}])[0]
        return _a("How did they get in",
                  "Purpose-built lookalike domain: %s (resembles %s, registered "
                  "%d day%s before first contact)"
                  % (g.get("domain", "?"), g.get("resembles", "?"),
                     g.get("age_days", 0), "" if g.get("age_days") == 1 else "s")
                  + (", %d more" % (li["indicated_count"] - 1)
                     if li["indicated_count"] > 1 else ""),
                  OBSERVED,
                  "Registration date from RDAP; resemblance to %s from the "
                  "corpus. Infrastructure made for this case, not a compromised "
                  "account -- the fraud arrives from outside."
                  % ("the victim's own domain" if g.get("resembles_victim")
                     else "a known correspondent"),
                  hit=True)
    if v.get("initial_email"):
        e = v["initial_email"]
        return _a("How did they get in",
                  "Credential phish by email: %s" % (e.get("subject") or "(no subject)"),
                  INFERRED,
                  "From %s, %s. Confidence %s. Scored by the tool, not recorded "
                  "by the service." % (e.get("sender", "?"), e.get("timestamp", "?"),
                                       v.get("confidence", "low")),
                  hit=True)
    pv = v.get("precursor") or {}
    if pv.get("verdict"):
        return _a("How did they get in", str(pv["verdict"]), INFERRED,
                  "Confidence %s." % pv.get("confidence", "low"))
    if s.get("available"):
        return _a("How did they get in", "No entry point established", NA,
                  "The sign-in log was read and shows no device code attack, no "
                  "token replay and no indicated record. The corpus scored no "
                  "initial email above the floor.",
                  gap="If the sign-in export is interactive-only, non-interactive "
                      "sign-ins carry the replayed-session events; re-export "
                      "with both.")
    return _a("How did they get in", "Not assessed", NA,
              gap="Get-GraphEntraSignInLogs (include non-interactive; 30-day "
                  "retention).")


def _t0(v, s, a, anchors):
    """When did it start."""
    if s.get("earliest_token"):
        return _a("When did it start", s["earliest_token"][:19].replace("T", " "),
                  OBSERVED, "First token issued to an attacker address. Earlier "
                  "than the first recorded action, and the true T0.", hit=True)
    d = (a.get("derived") or {})
    if d.get("compromise_date"):
        return _a("When did it start", d["compromise_date"][:19].replace("T", " "),
                  OBSERVED, "First suspicious action in the audit log (a rule, a "
                  "forward). The intrusion began no later than this.", hit=True)
    if anchors is not None and getattr(anchors, "compromise_date", None):
        return _a("When did it start",
                  anchors.compromise_date.strftime("%Y-%m-%d %H:%M:%S"),
                  ASSUMED, "Supplied with --compromise-date.")
    return _a("When did it start", "Not assessed", NA,
              gap="An audit log or sign-in log, or --compromise-date.")


def _tend(a):
    """When did it end."""
    if a.get("containment_date"):
        return _a("When did it end", a["containment_date"][:19].replace("T", " "),
                  ASSUMED, "Supplied with --containment-date. %d audit event(s) "
                  "after it were treated as the client's response."
                  % a.get("response_events", 0))
    return _a("When did it end", "Not assessed", NA,
              gap="--containment-date (password reset / sessions revoked). "
                  "Without it, response activity is indistinguishable from "
                  "the intrusion.")


def _accounts(s, a):
    """Which accounts."""
    users = set()
    for row in (a.get("ip_activity") or []):
        if row.get("is_attacker"):
            users.update(u for u in (row.get("users") or []) if u)
    users.update(u for u in (s.get("affected_users") or []) if u)
    da = a.get("delegate_access") or {}
    unknown = [p["principal"] for p in (da.get("principals") or [])
               if not p.get("known_delegate")]
    if users or unknown:
        names = sorted(users)
        detail = ", ".join(names[:6]) + (" ..." if len(names) > 6 else "")
        if unknown:
            detail += " -- plus %d principal(s) using delegate access they " \
                      "do not hold: %s" % (len(unknown), ", ".join(unknown[:3]))
        return _a("Which accounts", "%d account%s touched from attacker addresses"
                  % (len(names), "" if len(names) == 1 else "s") +
                  (" + %d unexplained delegate(s)" % len(unknown) if unknown else ""),
                  OBSERVED, detail, hit=True)
    if a or s.get("available"):
        return _a("Which accounts", "No account attributed", NA,
                  "Attribution needs an attacker address, which comes from a "
                  "malicious rule, a device code split, a known subject or "
                  "token replay. None was established.",
                  gap="--attacker-subject if the mass-mail subject is known.")
    return _a("Which accounts", "Not assessed", NA, gap="Get-UAL.")


def _exposed(v):
    """What was exposed."""
    x = v.get("exposure_scope") or {}
    if not x.get("available"):
        return _a("What was exposed", "Not assessed", NA,
                  x.get("reason", ""), gap="Get-UAL with MailItemsAccessed (E5), "
                  "and Get-MailboxAuditStatus to settle silence.")
    n = x.get("messages_read", 0)
    if not n:
        return _a("What was exposed", "No message recorded as read from an "
                  "attacker address", OBSERVED,
                  "MailItemsAccessed is present and attributes nothing.")
    lb = x.get("scope_is_lower_bound")
    ans = "%d message%s read" % (n, "" if n == 1 else "s")
    if lb:
        ans += " -- a LOWER BOUND, the log was throttled"
    detail = "%d via folder Sync (whole folder exposed), %d opened individually, " \
             "%d with an attachment." % (x.get("read_by_sync", 0),
                                          x.get("read_by_bind", 0),
                                          x.get("read_with_attachments", 0))
    if lb:
        detail += " Exchange stopped logging after ~1,000 accesses in a day; " \
                  "from that point the honest scope is everything the session " \
                  "could reach."
    sq = (v.get("audit_log") or {}).get("searches") or {}
    if sq.get("attacker_intent"):
        terms = ", ".join(w for w, _n in (sq.get("terms") or [])[:4])
        detail += " The attacker searched the mailbox for: %s." % terms
    return _a("What was exposed", ans, OBSERVED, detail, hit=True)


def _taken(a):
    """What was taken."""
    fa = a.get("file_activity") or {}
    if not a:
        return _a("What was taken", "Not assessed", NA, gap="Get-UAL.")
    if not fa.get("available"):
        return _a("What was taken", "No SharePoint/OneDrive activity in the log",
                  OBSERVED, "The audit log carries no file operations at all. If "
                  "the tenant uses OneDrive, confirm the export included the "
                  "SharePoint workload.")
    ex, fs, sh = fa.get("exfil_count", 0), fa.get("full_sync", 0), fa.get("shared_count", 0)
    if not (ex or sh):
        return _a("What was taken", "No file download or outward share from an "
                  "attacker address", OBSERVED,
                  "%d file event(s) in the log, none attributed."
                  % fa.get("total_file_events", 0))
    ans = "%d file download%s" % (ex, "" if ex == 1 else "s")
    if fs:
        ans += " including %d full-drive sync%s" % (fs, "" if fs == 1 else "s")
    if sh:
        ans += "; %d shared outward" % sh
    return _a("What was taken", ans, OBSERVED,
              "%d distinct file(s) left via attacker addresses."
              % fa.get("exfil_distinct_files", 0), hit=True)


def _money(v, a, records):
    """Was money moved -- what the tool can say is what was SENT."""
    au = v.get("attacker_authorship") or {}
    sent = au.get("attributed_count", 0)
    subj = sum(1 for r in (records or []) if getattr(r, "attacker_subject_sent", False))
    d = a.get("derived") or {}
    subject_sends = d.get("attacker_send_count", 0)
    bank = sum(1 for r in (records or [])
               if getattr(r, "attacker_subject_sent", False)
               and any("bank" in str(f.get("signal", "")).lower()
                       or "payment" in str(f.get("signal", "")).lower()
                       for f in (getattr(r, "provenance", None) or [])))
    total_sent = max(sent, subj, subject_sends)
    subs = (v.get("attachment_diffs") or {}).get("indicated_count", 0)
    if subs and not total_sent:
        return _a("Was money moved",
                  "%d attachment%s substituted on a thread" % (subs, "" if subs == 1 else "s"),
                  OBSERVED,
                  "The same document re-sent by name with different contents, "
                  "after the compromise, alongside payment or bank-change "
                  "language. The tool cannot see a payment; this is the "
                  "instruction being swapped. Compare the two copies.",
                  hit=True)
    if not total_sent:
        if a:
            return _a("Was money moved", "No attacker-sent mail attributed", NA,
                      "The tool cannot see a payment; it can see what was sent. "
                      "Nothing outbound is attributed to the attacker.",
                      gap="--attacker-subject if the fraudulent mail's subject "
                          "is known; Get-MessageTraceLog for mail deleted from "
                          "Sent Items.")
        return _a("Was money moved", "Not assessed", NA, gap="Get-UAL.")
    ans = "%d message%s sent by the attacker" % (total_sent, "" if total_sent == 1 else "s")
    if bank:
        ans += ", %d carrying payment or bank-change language" % bank
    if subs:
        ans += "; %d attachment%s substituted on a thread" % (subs, "" if subs == 1 else "s")
    return _a("Was money moved", ans,
              OBSERVED if (sent or subject_sends) else INFERRED,
              "The tool cannot see a payment. It can see the instruction. "
              "Confirm with the recipients named under 'who must be notified'.",
              hit=True)


def _notify(v):
    """Who must be notified."""
    n = v.get("notification_scope") or {}
    t = v.get("message_trace") or {}
    if not t.get("available"):
        return _a("Who must be notified", "Not assessed", NA,
                  gap="Get-MessageTraceLog (90-day historical). The PST holds "
                      "what survived; mail the attacker sent and deleted is "
                      "only in the trace.")
    if not n.get("external_domains"):
        return _a("Who must be notified", "No external recipient in the window",
                  OBSERVED, "Message trace covers the window and shows no mail "
                  "from the account to an external organisation.")
    return _a("Who must be notified",
              "%d external organisation%s, %d recipient%s"
              % (n["external_domains"], "" if n["external_domains"] == 1 else "s",
                 n.get("external_recipients", 0),
                 "" if n.get("external_recipients", 0) == 1 else "s"),
              OBSERVED, "Delivery confirmed by the service. Whether each message "
              "was the attacker's or the owner's still needs review; this is the "
              "set to review." + (" %d message(s) the service delivered are not "
              "in this export." % t.get("absent_delivered_count", 0)
              if t.get("absent_delivered_count") else ""), hit=True)


def _persists(v):
    """What persists."""
    p = v.get("persistence") or {}
    rem = v.get("remediation") or []
    if not p.get("available") and not rem:
        return _a("What persists", "Not assessed", NA,
                  gap="--mes-dir: an OAuth consent grant leaves no trace in mail "
                      "or sign-in data.")
    tw = p.get("tenant_wide_count", 0)
    both = p.get("survives_both_count", 0)
    n = len(rem)
    if not n:
        return _a("What persists", "No persistence mechanism identified", OBSERVED,
                  "Directory audit, OAuth grants and mailbox configuration were "
                  "read and nothing is unaccounted for.")
    ans = "%d action%s required" % (n, "" if n == 1 else "s")
    if tw:
        ans += " -- %d TENANT-WIDE, not fixed by anything at the account level" % tw
    elif both:
        ans += " -- %d survive a password reset AND a token revocation" % both
    return _a("What persists", ans, OBSERVED,
              "Ordered by what survives the response the client has already "
              "made. An unrevoked refresh token is 90 days of access.", hit=True)


def case_answers(initial_verdict, records=None, anchors=None):
    """The nine answers, in the order a client asks them."""
    v = initial_verdict or {}
    s = v.get("signin_log") or {}
    a = v.get("audit_log") or {}
    return [
        _entry(v, s),
        _t0(v, s, a, anchors),
        _tend(a),
        _accounts(s, a),
        _exposed(v),
        _taken(a),
        _money(v, a, records),
        _notify(v),
        _persists(v),
    ]


def exposure_rows(initial_verdict):
    """The read inventory as flat rows: the artefact counsel asks for."""
    x = (initial_verdict or {}).get("exposure_scope") or {}
    out = []
    for e in x.get("read") or []:
        out.append({
            "first_access": e.get("first_access", ""),
            "accesses": e.get("accesses", 1),
            "access_type": e.get("access_type", ""),
            "throttled": "yes" if e.get("throttled") else "",
            "client_ip": e.get("client_ip", ""),
            "session_id": e.get("session_id", ""),
            "subject": e.get("subject", ""),
            "sender": e.get("sender", ""),
            "has_attachment": "yes" if e.get("has_attachment") else "",
            "in_corpus": "yes" if e.get("in_corpus") else "no",
            "message_id": e.get("message_id", ""),
            "path": e.get("path", ""),
        })
    return out


EXPOSURE_COLUMNS = ["first_access_utc", "accesses", "access_type", "throttled",
                    "client_ip", "session_id", "subject", "sender",
                    "has_attachment", "in_corpus", "message_id", "path"]


def write_exposure_csv(initial_verdict, output):
    """Every message the attacker is recorded as having read, one per row.

    This is the list a breach-notification decision is made from and the
    file counsel asks for. --ioc is indicators; this is exposure.
    """
    rows = exposure_rows(initial_verdict)
    out = Path(output)
    with out.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(EXPOSURE_COLUMNS)
        for r in rows:
            w.writerow([r["first_access"], r["accesses"], r["access_type"],
                        r["throttled"], r["client_ip"], r["session_id"],
                        r["subject"], r["sender"], r["has_attachment"],
                        r["in_corpus"], r["message_id"], r["path"]])
    return len(rows)
