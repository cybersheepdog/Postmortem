"""Report generation: console summaries, the interactive HTML report, JSON and
CSV exports, and the reproducibility manifest. Consumes analysis results; it is
the top layer and nothing else imports it.
"""

import csv
import hashlib
import html
import json
import os
import re
import sys
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from postmortem import term
from postmortem.config import CONFIG, TOOL_VERSION, PARSER_VERSION
from postmortem.models import EmailRecord, CampaignInfo, AttackTimelineEvent
from postmortem.utils import date_sort_key, to_utc_fields, clean_text, parse_date
from postmortem.scoring import classify_attack_stage, build_evidence_graph

# Per-message URL links and body-snippet length embedded in the HTML report
# (the JSON/CSV reports keep everything). Caps only affect the interactive page.
_HTML_URL_CAP = 15
_HTML_SNIPPET = 300


def _confidence_c(text: str) -> str:
    """Color a confidence label: high=red, medium=yellow, low/other=dim."""
    styles = {"high": ("red", "bold"), "medium": ("yellow",)}.get(
        str(text).lower(), ("dim",))
    return term.c(text, *styles)


def _wrap_indent(text: str, indent: int, width: int = 78) -> str:
    """Wrap `text` to `width`, indenting every line after the first.

    Coverage warnings are full sentences that have to stay readable in a
    terminal; a paragraph run off the right edge is a warning nobody reads.
    """
    import textwrap
    lines = textwrap.wrap(str(text), width=max(20, width - indent))
    pad = " " * indent
    return ("\n" + pad).join(lines) if lines else ""


def _hdr(title: str, ch: str = "=") -> None:
    """Print a consistent, color-coded section header."""
    print(term.c(ch * 80, "cyan"))
    print(term.c(title, "cyan", "bold"))
    print(term.c(ch * 80, "cyan"))


# --------------------------------------------------------------------------
# MITRE ATT&CK technique mapping (heuristic, from finding categories/signals)
# --------------------------------------------------------------------------
# These are header/content heuristics offered to speed SOC triage, not confirmed
# behavior. Keyed by a finding's provenance category, refined by signal text.
_MITRE_BY_CATEGORY = {
    "language": ("T1566", "Phishing"),
    "url": ("T1566.002", "Spearphishing Link"),
    "attachment": ("T1566.001", "Spearphishing Attachment"),
    "identity": ("T1656", "Impersonation"),
    "auth": ("T1656", "Impersonation"),
    "thread": ("T1534", "Internal Spearphishing"),
    "concealment": ("T1564.008", "Email Hiding Rules"),
    "headers": ("T1036", "Masquerading"),
}
_MITRE_SIGNAL_REFINE = (
    ("disguised", ("T1036.008", "Masquerade File Type")),
    ("does not match the", ("T1036.008", "Masquerade File Type")),
    ("double extension", ("T1036.008", "Masquerade File Type")),
    ("macro", ("T1204.002", "User Execution: Malicious File")),
    ("forwards to", ("T1114.003", "Email Forwarding Rule")),
)


def mitre_for_record(record) -> list[dict]:
    """Best-effort ATT&CK techniques implied by a record's findings."""
    found = {}
    for p in (record.provenance or []):
        tech = _MITRE_BY_CATEGORY.get(p.get("category", ""))
        if tech:
            found[tech[0]] = tech[1]
        sig = (p.get("signal", "") or "").lower()
        for needle, t in _MITRE_SIGNAL_REFINE:
            if needle in sig:
                found[t[0]] = t[1]
    return [{"id": tid, "name": name} for tid, name in sorted(found.items())]


def mitre_summary(records) -> list[dict]:
    """Aggregate ATT&CK techniques across records, most-frequent first."""
    counts, names = {}, {}
    for r in records:
        for t in mitre_for_record(r):
            counts[t["id"]] = counts.get(t["id"], 0) + 1
            names[t["id"]] = t["name"]
    return [{"id": tid, "name": names[tid], "messages": counts[tid]}
            for tid in sorted(counts, key=lambda k: (-counts[k], k))]


def _defang(text: str) -> str:
    """Neutralize URLs and email addresses so a preview is never clickable."""
    text = text.replace("https://", "hxxps://").replace("http://", "hxxp://")
    text = re.sub(
        r"[\w.+%-]+@[\w.-]+\.\w+",
        lambda m: m.group(0).replace("@", "[at]").replace(".", "[.]"), text)
    text = re.sub(
        r"(?:hxxps?://)[\w./:%#?=&-]+",
        lambda m: m.group(0).replace(".", "[.]"), text)
    return re.sub(r"\bwww\.", "www[.]", text)


def evidence_snippet(
    record: EmailRecord,
    length: int = 500,
) -> str:
 
    text = clean_text(
        record.body
    )
 
    if len(text) <= length:
        return text
 
    return (
        text[:length]
        .rstrip()
        + "..."
    )
 
 
def print_campaigns(
    campaigns: list[CampaignInfo],
    records: list[EmailRecord],
):
 
    if not campaigns:
        return
 
    print()
    _hdr("CAMPAIGN CLUSTERS")
 
    for campaign in campaigns[:20]:
 
        print()
 
        print(
            f"{campaign.campaign_id} | "
            f"SCORE {campaign.campaign_score} | "
            f"{campaign.confidence.upper()} | "
            f"{campaign.message_count} messages"
        )
 
        print(
            f"    First seen: {campaign.first_seen or '(unknown)'}"
        )
 
        print(
            f"    Last seen:  {campaign.last_seen or '(unknown)'}"
        )
 
        if campaign.sender_domains:
 
            print(
                "    Sender domains: "
                + ", ".join(
                    campaign.sender_domains
                )
            )
 
        if campaign.url_domains:
 
            print(
                "    URL domains: "
                + ", ".join(
                    campaign.url_domains
                )
            )
 
        if campaign.shared_indicators:
 
            for indicator in (
                campaign.shared_indicators[:8]
            ):
 
                print(
                    f"    - {indicator}"
                )
 
        if campaign.likely_origin:
 
            print(
                "    Likely origin/precursor: "
                + campaign.likely_origin
            )
 
        print(
            "    Subjects:"
        )
 
        for subject in campaign.subjects[:5]:
 
            print(
                "      "
                + (
                    subject
                    or "(no subject)"
                )
            )
 
 
def print_audit_join(verdict: dict):
    """What the audit log proved about specific messages in this corpus.

    Separate from the audit summary above, which describes the mailbox. This
    is the join: recorded attacker actions matched to items actually present
    here, and it is the only place the tool states a fact about a message
    rather than an inference from it.
    """
    join = (verdict or {}).get("audit_join") or {}
    if not join.get("matched"):
        return
    print()
    _hdr("AUDIT LOG JOINED TO MESSAGES (recorded, not inferred)")
    print(f"  Messages in this corpus named by the audit log: {join['matched']}")
    print(f"  Audit events attached to them:                  {join['events']}")
    print(f"  Acted on by an attacker session:                {join['confirmed']}"
          + ("   -> Tier 1" if join["confirmed"] else ""))
    print(f"  Only seen by an attacker session:               "
          f"{join.get('read_only', 0)}"
          + ("   -> Tier 2 floor" if join.get("read_only") else ""))
    if not join["confirmed"]:
        print()
        print("  No deliberate message-level action (delete, move, send) was")
        print("  attributable to an attacker IP. Events with no ClientIP, or")
        print("  from the mailbox owner's own address, are attached as context")
        print("  but do not promote.")
    else:
        print()
        print("  'Acted on' means delete, move or send -- a deliberate act on a")
        print("  named item. A read is kept separate because one")
        print("  MailItemsAccessed sync record can name an entire folder.")



def print_deletion_completeness(verdict: dict, limit: int = 15):
    """State plainly what is missing from the corpus and why.

    Every other section describes messages that are here. This one describes
    messages that are not, which the message-only pipeline has no way to
    notice: a hard-deleted item is simply absent from the PST, and nothing
    about the remaining mail reveals the hole.
    """
    c = (verdict or {}).get("deletion_completeness") or {}
    if not c:
        return

    print()
    _hdr("EVIDENCE COMPLETENESS (what is missing from this export)")

    if not c.get("reliable"):
        # The alternative is printing "4,106 messages are missing", which is
        # both alarming and meaningless when the log describes a different
        # mailbox than the one exported.
        print(f"  The audit log names {c['messages_named_by_log']} message(s) and "
              "NONE of them are in this corpus.")
        print("  The log and the export do not correspond -- most likely a "
              "different mailbox,")
        print("  or windows that do not overlap. No completeness claim can be "
              "made until")
        print("  that is resolved; every deletion would otherwise read as a "
              "false absence.")
        return

    if not c.get("deleted_total"):
        print("  The audit log records no message-level deletions.")
        return

    print(f"  Messages the log records as deleted:      {c['deleted_total']}")
    print(f"    still present in this export:           {c['deleted_still_present']}")
    print(f"    ABSENT from this export:                {c['deleted_absent']}")
    if c.get("deleted_absent_by_attacker"):
        print(f"      of those, deleted by the attacker:    "
              f"{c['deleted_absent_by_attacker']}")

    if not c.get("deleted_absent"):
        print()
        print("  Every deleted message is still in the export, so the corpus is")
        print("  complete with respect to what the log records.")
        return

    print()
    print(f"  {c['deleted_absent']} message(s) were deleted and are not in this "
          "export. They cannot be")
    print("  scored, clustered or read. What follows is everything the audit log")
    print("  retained about them -- often the subject alone, which is still the "
          "only")
    print("  record that they existed:")
    print()
    for e in c["absent"][:limit]:
        who = "attacker" if e["by_attacker"] else (e["actor"] or "unknown")
        print(f"    {e['time'] or '(no time)':20} {e['verb']:22} by {who}"
              + (f" from {e['client_ip']}" if e["client_ip"] else ""))
        print(f"      subject: {e['subject'] or '(not recorded in the log)'}")
        if e["folder"]:
            print(f"      folder:  {e['folder']}")
    if len(c["absent"]) > limit:
        print(f"    ... and {len(c['absent']) - limit} more "
              "(complete list in the JSON report)")



def print_attacker_authorship(verdict: dict, limit: int = 12):
    """What the attacker sent from the mailbox they took over (E3)."""
    a = (verdict or {}).get("attacker_authorship") or {}
    if not (a.get("attributed_count") or a.get("in_window_count")):
        return
    print()
    _hdr("SENT BY THE ATTACKER (confirmed from the audit log)")
    print(f"  Sent from a known attacker address:  {a['attributed_count']}")
    if a.get("in_window_count"):
        print(f"  Sent after the compromise timestamp: {a['in_window_count']}"
              "   (timing, not attribution)")
    if a.get("burst_corroborated"):
        print(f"  Also detected as a mass-mail burst:  {a['burst_corroborated']}"
              "   (corpus repetition agrees)")

    rows = (a.get("attributed") or []) + (a.get("in_window") or [])
    if not rows:
        return
    print()
    for e in rows[:limit]:
        print(f"    {e['time'] or '(no time)':20} {e['operation']:14} "
              f"{'in corpus' if e['in_corpus'] else 'NOT in corpus'}")
        print(f"      subject: {e['subject'] or '(not recorded)'}")
        if e.get("recipients"):
            print(f"      to:      {', '.join(e['recipients'])}")
        print(f"      basis:   {e['basis']}")
    if len(rows) > limit:
        print(f"    ... and {len(rows) - limit} more (full list in the JSON report)")


def print_exposure_scope(verdict: dict, limit: int = 12):
    """Which messages the intruder actually read (E4)."""
    x = (verdict or {}).get("exposure_scope") or {}
    if not x:
        return
    print()
    _hdr("EXPOSURE SCOPE (what the intruder read)")

    if not x.get("available"):
        print("  " + _wrap_indent(x.get("reason", ""), 2))
        return

    if not x.get("messages_read"):
        print("  The log carries MailItemsAccessed, and no message in it was")
        print("  accessed from a known attacker address.")
        return

    print(f"  Messages read from an attacker address:  {x['messages_read']}")
    print(f"    present in this export:                {x['read_and_in_corpus']}")
    print(f"    carrying an attachment:                {x['read_with_attachments']}")
    print()
    print("  This is the set a breach-notification decision rests on: mail the")
    print("  intruder is recorded as having opened, not mail they could have.")
    print()
    for e in x["read"][:limit]:
        print(f"    {e['first_access'] or '(no time)':20} "
              f"{('x%d' % e['accesses']) if e['accesses'] > 1 else '  ':4} "
              f"{'' if e['in_corpus'] else '(NOT in corpus) '}"
              f"{e['subject'] or '(subject not recorded)'}")
        if e.get("sender"):
            print(f"      from: {e['sender']}"
                  + ("   [has attachment]" if e["has_attachment"] else ""))
    if len(x["read"]) > limit:
        print(f"    ... and {len(x['read']) - limit} more "
              "(full list in the JSON report)")


def print_rule_replay(verdict: dict, limit: int = 10):
    """What each malicious rule would have caught (E6)."""
    r = (verdict or {}).get("rule_replay") or {}
    if not r.get("rules"):
        return
    print()
    _hdr("MALICIOUS RULES REPLAYED OVER THE CORPUS")
    print("  A rule's conditions are a written statement of what the attacker")
    print("  wanted hidden. Each is re-run here as a predicate over the corpus.")

    for rule in r["rules"]:
        conds = rule.get("conditions") or {}
        spec = "; ".join(
            f"{field.replace('_', ' ')}: {', '.join(words)}"
            for field, words in conds.items() if words)
        print()
        print(f"  {rule['rule_time'] or '(no time)'} {rule['operation']}"
              f" from {rule['client_ip'] or '(no IP)'} - {rule['action']}")
        print(f"    conditions: {spec}")
        print(f"    would have caught {rule['matched_total']} message(s) in this "
              f"corpus:")
        print(f"      {rule['matched_before_rule']} that arrived BEFORE the rule "
              "existed")
        print(f"      {rule['matched_after_rule']} that arrived AFTER it - filed "
              "away unseen")
        for e in rule["after"][:limit]:
            print(f"        {e['date'][:31]:31} {e['subject'][:44]}")
        if len(rule["after"]) > limit:
            print(f"        ... and {len(rule['after']) - limit} more")


def print_attacker_ip_activity(audit: dict, limit: int = 8):
    """Everything done from each attacker address, and where it was (E9)."""
    if not audit:
        return
    rows = [x for x in (audit.get("ip_activity") or []) if x["is_attacker"]]
    flagged = [x for x in (audit.get("ip_activity") or [])
               if x.get("unexpected_country") and not x["is_attacker"]]
    if not rows and not flagged:
        return
    print()
    _hdr("ATTACKER SESSION ACTIVITY (every operation, not just sign-ins)")
    for x in rows:
        where = ", ".join(v for v in (x.get("country"), x.get("org")) if v)
        print(f"  {x['ip']:>39}  {x['events']} event(s)"
              + (f"   {where}" if where else ""))
        print(f"    {x['first_seen'] or '?'} to {x['last_seen'] or '?'}")
        print("    " + ", ".join(f"{op} ({n})" for op, n in x["operations"]))
        if x.get("unexpected_country"):
            print(f"    OUTSIDE --expected-countries: {x['country']}")
    for x in flagged:
        print(f"  {x['ip']:>39}  {x['events']} event(s)   "
              f"{x['country']} - outside --expected-countries, not otherwise "
              "attributed")


def print_initial_compromise(verdict: dict):
    print()
    _hdr("INITIAL COMPROMISE ANALYSIS")
    print(f"Scenario profile: {verdict.get('scenario', '')} "
          f"({verdict.get('scenario_reason', '')})")
    if verdict.get("victim_address"):
        print(f"Inferred victim mailbox: {verdict.get('victim_address')}")
    print(f"Investigator anchors supplied: "
          f"{'yes' if verdict.get('anchors_supplied') else 'no'}")
    tiers = verdict.get("tier_counts") or {}
    if tiers:
        print("Review tiers: "
              f"Tier 1 (prime suspects) = {tiers.get(1, 0)}, "
              f"Tier 2 (secondary) = {tiers.get(2, 0)}, "
              f"Tier 3 (rest) = {tiers.get(3, 0)}")
    print(f"Verdict:    {verdict.get('verdict', '')}")
    print(f"Confidence: {verdict.get('confidence', '')}")
    print(f"Reason:     {verdict.get('reason', '')}")

    initial = verdict.get("initial_email")
    if initial:
        print()
        print("Most likely INITIAL malicious email:")
        print(f"  Timestamp: {initial.get('timestamp', '')}")
        print(f"  Sender:    {initial.get('sender', '')}")
        print(f"  Subject:   {initial.get('subject', '')}")
        print(f"  Stage:     {initial.get('stage', '')}")
        print(f"  File:      {initial.get('path', '')}")
        print(f"  Initial-email score: {initial.get('initial_score', 0)} "
              f"(priority score {initial.get('priority_score', 0)})")
        if initial.get("anchor_matches"):
            print(f"  Anchor matches: {', '.join(initial['anchor_matches'])}")
        # Each reason with the value that triggered it. A finding an analyst
        # cannot check is a finding they have to trust, and "display-name
        # impersonation" without the two addresses is exactly that.
        findings = {f.get("signal"): f for f in initial.get("findings", []) or []}
        for reason in initial.get("reasons", [])[:8]:
            print(f"    - {reason}")
            hit = findings.get(reason) or {}
            evidence = str(hit.get("matched") or "")
            if evidence:
                where = hit.get("source") or ""
                print(f"        evidence: {evidence}"
                      + (f"   [{where}]" if where else ""))

    shortlist = [s for s in verdict.get("shortlist", []) if s.get("path") != (initial or {}).get("path")]
    if shortlist:
        print()
        print("Other candidates (ranked):")
        for item in shortlist[:6]:
            print(f"  [{item.get('initial_score', 0):>3}] {item.get('timestamp', '')} | "
                  f"{item.get('sender', '')} | {item.get('subject', '')}")


def print_attack_narrative(narrative: dict):
    if not narrative or not narrative.get("phases"):
        return
    print()
    _hdr("ATTACK NARRATIVE (reconstructed)")
    print(narrative.get("summary", ""))
    for i, phase in enumerate(narrative.get("phases", []), 1):
        print()
        print(f"  {i}. {phase.get('title', '')}"
              + (f"   [{phase.get('timestamp', '')}]" if phase.get("timestamp") else "")
              + f"   (confidence {phase.get('confidence', 'low')})")
        print(f"     {phase.get('description', '')}")
        for m in phase.get("messages", [])[:3]:
            print(f"       - {m.get('timestamp', '')} | {m.get('sender', '')} | "
                  f"{m.get('subject', '(no subject)')}")
    timeline = narrative.get("timeline", [])
    if timeline:
        print()
        print("  Chronological key events (UTC):")
        for e in timeline[:12]:
            print(f"    {e.get('timestamp_utc', ''):20} [{e.get('phase', '')}] "
                  f"{e.get('label', '')} - {e.get('subject', '')[:48]}")
    print()
    print(f"  Note: {narrative.get('disclaimer', '')}")


def print_audit_summary(audit: dict, warnings=None):
    """Console section for an ingested M365 Unified Audit Log.

    `warnings` come from auditlog.coverage_warnings() and state what the export
    cannot speak to. They print first: a conclusion drawn from a log that does
    not span the incident is worse than no conclusion, and an analyst needs to
    know that before reading the findings, not after.
    """
    if not audit:
        return
    d = audit.get("derived", {})
    cov = audit.get("coverage", {}) or {}
    print()
    _hdr("M365 UNIFIED AUDIT LOG (confirmed attacker activity)")

    if cov:
        span = cov.get("span_days", 0)
        print(f"  Log covers:             {cov.get('first_event', '?')} to "
              f"{cov.get('last_event', '?')}"
              + (f"  ({span}d)" if span else ""))
        print(f"  Scope:                  {cov.get('mailboxes', 0)} mailbox(es), "
              f"{cov.get('client_ips', 0)} client IP(s), "
              f"{cov.get('distinct_operations', 0)} distinct operation(s)")
        if cov.get("events_without_timestamp"):
            print(f"  Undated events:         "
                  f"{cov['events_without_timestamp']} (excluded from the timeline)")

    ops = cov.get("operations") or []
    if ops:
        top = ops[:8]
        print("  Operations:             " + ", ".join(
            f"{name} ({count})" for name, count in top)
            + (f", +{len(ops) - len(top)} more" if len(ops) > len(top) else ""))

    for w in (warnings or []):
        print()
        label = "COVERAGE GAP" if w["severity"] == "high" else "Coverage note"
        prefix = f"  {label}: "
        print(prefix + _wrap_indent(w["text"], len(prefix)))
    if warnings:
        print()

    print(f"  Events parsed:          {audit.get('events_parsed', 0)}")

    idx = audit.get("message_index") or {}
    if idx.get("messages_referenced"):
        print(f"  Message-level events:   "
              f"{idx['events_with_message_id']} event(s) naming "
              f"{idx['messages_referenced']} distinct message(s)")
    if d.get("compromise_date"):
        print(f"  Compromise (earliest):  {d['compromise_date']}")
    if d.get("attacker_ips"):
        print(f"  Attacker IP(s):         {', '.join(d['attacker_ips'])}")
    if d.get("attacker_addresses"):
        print(f"  Forwarding address(es): {', '.join(d['attacker_addresses'])}")
    if d.get("attacker_domains"):
        print(f"  Attacker domain(s):     {', '.join(d['attacker_domains'])}")
    if d.get("rule_keywords"):
        print(f"  Rule keyword(s):        {', '.join(d['rule_keywords'])}")

    rules = audit.get("malicious_rules", [])
    if rules:
        print()
        print(f"  Malicious mailbox rules ({len(rules)}):")
        for r in rules[:10]:
            bits = []
            if r.get("forwards"):
                bits.append("forwards to " + ", ".join(r["forwards"]))
            if r.get("move_to"):
                bits.append(f"moves to '{r['move_to']}'")
            if r.get("delete"):
                bits.append("deletes matching mail")
            if r.get("keywords"):
                bits.append("keywords: " + ", ".join(r["keywords"]))
            print(f"    {r.get('time', ''):20} {r.get('operation', '')} "
                  f"from {r.get('client_ip', '?')} - {'; '.join(bits)}")

    fwd = audit.get("forwarding_rules", [])
    if fwd:
        print()
        print(f"  Forwarding rules ({len(fwd)}):")
        for r in fwd[:10]:
            print(f"    {r.get('time', ''):20} {r.get('operation', '')} "
                  f"from {r.get('client_ip', '?')} - forwards to "
                  f"{', '.join(r.get('forwards', []))}")

    logins = audit.get("attacker_logins", [])
    if logins:
        print()
        print(f"  Attacker sign-ins from those IP(s) ({len(logins)}):")
        for lg in logins[:10]:
            print(f"    {lg.get('time', ''):20} {lg.get('ip', '')} "
                  f"({lg.get('user', '')})")
    if audit.get("deletions"):
        print()
        print(f"  Mail deletion events:   {audit['deletions']}")
    print()



def candidate_sort_key(record):
    """Ranking for every candidate list: recorded fact first, then score.

    A message an attacker is recorded as having deleted, or a lure tied to a
    token issuance, carries no score -- those are facts, and the score means
    "how suspicious is this text". Ordering by score alone therefore buried
    the best-evidenced message in the case under whatever content heuristic
    happened to rank highest. This restores the ranking benefit without
    putting a fact on the heuristic scale.
    """
    confirmed = (getattr(record, "audit_confirmed", False)
                 or getattr(record, "signin_confirmed", False)
                 or getattr(record, "attacker_authored", False))
    return (not confirmed, -record.score, date_sort_key(record))



def print_signin_analysis(signin_summary: dict):
    """What the Entra sign-in log recorded about device code authentication.

    The mail corpus cannot see this attack at all. There is no attacker
    domain in the lure, no credential-harvesting page and nothing for URL
    analysis to score -- the victim authenticates on the real Microsoft page
    and passes real MFA. The only record that it happened is here.
    """
    s = signin_summary or {}
    if not s.get("available"):
        return
    cov = s.get("coverage") or {}
    print()
    _hdr("ENTRA SIGN-IN LOG: DEVICE CODE FLOW")
    print(f"  Records read:            {s['records']} from {s['files']} file(s)")
    print(f"  Window:                  {cov.get('first_event') or '?'}"
          f"  ->  {cov.get('last_event') or '?'}")
    print(f"  Accounts in export:      {cov.get('accounts', 0)}")

    blind = cov.get("blind")
    detect = "  originalTransferMethod:  %d of %d      authenticationProtocol:  %d of %d" % (
        cov.get("have_transfer", 0), s["records"],
        cov.get("have_protocol", 0), s["records"])
    print(term.c(detect, "red") if blind else detect)
    if blind:
        print()
        print(term.c("  " + _wrap_indent(
            "Neither field is present. This export cannot answer the device "
            "code question at all, and a clean result here is not a negative.",
            2), "red", "bold"))
        return

    print(f"  Device code sign-ins:    {s['device_code_records']}")
    if not s["device_code_records"]:
        print()
        print("  No device code authentication in the covered window.")
        return

    attack = s.get("attack_groups", 0)
    line = f"  Groups showing a location split: {attack}"
    print(term.c(line, "red", "bold") if attack else line)
    print(f"  Tokens issued to an attacker address: {s.get('tokens_issued', 0)}")
    if s.get("earliest_token"):
        print(term.c(f"  First token issued:      {s['earliest_token']}"
                     "   <- true compromise T0", "red"))

    if s.get("attacker_ips"):
        print()
        print("  Attacker addresses established here (seeded into the audit-log")
        print("  attribution, which otherwise derives them only from rules):")
        for ip in s["attacker_ips"]:
            print(term.c(f"    {ip}", "red"))

    for g in s.get("groups", []):
        if g["verdict"] != "attack":
            continue
        print()
        print(term.c(f"  [{g['verdict'].upper()}] {g['user']}   "
                     f"differs by: {', '.join(g['differs'])}", "red", "bold"))
        print(f"    correlation {g['correlation']}   "
              f"attribution: {g['attribution_basis'] or 'not established'}")
        for leg in g["legs"]:
            role = "victim (interactive)" if leg["interactive"] else "polling client"
            mark = "  " if leg["interactive"] else "->"
            row = (f"    {mark} {leg['time']}  {leg['ip']:<16} {leg['location']:<22} "
                   f"{role}")
            print(row if leg["interactive"] else term.c(row, "red"))
            detail = f"         {leg['app']}"
            if leg["resource"]:
                detail += f" -> {leg['resource']}"
            if leg["status"] != "success":
                detail += f"   [{leg['status']}]"
            print(term.c(detail, "dim") if hasattr(term, "c") else detail)

    singles = s.get("single_groups") or []
    if singles:
        print()
        print("  " + _wrap_indent(
            "%d device code group(s) have only one recorded leg. These are "
            "UNRESOLVED, not clean: the export did not capture the other leg, "
            "or the attacker's address resembled the victim's. A residential "
            "proxy in the victim's own country produces exactly this picture."
            % len(singles), 2))

    for w in s.get("warnings", []):
        print()
        print(term.c("  [!] " + _wrap_indent(w, 6), "yellow"))


def print_signin_lures(verdict: dict):
    """The message that produced the token, matched by time rather than words."""
    lures = (verdict or {}).get("signin_lures") or {}
    if not lures.get("available"):
        return
    print()
    _hdr("DEVICE CODE LURE (sign-in log joined to the corpus)")
    print(f"  Token issuances examined: {lures['tokens']}")
    print(f"  Search window:            {lures['window_minutes']} minutes before each")

    for e in lures.get("confirmed", []):
        print()
        print(term.c(f"  CONFIRMED  {e['subject'] or '(no subject)'}", "red", "bold"))
        print(f"    from     {e['sender']}")
        print(f"    arrived  {e['arrival']}")
        print(term.c(f"    token    {e['token_time']}  "
                     f"({e['delta_seconds']}s later) from {e['attacker_ip']}", "red"))
        if e.get("code"):
            print(f"    code     {e['code']}")
        if e.get("url"):
            print(f"    url      {e['url']}")
        print(f"    file     {e['path']}")

    barren = lures.get("tokens_without_lure") or []
    if barren and not lures.get("confirmed"):
        print()
        for t in barren:
            print(term.c(f"  Token issued {t['time']} to {t['user']} "
                         f"from {t['ip']} -- no lure found", "yellow"))

    cands = lures.get("in_window_only") or []
    if cands and not lures.get("confirmed"):
        print()
        print(f"  {len(cands)} message(s) arrived in the window but carry no")
        print("  device login URL. Listed for review, not promoted:")
        for e in cands[:10]:
            print(f"    {e['arrival']}  {e['sender']:<34} {e['subject'][:34]}")
        if len(cands) > 10:
            print(f"    ... {len(cands) - 10} more in the JSON report")

    if lures.get("note"):
        print()
        print("  " + _wrap_indent(lures["note"], 2))



def print_persistence(persistence: dict):
    """What the attacker left behind that outlives the obvious remediation."""
    p = persistence or {}
    if not p.get("available"):
        return
    print()
    _hdr("PERSISTENCE MECHANISMS (does the attacker still have access?)")

    src = p.get("sources") or {}
    if src:
        print("  Sources read: " + ", ".join(
            f"{k} ({v})" for k, v in sorted(src.items())))

    findings = p.get("findings") or []
    if not findings:
        print()
        print("  No persistence mechanism was found in the supplied data.")
        for w in p.get("warnings", []):
            print()
            print(term.c("  [!] " + _wrap_indent(w, 6), "yellow"))
        return

    both = p.get("survives_both_count", 0)
    line = (f"  Mechanisms found: {len(findings)}   "
            f"attacker-attributed: {p.get('confirmed_count', 0)}   "
            f"survive password reset AND token revocation: {both}")
    print(term.c(line, "red", "bold") if both else line)

    for e in findings:
        print()
        tag = "CONFIRMED" if e.get("by_attacker") else "REVIEW   "
        target = ", ".join(e.get("targets", [])) or e.get("role") \
            or e.get("name") or e.get("user") or "(unnamed)"
        head = f"  {tag}  {e.get('activity', e['kind'])}: {target}"
        colour = ("red", "bold") if e.get("by_attacker") else ("yellow",)
        print(term.c(head, *colour))
        if e.get("time"):
            print(f"      when     {e['time']}"
                  + (f"   from {e['ip']}" if e.get("ip") else ""))
        if e.get("actor"):
            print(f"      actor    {e['actor']}")
        if e.get("attribution"):
            print(f"      basis    {e['attribution']}")
        if e.get("mail_scopes"):
            print(term.c("      mailbox  " + ", ".join(e["mail_scopes"]), "red"))
        if e.get("high_risk_scopes"):
            print("      other    " + ", ".join(e["high_risk_scopes"]))
        if e.get("durable_scopes"):
            print(term.c("      standing offline_access: not bound to a "
                         "session", "red"))
        survives = []
        if e.get("survives_password_reset") == "survives":
            survives.append("a password reset")
        if e.get("survives_token_revocation") == "survives":
            survives.append("a token revocation")
        if survives:
            print(term.c("      SURVIVES " + " and ".join(survives), "red", "bold"))
        if e.get("grants"):
            print("      " + _wrap_indent(e["grants"], 6))

    mfa = p.get("mfa_state") or []
    if mfa:
        print()
        print("  Authentication methods currently registered:")
        for m in mfa[:12]:
            print(f"    {m['user']:<38} {m.get('methods', '') or '(none recorded)'}")
        if len(mfa) > 12:
            print(f"    ... {len(mfa) - 12} more in the JSON report")
        print()
        print("  " + _wrap_indent(
            "Confirm each of these with the account owner. A method the "
            "owner does not recognise is the attacker's, and removing it "
            "is part of remediation.", 2))

    risk = p.get("risk_detections") or []
    if risk:
        print()
        print("  Identity Protection detections (independent corroboration):")
        for d in risk[:10]:
            print(f"    {d.get('time', '')[:19]:<20} {d.get('level', ''):<8} "
                  f"{d.get('detection', ''):<28} {d.get('ip', '')}")

    for w in p.get("warnings", []):
        print()
        print(term.c("  [!] " + _wrap_indent(w, 6), "yellow"))


def print_remediation(actions: list):
    """The action list, ordered by what the client's usual response misses."""
    if not actions:
        return
    print()
    _hdr("REMEDIATION REQUIRED", ch="=")
    print("  " + _wrap_indent(
        "Ordered by what survives the response most clients have already "
        "made. Items at the top are NOT addressed by resetting the password "
        "or revoking sessions, and remain live until the stated action is "
        "taken.", 2))

    for a in actions:
        print()
        head = f"  {a['priority']}. {a['kind'].replace('_', ' ')}: {a['target']}"
        print(term.c(head, "red", "bold") if a["by_attacker"]
              else term.c(head, "yellow"))
        if a.get("when"):
            print(f"       when    {a['when']}"
                  + (f"  ({a['attribution']})" if a.get("attribution") else ""))
        if a.get("detail"):
            print(f"       detail  {_wrap_indent(a['detail'], 15)}")
        if a.get("grants"):
            print(f"       risk    {_wrap_indent(a['grants'], 15)}")
        print(f"       ACTION  {_wrap_indent(a['action'], 15)}")
        if a.get("not_fixed_by"):
            print(term.c(f"       NOTE    {_wrap_indent(a['not_fixed_by'], 15)}",
                         "red"))


def print_mes_manifest(mes: dict):
    """What was collected, what was read, and what was left on the floor."""
    if not mes or not mes.get("manifest"):
        return
    print()
    _hdr("EVIDENCE COLLECTION (Microsoft-Extractor-Suite)")
    print(f"  Files seen: {mes.get('files_seen', 0)}")
    print()
    print(f"  {'source':<22} {'files':>6} {'rows':>8}  status")
    print("  " + "-" * 60)
    for m in mes["manifest"]:
        if m["consumed"]:
            status = "read"
        elif m.get("routed_to"):
            status = "read by %s" % m["routed_to"].split(".")[-1]
        else:
            status = "collected, not yet used"
        row = (f"  {m['kind']:<22} {m['files']:>6} {m['rows']:>8}  {status}")
        print(row if m["consumed"] else term.c(row, "dim")
              if hasattr(term, "c") else row)
    if mes.get("unrecognised_count"):
        print()
        print(term.c(f"  [!] {mes['unrecognised_count']} file(s) not "
                     "recognised and not read:", "yellow"))
        for n in mes.get("unrecognised", [])[:8]:
            print(f"        {n}")



def print_directory(dir_summary: dict):
    """Tenant facts, and configuration nothing accounts for.

    Two different things share this section because they come from the same
    export and answer adjacent questions: who really works here (which
    replaces two inferences the scorer would otherwise make), and what the
    mailbox is configured to do that the audit log never saw being set up.
    """
    d = dir_summary or {}
    if not d.get("available"):
        return
    print()
    _hdr("TENANT DIRECTORY AND MAILBOX CONFIGURATION")

    info = d.get("directory") or {}
    if info.get("users"):
        print(f"  Directory accounts:      {info['users']} "
              f"({info.get('enabled', 0)} enabled)")
        print(f"  Addresses indexed:       {info.get('addresses_indexed', 0)} "
              f"across {info.get('distinct_names', 0)} distinct display name(s)")
        doms = info.get("accepted_domains") or []
        if doms:
            print(f"  Tenant domains:          {', '.join(doms[:8])}"
                  + (f"  (+{len(doms) - 8} more)" if len(doms) > 8 else ""))
            print("  " + _wrap_indent(
                "These replace the internal domains inferred from traffic. A "
                "colleague who rarely emails this mailbox is now internal by "
                "fact rather than external by omission.", 2))

    drift = d.get("drift") or {}
    if not drift.get("available"):
        return

    print()
    print(f"  Inbox rules seen:        {drift.get('rules_seen', 0)}"
          f"    delegations: {drift.get('permissions_seen', 0)}"
          f"    transport rules: {drift.get('transport_rules_seen', 0)}")

    unexplained = drift.get("unexplained_rules") or []
    transport = drift.get("unexplained_transport_rules") or []
    delegations = [x for x in (drift.get("delegations") or []) if x["external"]]

    if not (unexplained or transport or delegations):
        print()
        print("  Nothing in the current configuration is unaccounted for.")
        return

    total = len(unexplained) + len(transport) + len(delegations)
    print()
    print(term.c(f"  {total} configuration item(s) exist now but were never "
                 "recorded being created:", "yellow", "bold"))

    for rule in unexplained:
        print()
        label = f"  RULE      {rule['name']}"
        if rule.get("mailbox"):
            label += f"  [{rule['mailbox']}]"
        print(term.c(label, "red" if rule.get("external_forwards") else "yellow"))
        if rule.get("external_forwards"):
            print(term.c("      forwards outside the tenant: "
                         + ", ".join(rule["external_forwards"]), "red"))
        elif rule.get("forwards"):
            print("      forwards to " + ", ".join(rule["forwards"]))
        if rule.get("move_to"):
            print(f"      moves to '{rule['move_to']}'")
        if rule.get("delete"):
            print("      deletes matching mail")
        if rule.get("keywords"):
            print("      keywords: " + ", ".join(rule["keywords"][:8]))

    for t in transport:
        print()
        print(term.c(f"  TRANSPORT {t['name']}  (tenant-wide)", "red"))
        if t.get("redirects_to"):
            print(term.c("      redirects/copies to: "
                         + ", ".join(t["redirects_to"]), "red"))

    for dele in delegations:
        print()
        print(term.c(f"  DELEGATE  {dele['trustee']} -> {dele['mailbox']}", "red"))
        print(f"      rights: {dele['rights']}")

    print()
    print("  " + _wrap_indent(drift.get("note", ""), 2))


def print_summary(
    records: list[EmailRecord],
    timeline: list[AttackTimelineEvent],
    precursor_verdict: dict,
):

    records_sorted = sorted(records, key=candidate_sort_key)
 
    print()
    print(term.c("=" * 80, "cyan"))
    print(term.c("BEC / PHISHING FORENSIC ANALYSIS", "cyan", "bold"))
    print(term.c("=" * 80, "cyan"))
 
    print(
        f"Emails analyzed: {len(records)}"
    )
 
    senders = {
        r.sender_email
        for r in records
        if r.sender_email
    }
 
    domains = {
        r.sender_domain
        for r in records
        if r.sender_domain
    }
 
    campaigns = {
        r.campaign_id
        for r in records
        if r.campaign_id
    }
 
    print(
        f"Unique senders:  {len(senders)}"
    )
 
    print(
        f"Sender domains:  {len(domains)}"
    )
 
    print(
        f"Campaigns found:  {len(campaigns)}"
    )
 
    print()
    print(term.c("EARLIEST MALICIOUS PRECURSOR VERDICT", "cyan", "bold"))
    print(term.c("-" * 80, "cyan"))
    _pv = precursor_verdict.get("verdict", "")
    _vc = ("green",) if "NO_" in _pv or "NOT" in _pv else ("red", "bold")
    print("Verdict:    " + term.c(_pv, *_vc))
    print("Confidence: " + _confidence_c(precursor_verdict.get("confidence", "")))
    if precursor_verdict.get("message_path"):
        print("Message:    " + precursor_verdict.get("message_path", ""))
        print("Timestamp:  " + precursor_verdict.get("timestamp", ""))
        print("Stage:      " + precursor_verdict.get("stage", ""))
        print("Subject:    " + precursor_verdict.get("subject", ""))
    print("Reason:     " + precursor_verdict.get("reason", ""))
 
    print()
    print("ATTACK TIMELINE")
    print("-" * 80)
    # Audit events are always shown. They are the recorded facts of the case,
    # and on a large corpus a plain head-50 cut would drop every one of them
    # behind the message volume.
    # Recorded-fact events are never crowded out by the message cap: they are
    # the entries an analyst reads the timeline for.
    _recorded = ("audit", "persistence")
    shown = [e for e in timeline if getattr(e, "source", "message") in _recorded]
    for event in timeline:
        if len(shown) >= 50:
            break
        if getattr(event, "source", "message") not in _recorded:
            shown.append(event)
    shown.sort(key=lambda e: timeline.index(e))
    omitted = len(timeline) - len(shown)
    for event in shown:
        _src = getattr(event, "source", "message")
        if _src in _recorded:
            who = event.actor or "unknown account"
            where = f" from {event.client_ip}" if event.client_ip else ""
            _tag, _colour = (("AUDIT", "magenta") if _src == "audit"
                             else ("IDENT", "red"))
            line = (f"{event.timestamp or '(unknown)':25} | {event.stage:28} | "
                    f"{term.c(_tag, _colour, 'bold')}    | {event.subject}"
                    f"  [{who}{where}]")
            print(line)
            for detail in event.evidence[:3]:
                print(f"{'':25} | {'':28} |          - {detail}")
        else:
            print(f"{event.timestamp or '(unknown)':25} | {event.stage:28} | "
                  f"score={event.score:3} | {event.path}")
    if omitted > 0:
        print(f"{'':25} | ... {omitted} further message event(s) omitted; "
              "the JSON report carries the full timeline")
 
    print()
    print("TOP CANDIDATE EMAILS")
    print("-" * 80)
 
    for rank, record in enumerate(
        records_sorted[:20],
        1,
    ):
 
        date = (
            record.date
            or "(no date)"
        )
 
        sender = (
            record.sender_email
            or "(unknown sender)"
        )
 
        print()

        _tier = getattr(record, "tier", 3)
        _head = f"{rank:2}. SCORE {record.score:3} | {date} | {sender}"
        if getattr(record, "tier", 3) == 1:
            _head += "  [TIER 1]"
        print(term.c(_head, *term.tier_color(_tier)))
 
        print(
            f"    Subject: {record.subject or '(no subject)'}"
        )
 
        print(
            f"    File:    {record.path}"
        )
 
        if getattr(record, "campaign_id", None):
 
            print(
                f"    Campaign: {record.campaign_id} "
                f"(score {record.campaign_score}, "
                f"similarity {record.campaign_similarity:.2f})"
            )
 
        if record.likely_precursor:
 
            print(
                "    *** POSSIBLE PRECURSOR ***"
            )
 
        prov_by_signal = {
            p.get("signal"): p for p in (record.provenance or [])
        }

        for indicator in (
            record.indicators[:10]
        ):

            p = prov_by_signal.get(indicator)
            if p:
                sev = p.get('severity', 'low')
                tag = f"  [{p.get('source', '?')}"
                if p.get("weight"):
                    tag += f" +{p['weight']}"
                tag += f" | {sev}]"
                tag = term.c(tag, *term.severity_color(sev))
            else:
                tag = ""

            print(
                f"    - {indicator}{tag}"
            )
 
        if record.urls:
 
            print("    URLs:")
 
            for url in record.urls[:5]:
 
                print(
                    f"      {url}"
                )
 
        snippet = evidence_snippet(
            record
        )
 
        if snippet:
 
            print()
            print("    Evidence:")
 
            print(
                "    "
                + snippet.replace(
                    "\n",
                    "\n    ",
                )
            )
 
    print()
    _hdr("IMPORTANT")
 
    print(
        "Scores are heuristic investigation priorities, "
        "not proof of compromise."
    )
 
    print(
        "Campaign clustering identifies related messages, "
        "not confirmed attacker infrastructure."
    )
 
    print(
        "Validate candidates against mail-server logs, "
        "authentication logs, identity-provider logs, "
        "endpoint telemetry, and original headers."
    )
 
 
def generate_html(
    records: list[EmailRecord],
    campaigns: list[CampaignInfo],
    output: Path,
    timeline: list[AttackTimelineEvent],
    precursor_verdict: dict,
):
 
    records_sorted = sorted(records, key=candidate_sort_key)
 
    campaign_rows = []
 
    for campaign in campaigns:
 
        campaign_rows.append(
            f"""
            <tr>
                <td><strong>{html.escape(campaign.campaign_id)}</strong></td>
                <td><strong>{campaign.campaign_score}</strong></td>
                <td>{html.escape(campaign.confidence.upper())}</td>
                <td>{campaign.message_count}</td>
                <td>{html.escape(campaign.first_seen)}</td>
                <td>{html.escape(campaign.last_seen)}</td>
                <td>{html.escape(", ".join(campaign.sender_domains))}</td>
                <td>{html.escape(", ".join(campaign.url_domains))}</td>
                <td>{html.escape(campaign.likely_origin)}</td>
            </tr>
            """
        )
 
    rows = []
 
    for record in records_sorted:
 
        indicators = (
            "<ul>"
            + "".join(
                f"<li>{html.escape(i)}</li>"
                for i in record.indicators
            )
            + "</ul>"
        )
 
        urls = "<br>".join(
            html.escape(u)
            for u in record.urls
        )
 
        snippet = html.escape(
            evidence_snippet(
                record,
                1000,
            )
        )
 
        precursor = (
            '<span class="precursor">'
            'POSSIBLE PRECURSOR'
            '</span>'
            if record.likely_precursor
            else ""
        )
 
        campaign = html.escape(
            record.campaign_id
        )
 
        rows.append(
            f"""
            <tr>
                <td>
                    <strong>{record.score}</strong>
                    <br>
                    {precursor}
                </td>
 
                <td>
                    {campaign}
                    <br>
                    {record.campaign_score}
                </td>
 
                <td>
                    {html.escape(record.date)}
                </td>
 
                <td>
                    {html.escape(record.sender_email)}
                </td>
 
                <td>
                    {html.escape(record.subject)}
                </td>
 
                <td>
                    {html.escape(record.path)}
                </td>
 
                <td>
                    {indicators}
                </td>
 
                <td>
                    {urls}
                </td>
 
                <td>
                    <pre>{snippet}</pre>
                </td>
            </tr>
            """
        )
 
    document = f"""<!doctype html>
 
<html>
 
<head>
 
<meta charset="utf-8">
 
<title>BEC Forensic Analysis</title>
 
<style>
 
body {{
    font-family: Arial, sans-serif;
    margin: 30px;
    background: #f5f5f5;
}}
 
h1, h2 {{
    color: #222;
}}
 
table {{
    border-collapse: collapse;
    width: 100%;
    background: white;
    margin-bottom: 40px;
}}
 
th, td {{
    border: 1px solid #ccc;
    padding: 8px;
    vertical-align: top;
    text-align: left;
}}
 
th {{
    background: #222;
    color: white;
    position: sticky;
    top: 0;
}}
 
tr:nth-child(even) {{
    background: #fafafa;
}}
 
pre {{
    white-space: pre-wrap;
    max-width: 500px;
}}
 
.precursor {{
    background: #b00020;
    color: white;
    padding: 3px 5px;
    font-size: 11px;
    font-weight: bold;
}}
 
ul {{
    margin-top: 0;
}}
 
.high {{
    color: #b00020;
    font-weight: bold;
}}
 
.medium {{
    color: #b36b00;
    font-weight: bold;
}}
 
.low {{
    color: #555;
}}
 
 
.progress-panel{{border:1px solid #d7dce3;border-radius:10px;padding:14px;background:#f8fafc;margin:12px 0 24px}}
.progress-row{{display:flex;justify-content:space-between;gap:12px;margin-bottom:8px}}
.progress-track{{height:10px;border-radius:999px;background:#e4e7ec;overflow:hidden}}
.progress-fill{{height:100%;border-radius:999px;background:#475467;transition:width .25s ease}}
.progress-stats{{display:flex;gap:18px;flex-wrap:wrap;margin-top:8px;font-size:12px;color:#667085}}
</style>
 
</head>
 
<body>
 
<h1>BEC / Phishing Forensic Analysis</h1>
 
<p>
<strong>Emails analyzed:</strong>
{len(records)}
</p>
 
<p>
<strong>Campaigns identified:</strong>
{len(campaigns)}
</p>
 
<p>
The ranking is heuristic and intended to prioritize forensic review.
It does not establish that an email is malicious.
</p>
 
 
<h2>Campaign Clusters</h2>
 
<table>
 
<thead>
 
<tr>
<th>Campaign</th>
<th>Score</th>
<th>Confidence</th>
<th>Messages</th>
<th>First Seen</th>
<th>Last Seen</th>
<th>Sender Domains</th>
<th>URL Domains</th>
<th>Likely Origin</th>
</tr>
 
</thead>
 
<tbody>
 
{''.join(campaign_rows)}
 
</tbody>
 
</table>
 
 
 
<h2>Live Analysis Progress</h2>
<div class="progress-panel">
  <div class="progress-row">
    <span id="progressPhase">Analysis complete</span>
    <strong id="progressPercent">100%</strong>
  </div>
  <div class="progress-track"><div id="progressFill" class="progress-fill" style="width:100%"></div></div>
  <div class="progress-stats">
    <span>Messages: {len(timeline)}</span>
    <span>URLs: {sum(len(r.urls) for r in records)}</span>
    <span>Attachments: {sum(len(r.attachments) for r in records)}</span>
  </div>
</div>
 
<h2>Candidate Messages</h2>
 
<table>
 
<thead>
 
<tr>
<th>Email Score</th>
<th>Campaign</th>
<th>Date</th>
<th>Sender</th>
<th>Subject</th>
<th>File</th>
<th>Indicators</th>
<th>URLs</th>
<th>Evidence</th>
</tr>
 
</thead>
 
<tbody>
 
{''.join(rows)}
 
</tbody>
 
</table>
 
</body>
 
</html>
"""
 
    output.write_text(
        document,
        encoding="utf-8",
    )
 
 
def write_csv(records: list[EmailRecord], output: Path):
    """Per-message CSV with all timestamps normalized to UTC, sorted
    chronologically. One row per email; group by `date_utc_day` for a daily view."""
    columns = [
        "date_utc", "date_utc_day", "date_original",
        "tier", "is_inbound",
        "sender_email", "sender_domain", "sender_name",
        "subject",
        "priority_score", "initial_email_score", "attack_stage",
        "likely_precursor", "is_pre_compromise",
        "authentication_failed", "auth_anomaly", "self_spoofing",
        "reply_to_mismatch", "lookalike_of", "sending_ip_anomaly", "origin_ip",
        "thread_injection", "display_name_spoof", "deleted_or_moved", "hidden_folder",
        "attachment_threat", "attachment_threat_note",
        "sender_established", "sender_first_contact",
        "anchor_matches", "campaign_id", "campaign_score",
        "url_count", "attachment_count",
        "urls", "indicators", "path",
    ]

    def sort_key(record):
        iso, _ = to_utc_fields(record.date)
        # Unparseable dates sort last but stay in the export.
        return (iso == "", iso, record.path)

    with output.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        for record in sorted(records, key=sort_key):
            date_utc, date_day = to_utc_fields(record.date)
            writer.writerow([
                date_utc,
                date_day,
                record.date,
                record.tier,
                record.is_inbound,
                record.sender_email,
                record.sender_domain,
                record.sender_name,
                record.subject,
                record.score,
                record.scenario_score,
                classify_attack_stage(record),
                record.likely_precursor,
                record.is_pre_compromise,
                record.authentication_failed,
                record.auth_anomaly,
                record.self_spoofing,
                record.reply_to_mismatch,
                record.lookalike_of,
                record.sending_ip_anomaly,
                record.origin_ip,
                record.thread_injection,
                record.display_name_spoof,
                record.deleted_or_moved,
                record.hidden_folder,
                record.attachment_threat,
                record.attachment_threat_note,
                record.sender_established,
                record.sender_first_contact,
                "; ".join(record.anchor_matches),
                record.campaign_id,
                record.campaign_score,
                len(record.urls),
                len(record.attachments),
                " | ".join(record.urls),
                " | ".join(record.indicators),
                record.path,
            ])


def corpus_fingerprint(records):
    """A reproducible fingerprint of the analysed corpus. Uses per-file SHA-256
    when available (content-hash mode), else (path, size, mtime) metadata."""
    parts = []
    content_based = True
    for r in sorted(records, key=lambda x: x.path):
        file_hash = getattr(r, "_cache_file_sha256", "") or ""
        if file_hash:
            parts.append(f"{r.path}:{file_hash}")
        else:
            content_based = False
            try:
                st = os.stat(r.path)
                parts.append(f"{r.path}:{st.st_size}:{st.st_mtime_ns}")
            except OSError:
                parts.append(f"{r.path}:?")
    digest = hashlib.sha256("\n".join(parts).encode("utf-8", "replace")).hexdigest()
    return digest, ("content" if content_based else "metadata")


def _command_line() -> str:
    """Reconstruct the invocation for the manifest. When launched as a package
    (`python -m postmortem`), argv[0] is the absolute __main__.py path; render
    the clean module form instead."""
    argv0 = sys.argv[0] or ""
    if argv0.replace("\\", "/").endswith("postmortem/__main__.py"):
        return " ".join(["python", "-m", "postmortem", *sys.argv[1:]])
    return " ".join(sys.argv)


def build_run_manifest(args, records, scenario, anchors, initial_verdict,
                       campaigns, iocs, generated_utc, elapsed_seconds,
                       phase_timings=None, host=None, entry_point_window=None,
                       audit_summary=None, completeness=None,
                       signin_summary=None, mes_bundle=None):
    """Reproducibility / chain-of-custody metadata recorded in every report."""
    digest, basis = corpus_fingerprint(records)
    tier_counts = Counter(r.tier for r in records)
    timings = {}
    for label, seconds in (phase_timings or []):
        timings[label] = round(timings.get(label, 0.0) + seconds, 2)
    return {
        # Where the run spent its time, and on what hardware. Two runs of the
        # same corpus that differ wildly in duration are usually explained by
        # one of these, so both belong in the manifest.
        "phase_timings_seconds": timings,
        "host": host or "",
        # The period the entry point was searched in. "No entry point found"
        # means something different depending on how far back the search
        # reached, so the window is part of the record.
        "entry_point_window": entry_point_window or {},
        # Provenance of the audit evidence. A conclusion drawn from a log is
        # bounded by that log, so the log's own range, operation mix and known
        # gaps belong in the chain-of-custody record alongside the corpus
        # hash -- otherwise a reader cannot tell what the run could not see.
        "audit_log": _audit_provenance(args, audit_summary),
        # The same argument as the audit log, for the identity-side
        # evidence: a conclusion about whether the attacker still has
        # access is bounded by which of these were actually collected,
        # and a reader cannot tell that from the findings alone.
        "evidence_sources": _evidence_provenance(
            args, signin_summary, mes_bundle),
        # A completeness statement about the evidence, recorded beside the
        # corpus hash. The hash says what was analysed; this says what was
        # missing from it and could not be.
        "corpus_completeness": _completeness_block(completeness),
        "tool": "postmortem",
        "tool_version": TOOL_VERSION,
        "parser_version": PARSER_VERSION,
        "generated_utc": generated_utc,
        "elapsed_seconds": round(elapsed_seconds, 2),
        "command_line": _command_line(),
        "scenario_profile": scenario,
        "effective_config": CONFIG,
        "corpus": {
            "directory": str(getattr(args, "directory", "")),
            "message_count": len(records),
            "corpus_sha256": digest,
            "hash_basis": basis,
        },
        "parameters": {
            "candidate_threshold": getattr(args, "candidate_threshold", None),
            "campaign_threshold": getattr(args, "campaign_threshold", None),
            "screen_chars": getattr(args, "screen_chars", None),
            "html_limit": getattr(args, "html_limit", None),
            "content_hash": getattr(args, "content_hash", None),
            "workers": getattr(args, "workers", None),
        },
        "anchors_supplied": {
            "compromise_date": anchors.compromise_date.isoformat() if anchors.compromise_date else None,
            "victim_domains": anchors.victim_domains,
            "impersonated": anchors.impersonated,
            "fraud_accounts_count": len(anchors.fraud_accounts),
            "attacker_domains": anchors.attacker_domains,
            "attacker_ips": anchors.attacker_ips,
            "attacker_addresses": anchors.attacker_addresses,
            "rule_keywords": anchors.rule_keywords,
        },
        "counts": {
            "tier1": tier_counts.get(1, 0),
            "tier2": tier_counts.get(2, 0),
            "tier3": tier_counts.get(3, 0),
            "campaigns": len(campaigns),
            "iocs": len(iocs or []),
            "initial_email_verdict": (initial_verdict or {}).get("verdict"),
            "initial_email_confidence": (initial_verdict or {}).get("confidence"),
        },
    }


def _completeness_block(c):
    if not c:
        return {"assessed": False,
                "note": "No audit log, so corpus completeness cannot be assessed."}
    if not c.get("reliable"):
        return {
            "assessed": False,
            "note": ("The audit log names %d message(s), none of which are in "
                     "this corpus; the log and the export do not correspond."
                     % c.get("messages_named_by_log", 0)),
        }
    return {
        "assessed": True,
        "deleted_recorded": c.get("deleted_total", 0),
        "deleted_still_present": c.get("deleted_still_present", 0),
        "deleted_absent": c.get("deleted_absent", 0),
        "deleted_absent_by_attacker": c.get("deleted_absent_by_attacker", 0),
        # The ids and what the log retained about them, so a later reader can
        # tell exactly which items this analysis never saw.
        "absent_items": c.get("absent", []),
    }



def _evidence_provenance(args, signin_summary, mes_bundle):
    """Which identity-side sources were supplied, and what each contained.

    Recorded whether or not they were supplied: "no OAuth grant export" is a
    fact about the investigation that a later reader needs, and its absence
    from the manifest would read as if the question had been answered.
    """
    out = {
        "signin_logs": {
            "supplied": bool(signin_summary),
            "path": str(getattr(args, "signin_logs", "") or ""),
        },
        "collection": {
            "path": str(getattr(args, "mes_dir", "") or ""),
            "supplied": bool(mes_bundle),
        },
    }
    if signin_summary:
        cov = dict(signin_summary.get("coverage") or {})
        out["signin_logs"].update({
            "records": signin_summary.get("records", 0),
            "coverage": cov,
            "device_code_records": signin_summary.get("device_code_records", 0),
            "attacker_ips_contributed": signin_summary.get("attacker_ips", []),
            "earliest_token": signin_summary.get("earliest_token", ""),
            "warnings": signin_summary.get("warnings", []),
        })
    if mes_bundle:
        out["collection"].update({
            "files_seen": mes_bundle.get("files_seen", 0),
            "sources": [
                {k: m[k] for k in ("kind", "files", "rows", "consumed")}
                for m in (mes_bundle.get("manifest") or [])
            ],
            "unrecognised": mes_bundle.get("unrecognised_count", 0),
        })
    return out


def _audit_provenance(args, audit_summary):
    path = str(getattr(args, "audit_log", "") or "")
    if not audit_summary:
        return {"supplied": bool(path), "path": path}
    cov = dict(audit_summary.get("coverage") or {})
    for k in ("_first_dt", "_last_dt"):
        cov.pop(k, None)
    return {
        "supplied": True,
        "path": path,
        "coverage": cov,
        "warnings": audit_summary.get("coverage_warnings") or [],
    }


def print_run_manifest(manifest):
    print()
    _hdr("RUN MANIFEST (reproducibility / chain of custody)")
    c = manifest["corpus"]
    print(f"Tool: postmortem {manifest['tool_version']} (parser {manifest['parser_version']})")
    print(f"Generated (UTC): {manifest['generated_utc']}   Elapsed: {manifest['elapsed_seconds']}s")
    print(f"Corpus: {c['message_count']} messages | SHA-256 ({c['hash_basis']}): {c['corpus_sha256']}")
    print(f"Scenario: {manifest['scenario_profile']}   Command: {manifest['command_line']}")
    a = manifest.get("audit_log") or {}
    if a.get("supplied") and a.get("coverage"):
        cov = a["coverage"]
        print(f"Audit log: {cov.get('events_parsed', 0)} events, "
              f"{cov.get('first_event', '?')} to {cov.get('last_event', '?')}"
              f" ({cov.get('span_days', 0)}d)"
              + (f" | {len(a['warnings'])} coverage warning(s)"
                 if a.get("warnings") else ""))
        cc = manifest.get("corpus_completeness") or {}
        if cc.get("assessed") and cc.get("deleted_absent"):
            print(f"Corpus completeness: {cc['deleted_absent']} deleted "
                  f"message(s) absent from this export"
                  + (f" ({cc['deleted_absent_by_attacker']} by the attacker)"
                     if cc.get("deleted_absent_by_attacker") else ""))
        elif cc.get("assessed"):
            print("Corpus completeness: no recorded deletion is missing from "
                  "this export")
    elif a.get("supplied"):
        print("Audit log: supplied but no events were parsed")
    else:
        print("Audit log: none supplied - every attacker action below is "
              "inferred from message content alone")


def write_json(
    records: list[EmailRecord],
    campaigns: list[CampaignInfo],
    timeline: list[AttackTimelineEvent],
    precursor_verdict: dict,
    output: Path,
    initial_verdict: Optional[dict] = None,
    iocs: Optional[list] = None,
    manifest: Optional[dict] = None,
):

    data = {
        "manifest": manifest or {},

        "summary": {
            "emails_analyzed": len(records),
            "campaigns_identified": len(
                campaigns
            ),
            "earliest_malicious_precursor_verdict": precursor_verdict,
            "initial_compromise_verdict": initial_verdict or {},
        },

        "initial_compromise": initial_verdict or {},

        "iocs": iocs or [],

        "mitre_attack": mitre_summary(records),

        "top_flagged_domains": top_flagged_domains(records),

        "attack_timeline": [asdict(x) for x in timeline],

        "earliest_malicious_precursor": precursor_verdict or {},
        "evidence_graph": build_evidence_graph(records),
 
        "campaigns": [
            asdict(campaign)
            for campaign in campaigns
        ],
 
        "emails": [
            asdict(record)
            for record in sorted(
                records,
                key=lambda r: (
                    -r.score,
                    date_sort_key(r),
                ),
            )
        ],
    }
 
    output.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def _html_slim_urls(record):
    """Deduped, risky-first, capped URL analysis for the HTML payload only."""
    analyses = []
    for a in (record.url_analysis or []):
        analyses.append({
            "original": a.get("url") or a.get("original") or a.get("normalized") or "",
            "suspicious_score": a.get("suspicious_score", a.get("risk_score", 0)) or 0,
            "registrable_domain": a.get("registrable_domain", "") or "",
            "hostname": a.get("hostname", "") or "",
            "indicators": list((a.get("indicators") or a.get("flags") or []))[:8],
        })
    analyses.sort(key=lambda a: -int(a["suspicious_score"] or 0))
    seen, slim = set(), []
    for a in analyses:
        key = a["registrable_domain"] or a["original"]
        if key in seen:
            continue
        seen.add(key)
        slim.append(a)
        if len(slim) >= _HTML_URL_CAP:
            break
    urls = list(dict.fromkeys(record.urls or []))[:_HTML_URL_CAP]
    return urls, slim


def _html_record(record):
    auth = record.authentication_results or {}
    urls, url_analysis = _html_slim_urls(record)
    attachments = [
        {
            "filename": a.get("filename", "") if isinstance(a, dict) else str(a),
            "content_type": a.get("content_type", "") if isinstance(a, dict) else "",
            "size": a.get("size", 0) if isinstance(a, dict) else 0,
            "sha256": a.get("sha256", "") if isinstance(a, dict) else "",
            "flags": a.get("attachment_flags", []) if isinstance(a, dict) else [],
        }
        for a in (record.attachment_details or [])
    ]
    return {
        "path": record.path, "sender": record.sender_email,
        "sender_domain": record.sender_domain, "subject": record.subject,
        "date": record.date, "score": record.score, "tier": record.tier,
        "initial_score": record.scenario_score,
        "campaign_id": record.campaign_id, "campaign_score": record.campaign_score,
        "likely_precursor": record.likely_precursor,
        "indicators": list(record.indicators or [])[:15],
        "provenance": [
            {k: p.get(k) for k in ("signal", "source", "weight", "severity", "matched")}
            for p in (record.provenance or [])[:20]
        ],
        "urls": urls, "url_analysis": url_analysis,
        "attachments": list(record.attachments or [])[:_HTML_URL_CAP],
        "attachment_details": attachments,
        "authentication": {
            "spf_fail": bool(auth.get("spf_fail")),
            "dkim_fail": bool(auth.get("dkim_fail")),
            "dmarc_fail": bool(auth.get("dmarc_fail")),
        },
        "snippet": evidence_snippet(record, _HTML_SNIPPET),
        "preview": _defang(evidence_snippet(record, _HTML_SNIPPET)),
        "mitre": mitre_for_record(record),
    }


def top_flagged_domains(records, limit=15):
    """Group flagged (Tier 1/2) messages by sender domain so a campaign shows as
    one row instead of many. Sorted by highest tier, then total score."""
    agg = {}
    for r in records:
        if r.tier not in (1, 2):
            continue
        dom = r.sender_domain or "(none)"
        a = agg.get(dom)
        if a is None:
            a = agg[dom] = {"domain": dom, "messages": 0, "highest_tier": 3,
                            "total_score": 0, "senders": set()}
        a["messages"] += 1
        a["highest_tier"] = min(a["highest_tier"], r.tier)
        a["total_score"] += r.score
        if r.sender_email:
            a["senders"].add(r.sender_email)
    rows = [{"domain": a["domain"], "messages": a["messages"],
             "highest_tier": a["highest_tier"], "total_score": a["total_score"],
             "sender_count": len(a["senders"]),
             "senders": sorted(a["senders"])[:8]}
            for a in agg.values()]
    rows.sort(key=lambda x: (x["highest_tier"], -x["total_score"]))
    return rows[:limit]


def print_top_domains(rows):
    """Console 'top flagged domains' table."""
    if not rows:
        return
    print()
    print(term.c("=" * 80, "cyan"))
    print(term.c("TOP FLAGGED DOMAINS", "cyan", "bold"))
    print(term.c("=" * 80, "cyan"))
    print(f"  {'DOMAIN':<34} {'MSGS':>4} {'TIER':>4} {'SCORE':>6}  SENDERS")
    for r in rows:
        tier = r["highest_tier"]
        dom = term.c(f"{r['domain'][:34]:<34}", *term.tier_color(tier))
        senders = ", ".join(r["senders"][:3])
        if r["sender_count"] > 3:
            senders += f" (+{r['sender_count'] - 3})"
        print(f"  {dom} {r['messages']:>4} {('T'+str(tier)):>4} "
              f"{r['total_score']:>6}  {senders}")


def build_entity_graph(records_subset, cap_nodes=150):
    """Build a node-link graph of the entities that connect suspect messages -
    senders, domains, attachment hashes, campaigns, and (when geolocated) ASNs
    and countries - so shared infrastructure across a batch is visible at a
    glance. Capped to the highest-degree nodes to keep the render legible."""
    nodes, links = {}, {}

    def node(nid, label, ntype):
        n = nodes.get(nid)
        if n is None:
            n = nodes[nid] = {"id": nid, "label": label, "type": ntype, "weight": 0}
        n["weight"] += 1
        return nid

    def link(a, b, ltype):
        if not a or not b or a == b:
            return
        key = (a, b) if a < b else (b, a)
        e = links.get(key)
        if e is None:
            e = links[key] = {"source": key[0], "target": key[1],
                              "type": ltype, "count": 0}
        e["count"] += 1

    for r in records_subset:
        s = node("sender:" + r.sender_email, r.sender_email, "sender") \
            if r.sender_email else None
        if r.sender_domain:
            link(s, node("domain:" + r.sender_domain, r.sender_domain, "domain"),
                 "sender-domain")
        for ud in (r.url_domains or [])[:5]:
            if ud:
                link(s, node("domain:" + ud, ud, "domain"), "url-domain")
        for a in (r.attachment_details or []):
            h = a.get("sha256") if isinstance(a, dict) else None
            if h:
                label = (a.get("filename") or h[:10]) if isinstance(a, dict) else h[:10]
                link(s, node("hash:" + h, label, "hash"), "attachment")
        if r.campaign_id:
            link(s, node("camp:" + r.campaign_id, r.campaign_id, "campaign"),
                 "campaign")
        if r.origin_asn:
            link(s, node("asn:" + r.origin_asn, r.origin_org or r.origin_asn, "asn"),
                 "asn")
        if r.origin_country:
            link(s, node("cc:" + r.origin_country, r.origin_country, "country"),
                 "country")

    ranked = sorted(nodes.values(), key=lambda n: -n["weight"])
    keep = {n["id"] for n in ranked[:cap_nodes]}
    return {
        "nodes": [n for n in ranked if n["id"] in keep],
        "links": [e for e in links.values()
                  if e["source"] in keep and e["target"] in keep],
    }


def generate_html_interactive(records, campaigns, output, timeline, precursor_verdict, initial_verdict=None, limit=1000):
    # A: embed only the investigation subset (top-N by score), plus any message
    # named by the initial-email verdict so the key finding is always present.
    # The full dataset remains in the JSON/CSV reports.
    ranked = sorted(records, key=candidate_sort_key)
    if limit and limit > 0:
        subset = ranked[:limit]
    else:
        subset = ranked
    keep_paths = {r.path for r in subset}

    verdict_paths = set()
    if initial_verdict:
        chosen = initial_verdict.get("initial_email") or {}
        if chosen.get("path"):
            verdict_paths.add(chosen["path"])
        for item in initial_verdict.get("shortlist", []):
            if item.get("path"):
                verdict_paths.add(item["path"])
    # Always embed Tier-1 prime suspects and any verdict-named message, even if
    # they fall outside the top-N-by-score cut.
    for record in records:
        if record.path in keep_paths:
            continue
        if record.tier == 1 or record.path in verdict_paths:
            subset.append(record)
            keep_paths.add(record.path)

    graph = build_evidence_graph(subset)

    def event_sort_key(event):
        dt = parse_date(getattr(event, "timestamp", "") or "")
        return dt or datetime.max.replace(tzinfo=timezone.utc)

    sub_events = sorted(
        # Recorded-fact events carry no message path, so the record filter
        # would drop all of them; they are always kept.
        (e for e in timeline
         if getattr(e, "source", "message") in ("audit", "persistence")
         or e.path in keep_paths),
        key=event_sort_key,
    )

    payload = {
        'events': [asdict(e) for e in sub_events],
        'records': [_html_record(r) for r in subset],
        'campaigns': [asdict(c) for c in campaigns],
        'precursor': precursor_verdict,
        'initial': initial_verdict or {},
        'graph': graph,
        'network': build_entity_graph(subset),
        'top_domains': top_flagged_domains(records),
        'total_records': len(records),
        'shown_records': len(subset),
    }
    data = json.dumps(payload, ensure_ascii=False).replace('</', '<\\/')
    html_doc = r"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BEC / Phishing Forensic Investigation</title>
<style>
:root{--bg:#f4f6f8;--panel:#fff;--text:#17212b;--muted:#667085;--line:#d9dee5;--danger:#b42318;--warn:#b54708}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",sans-serif}.wrap{max-width:1500px;margin:auto;padding:28px}
h1{margin:0 0 6px;font-size:28px}h2{margin:28px 0 12px;font-size:20px}.muted{color:var(--muted)}
.dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0}.metric,.card,.panel{background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px}.metric-label{font-size:11px;color:var(--muted);text-transform:uppercase}.metric-value{font-size:21px;font-weight:750;margin-top:4px}
.controls{position:sticky;top:0;z-index:20;display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:12px;background:rgba(244,246,248,.96);border-bottom:1px solid var(--line)}input,select,button{font:inherit;border:1px solid #cfd5dd;border-radius:8px;background:#fff;padding:8px 10px}#search{min-width:300px;flex:1}button{cursor:pointer}
.verdict{background:#fffaeb;border:1px solid #fedf89;border-radius:12px;padding:16px}.verdict-title{font-weight:800;color:var(--warn)}
.timeline{position:relative;margin:18px 0 30px 8px;padding-left:27px}.timeline:before{content:"";position:absolute;left:6px;top:0;bottom:0;width:3px;background:#d0d5dd}.event{position:relative;margin-bottom:14px}.dot{position:absolute;left:-27px;top:17px;width:13px;height:13px;border-radius:50%;background:#475467;border:3px solid var(--bg)}.selected{box-shadow:0 0 0 3px rgba(23,92,211,.16)!important;border-color:#84adff!important}
.top{display:flex;gap:7px;align-items:center;flex-wrap:wrap}.badge{border-radius:999px;padding:3px 8px;background:#eef2f6;font-size:10px;font-weight:700}.precursor{background:#fee4e2;color:var(--danger)}.meta{display:flex;gap:14px;flex-wrap:wrap;color:var(--muted);font-size:12px}.pivots{display:flex;gap:6px;flex-wrap:wrap;margin:9px 0}.small{font-size:12px}
.inspect{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:10px;margin-top:12px}.inspect section{border:1px solid #eaecf0;border-radius:9px;padding:10px}.evidence{border:1px solid #eaecf0;border-radius:8px;padding:9px;margin:7px 0;overflow-wrap:anywhere}.evidence code{font-size:11px}.indicator{margin:0;padding-left:18px;font-size:12px}.risk{font-size:11px;font-weight:700;color:var(--warn)}.auth-bad{color:var(--danger);font-weight:700}.auth-ok{color:#027a48}
.graph{display:grid;gap:7px}.edge{display:grid;grid-template-columns:1fr auto 1fr 2fr;gap:8px;align-items:center;background:#fff;border:1px solid var(--line);border-radius:8px;padding:9px;font:11px ui-monospace,monospace}.edge.strong{border-left:4px solid var(--warn)}.edge.contextual{border-left:4px solid #98a2b3}.edge-label{color:var(--muted)}
.table-wrap{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:12px}table{border-collapse:collapse;width:100%;min-width:1250px}th,td{padding:9px;border-bottom:1px solid #eaecf0;text-align:left;vertical-align:top}th{background:#17212b;color:#fff;position:sticky;top:57px}pre{white-space:pre-wrap;max-width:500px}.empty{text-align:center;padding:28px;color:var(--muted)}.remed{background:#fff;border:1px solid var(--line);border-left:4px solid var(--line);border-radius:8px;padding:10px 12px;margin:8px 0;font-size:13px;line-height:1.5}.remed.hit{border-left-color:#d13438}.remed code{display:block;background:#f6f8fa;border-radius:4px;padding:6px 8px;margin-top:6px;font:11px ui-monospace,monospace;white-space:pre-wrap;word-break:break-word}.remed .warn{color:#d13438;display:block;margin-top:6px}
th.sortable{cursor:pointer;user-select:none}th.sortable::after{content:" \2195";opacity:.45;font-size:10px}details>summary{cursor:pointer;color:var(--muted)}#execSummary li{margin:2px 0}#execSummary .badge{margin:2px 3px 0 0;display:inline-block}
#network svg{width:100%;height:520px;display:block}#network .nlabel{font:10px system-ui,sans-serif;fill:#334;pointer-events:none}#network circle{cursor:pointer;stroke:#fff;stroke-width:1.5}#network line{stroke:#c4ccd6}#netLegend .badge{margin-right:8px}
@media(max-width:800px){.wrap{padding:14px}#search{min-width:180px}.edge{grid-template-columns:1fr}}
</style></head><body><div class="wrap">
<h1>BEC / Phishing Forensic Investigation</h1><p class="muted">Interactive local-only report. URLs are never visited and no external assets are loaded.</p>
<div id="dashboard" class="dashboard"></div>
<h2>Executive Summary</h2><div id="execSummary" class="panel"></div>
<div class="controls"><input id="search" placeholder="Search sender, subject, campaign, URL, SHA-256, or file..." oninput="render()"><select id="stage" onchange="render()"><option value="">All stages</option><option>initial_contact</option><option>social_engineering</option><option>suspicious_link</option><option>credential_harvest</option><option>attachment_delivery</option><option>delivery_or_credential_harvest</option><option>payment_request</option></select><label><input id="onlyPrecursor" type="checkbox" onchange="render()"> Precursors only</label><button onclick="clearFilters()">Clear</button></div>
<h2>Initial Compromise (scenario-anchored)</h2><div id="initial" class="verdict"></div>
<h2>Remediation Required</h2><div id="remediation" class="verdict"></div>
<h2>Attack Narrative (reconstructed)</h2><div id="narrative" class="verdict"></div>
<h2>Earliest Malicious Precursor</h2><div id="verdict" class="verdict"></div>
<h2>Attack Timeline</h2><div id="timeline" class="timeline"></div>
<h2>Evidence Graph</h2><div class="controls" style="position:static;background:transparent;border:0"><label><input id="strongEdges" type="checkbox" checked onchange="toggleEdges()"> Strong pivots</label><label><input id="contextEdges" type="checkbox" checked onchange="toggleEdges()"> Temporal/contextual links</label></div><div id="graph" class="graph"></div>
<h2>Relationship Graph <span class="muted" style="font-size:13px">(shared senders, domains, hashes, campaigns; click a node to pivot)</span></h2>
<div class="controls" style="position:static;background:transparent;border:0"><span id="netLegend" class="small muted"></span><button class="small" onclick="networkGraph()">Re-layout</button></div>
<div id="network" class="table-wrap" style="padding:6px"></div>
<h2>Top Flagged Domains <span class="muted" style="font-size:13px">(Tier 1/2 grouped by sender domain; click to pivot)</span></h2>
<div id="topDomains" class="table-wrap"></div>
<h2>Campaign Clusters</h2><div id="campaigns" class="table-wrap"></div>
<h2>Candidate Messages <span class="muted" style="font-size:13px">(top by score; full set in the JSON/CSV report)</span></h2>
<div class="controls" style="position:static;background:transparent;border:0"><label>Tier <select id="tierFilter" onchange="candidates()"><option value="">All tiers</option><option value="1">Tier 1 — prime suspects</option><option value="2">Tier 2 — secondary</option><option value="3">Tier 3 — rest</option></select></label></div>
<div id="candidates" class="table-wrap"></div>
</div>
<script>
const DATA=__DATA__;
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const js=s=>JSON.stringify(String(s??''));
function rec(path){return DATA.records.find(r=>r.path===path)||{path};}
function render(){dashboard();execSummary();initialPanel();remediationPanel();narrativePanel();verdict();timeline();graph();networkGraph();topDomains();campaigns();candidates();toggleEdges();}
function topDomains(){const el=document.getElementById('topDomains');if(!el)return;const rows=DATA.top_domains||[];if(!rows.length){el.innerHTML='<div class="empty">No flagged domains.</div>';return;}el.innerHTML=`<table><thead><tr><th class="sortable">Domain</th><th class="sortable">Messages</th><th class="sortable">Highest tier</th><th class="sortable">Total score</th><th>Senders</th></tr></thead><tbody>${rows.map(r=>`<tr><td data-pivot="${esc(r.domain)}" style="cursor:pointer"><b>${esc(r.domain)}</b></td><td data-sort-value="${r.messages}">${r.messages}</td><td data-sort-value="${r.highest_tier}"><span class="badge${r.highest_tier===1?' precursor':''}">T${r.highest_tier}</span></td><td data-sort-value="${r.total_score}">${r.total_score}</td><td class="small">${(r.senders||[]).map(esc).join(', ')}${r.sender_count>(r.senders||[]).length?` (+${r.sender_count-(r.senders||[]).length})`:''}</td></tr>`).join('')}</tbody></table>`;el.querySelectorAll('td[data-pivot]').forEach(c=>c.addEventListener('click',()=>pivot(c.getAttribute('data-pivot'))));makeSortable(el.querySelector('table'));}
const NET_COLORS={sender:'#175cd3',domain:'#b54708',hash:'#6941c6',campaign:'#027a48',asn:'#b42318',country:'#475467'};
function networkGraph(){const el=document.getElementById('network');if(!el)return;const g=DATA.network||{nodes:[],links:[]};const nodes=(g.nodes||[]).map(n=>Object.assign({},n));const rawlinks=g.links||[];if(!nodes.length){el.innerHTML='<div class="empty">No entity relationships to graph.</div>';document.getElementById('netLegend').innerHTML='';return;}const W=1100,H=520,idx={};nodes.forEach((n,i)=>{idx[n.id]=i;const a=2*Math.PI*i/nodes.length;n.x=W/2+Math.cos(a)*Math.min(W,H)*0.35;n.y=H/2+Math.sin(a)*Math.min(W,H)*0.35;});const L=rawlinks.map(e=>({s:idx[e.source],t:idx[e.target]})).filter(e=>e.s!=null&&e.t!=null);const k=Math.sqrt((W*H)/nodes.length)*0.5;let temp=W/8;for(let it=0;it<200;it++){for(const n of nodes){n.dx=0;n.dy=0;}for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){let dx=nodes[i].x-nodes[j].x,dy=nodes[i].y-nodes[j].y,d=Math.hypot(dx,dy)||0.01;const f=k*k/d,ux=dx/d,uy=dy/d;nodes[i].dx+=ux*f;nodes[i].dy+=uy*f;nodes[j].dx-=ux*f;nodes[j].dy-=uy*f;}for(const e of L){let dx=nodes[e.s].x-nodes[e.t].x,dy=nodes[e.s].y-nodes[e.t].y,d=Math.hypot(dx,dy)||0.01;const f=d*d/k,ux=dx/d,uy=dy/d;nodes[e.s].dx-=ux*f;nodes[e.s].dy-=uy*f;nodes[e.t].dx+=ux*f;nodes[e.t].dy+=uy*f;}for(const n of nodes){let d=Math.hypot(n.dx,n.dy)||0.01;n.x+=(n.dx/d)*Math.min(d,temp);n.y+=(n.dy/d)*Math.min(d,temp);n.x-=(n.x-W/2)*0.012;n.y-=(n.y-H/2)*0.012;n.x=Math.max(18,Math.min(W-18,n.x));n.y=Math.max(18,Math.min(H-18,n.y));}temp*=0.97;}const maxw=Math.max(1,...nodes.map(n=>n.weight||1));const out=[`<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">`];for(const e of L){out.push(`<line x1="${nodes[e.s].x.toFixed(1)}" y1="${nodes[e.s].y.toFixed(1)}" x2="${nodes[e.t].x.toFixed(1)}" y2="${nodes[e.t].y.toFixed(1)}"/>`);}for(const n of nodes){const r=4+6*Math.sqrt((n.weight||1)/maxw),c=NET_COLORS[n.type]||'#98a2b3';out.push(`<circle cx="${n.x.toFixed(1)}" cy="${n.y.toFixed(1)}" r="${r.toFixed(1)}" fill="${c}" data-pivot="${esc(n.label)}"><title>${esc(n.type)}: ${esc(n.label)} (${n.weight})</title></circle>`);if((n.weight||1)>=2||nodes.length<=40)out.push(`<text class="nlabel" x="${(n.x+r+2).toFixed(1)}" y="${(n.y+3).toFixed(1)}">${esc(String(n.label).slice(0,28))}</text>`);}out.push('</svg>');el.innerHTML=out.join('');el.querySelectorAll('circle[data-pivot]').forEach(c=>c.addEventListener('click',()=>pivot(c.getAttribute('data-pivot'))));const types=[...new Set(nodes.map(n=>n.type))];document.getElementById('netLegend').innerHTML=types.map(t=>`<span class="badge" style="background:${NET_COLORS[t]||'#98a2b3'};color:#fff">${esc(t)}</span>`).join('');}
function execSummary(){const R=DATA.records||[],total=DATA.total_records||R.length;const t1=R.filter(r=>r.tier===1).length,t2=R.filter(r=>r.tier===2).length;const iv=DATA.initial||{},pv=DATA.precursor||{};const mc={},mn={};R.forEach(r=>(r.mitre||[]).forEach(t=>{mc[t.id]=(mc[t.id]||0)+1;mn[t.id]=t.name;}));const mids=Object.keys(mc).sort((a,b)=>mc[b]-mc[a]);const camps=(DATA.campaigns||[]).slice().sort((a,b)=>b.campaign_score-a.campaign_score).slice(0,3);const top=R.slice().sort((a,b)=>(a.tier-b.tier)||(b.score-a.score)).filter(r=>r.tier<=2).slice(0,5);let body=`<p><b>${total}</b> message(s) analyzed — <b>${t1}</b> Tier-1 prime suspect(s), <b>${t2}</b> Tier-2. Scenario profile: <b>${esc(iv.scenario||'n/a')}</b>.</p>`;if(iv.initial_email){const e=iv.initial_email;body+=`<p><b>Likely initial email:</b> <button class="small" onclick="focusPath(${js(e.path)})">${esc(e.subject||'(no subject)')}</button> — ${esc(e.sender||'')} (${esc(e.timestamp||'')}), confidence ${esc(iv.confidence||'low')}.</p>`;}else if(pv.verdict){body+=`<p><b>Earliest precursor:</b> ${esc(pv.verdict)} (confidence ${esc(pv.confidence||'low')}).</p>`;}if(top.length){body+=`<b>Highest-risk messages</b><ul class="indicator">${top.map(r=>`<li><button class="small" onclick="focusPath(${js(r.path)})">[T${r.tier} · score ${r.score}] ${esc(r.sender)} — ${esc(r.subject||'(no subject)')}</button></li>`).join('')}</ul>`;}if(camps.length){body+=`<b>Top campaigns</b><ul class="indicator">${camps.map(c=>`<li>${esc(c.campaign_id)} — ${c.message_count} msg(s), score ${c.campaign_score}${(c.sender_domains||[]).length?' · '+esc((c.sender_domains||[]).slice(0,3).join(', ')):''}</li>`).join('')}</ul>`;}if(mids.length){body+=`<b>ATT&CK techniques observed</b><div class="top" style="margin-top:6px">${mids.map(id=>`<span class="badge" title="${esc(mn[id])}">${esc(id)} ${esc(mn[id])} ×${mc[id]}</span>`).join('')}</div>`;}document.getElementById('execSummary').innerHTML=body;}
function makeSortable(table){if(!table||!table.tHead)return;const ths=table.tHead.rows[0].cells;[...ths].forEach((th,idx)=>{if(!th.classList.contains('sortable'))return;th.onclick=()=>{const tb=table.tBodies[0];if(!tb)return;const rows=[...tb.rows];const dir=th.dataset.dir==='asc'?'desc':'asc';th.dataset.dir=dir;const val=tr=>{const c=tr.cells[idx];const dv=c&&c.dataset?c.dataset.sortValue:null;const t=dv!=null?dv:(c?c.textContent:'');return{n:parseFloat(t),t:String(t)};};rows.sort((a,b)=>{const A=val(a),B=val(b);let r=(!isNaN(A.n)&&!isNaN(B.n))?A.n-B.n:A.t.localeCompare(B.t);return dir==='asc'?r:-r;});rows.forEach(r=>tb.appendChild(r));};});}
function narrativePanel(){const n=(DATA.initial||{}).attack_narrative||{};const el=document.getElementById('narrative');if(!el)return;if(!(n.phases||[]).length){el.innerHTML='<span class="muted">No narrative reconstructed.</span>';return;}let body=`<p>${esc(n.summary||'')}</p>`;body+=(n.phases||[]).map((p,i)=>`<div class="event"><div class="card"><div class="top"><span class="badge">Phase ${i+1}</span><b>${esc(p.title||'')}</b>${p.timestamp?`<span class="badge">${esc(p.timestamp)}</span>`:''}<span class="badge">confidence ${esc(p.confidence||'low')}</span></div><p class="small">${esc(p.description||'')}</p>${(p.messages||[]).map(m=>`<div class="small"><button class="small" onclick="focusPath(${js(m.path)})">${esc(m.timestamp||'')} · ${esc(m.sender||'')} · ${esc(m.subject||'(no subject)')}</button></div>`).join('')}</div></div>`).join('');if((n.timeline||[]).length){body+=`<b>Chronological key events (UTC)</b><div class="graph">${(n.timeline||[]).map(e=>`<div class="edge contextual"><span>${esc(e.timestamp_utc||'')}</span><span class="edge-label">${esc(e.phase||'')}</span><span>${esc(e.subject||'')}</span></div>`).join('')}</div>`;}body+=`<p class="small muted">Note: ${esc(n.disclaimer||'')}</p>`;el.innerHTML=body;}
function remediationPanel(){const el=document.getElementById('remediation');if(!el)return;const v=DATA.initial||{};const acts=v.remediation||[];const p=v.persistence||{};if(!acts.length){const w=(p.warnings||[]);el.innerHTML=w.length?`<div class="verdict-title">NOT ASSESSED</div>`+w.map(x=>`<p class="small">${esc(x)}</p>`).join(''):'<div class="empty">No persistence mechanism was identified. '+'Supply --mes-dir to assess whether the attacker retains access: an '+'OAuth consent grant leaves no trace in mail or sign-in data.</div>';return;}const both=acts.filter(a=>a.survives_password_reset==='survives'&&a.survives_token_revocation==='survives').length;let body=`<div class="verdict-title">${acts.length} ACTION(S) REQUIRED`+(both?` \u00b7 ${both} NOT fixed by a password reset or token revocation`:'')+`</div>`;body+='<p class="small muted">Ordered by what survives the response most '+'clients have already made.</p>';body+=acts.map(a=>`<div class="remed ${a.by_attacker?'hit':''}">`+`<b>${a.priority}. ${esc(String(a.kind).replace(/_/g,' '))}:</b> ${esc(a.target||'')}`+(a.when?`<br><span class="small muted">${esc(a.when)}`+(a.attribution?` \u2014 ${esc(a.attribution)}`:'')+`</span>`:'')+(a.detail?`<br><span class="small">${esc(a.detail)}</span>`:'')+(a.grants?`<br><span class="small">${esc(a.grants)}</span>`:'')+`<br><code class="small">${esc(a.action||'')}</code>`+(a.not_fixed_by?`<span class="warn small">${esc(a.not_fixed_by)}</span>`:'')+`</div>`).join('');el.innerHTML=body;}
function initialPanel(){const v=DATA.initial||{};const e=v.initial_email;const el=document.getElementById('initial');if(!el)return;let body=`<div class="verdict-title">${esc(v.verdict||'NO INITIAL EMAIL IDENTIFIED')} · ${esc(v.scenario||'')} · confidence ${esc(v.confidence||'low')}</div><p class="small muted">${esc(v.scenario_reason||'')}</p>`;if(e){body+=`<p><b>Initial email:</b> <button class="small" onclick="focusPath(${js(e.path)})">${esc(e.subject||'(no subject)')}</button><br><b>Timestamp:</b> ${esc(e.timestamp||'')}<br><b>Sender:</b> ${esc(e.sender||'')}<br><b>Stage:</b> ${esc(e.stage||'')}<br><b>Initial-email score:</b> ${Number(e.initial_score||0)} (priority ${Number(e.priority_score||0)})</p>`;if((e.anchor_matches||[]).length)body+=`<p class="risk">Anchor matches: ${(e.anchor_matches||[]).map(esc).join(', ')}</p>`;const FV={};(e.findings||[]).forEach(f=>{FV[f.signal]=f;});body+=`<b>Why</b><ul class="indicator">${(e.reasons||[]).map(x=>{const f=FV[x]||{};const ev=f.matched?`<div class="small muted">evidence: <code>${esc(String(f.matched))}</code>${f.source?` &middot; ${esc(f.source)}`:''}${f.weight?` &middot; ${f.weight>0?'+':''}${f.weight}`:''}</div>`:'';return `<li>${esc(x)}${ev}</li>`;}).join('')||'<li>&mdash;</li>'}</ul>`;}body+=`<b>Ranked candidates</b>${(v.shortlist||[]).map(x=>`<div class="small"><button class="small" onclick="focusPath(${js(x.path)})">[${Number(x.initial_score||0)}] ${esc(x.timestamp||'')} · ${esc(x.sender||'')} · ${esc(x.subject||'(no subject)')}</button></div>`).join('')||'<span class="muted">None</span>'}`;el.innerHTML=body;}
function dashboard(){const t1=DATA.records.filter(r=>r.tier===1).length;document.getElementById('dashboard').innerHTML=[['Emails shown',(DATA.shown_records||DATA.records.length)+' / '+(DATA.total_records||DATA.records.length)],['Tier 1 prime suspects',t1],['Campaigns',DATA.campaigns.length],['Timeline events',DATA.events.length],['Precursor confidence',DATA.precursor.confidence||'low']].map(x=>`<div class="metric"><div class="metric-label">${esc(x[0])}</div><div class="metric-value">${esc(x[1])}</div></div>`).join('');}
function verdict(){const p=DATA.precursor||{};document.getElementById('verdict').innerHTML=`<div class="verdict-title">${esc(p.verdict||'UNKNOWN')} · confidence ${esc(p.confidence||'low')}</div><p><b>Message:</b> <button class="small" onclick="focusPath(${js(p.message_path)})">${esc(p.message_path||'None identified')}</button><br><b>Timestamp:</b> ${esc(p.timestamp||'')}<br><b>Stage:</b> ${esc(p.stage||'')}<br><b>Reason:</b> ${esc(p.reason||'')}</p><b>Evidence</b><ul class="indicator">${(p.evidence||[]).map(x=>`<li>${esc(x)}</li>`).join('')||'<li>No explicit evidence.</li>'}</ul><b>Supporting later activity</b>${(p.follow_on_messages||[]).map(x=>`<button class="small" onclick="focusPath(${js(x.path)})">${esc(x.timestamp)} · ${esc(x.stage)} · ${esc(x.subject||'(no subject)')}</button> `).join('')||'<span class="muted"> None</span>'}`;}
function timeline(){const q=document.getElementById('search').value.toLowerCase().trim(),st=document.getElementById('stage').value,only=document.getElementById('onlyPrecursor').checked;const es=DATA.events.filter(e=>{const r=rec(e.path),blob=JSON.stringify(r).toLowerCase()+' '+JSON.stringify(e).toLowerCase();return(!q||blob.includes(q))&&(!st||e.stage===st)&&(!only||e.precursor)});document.getElementById('timeline').innerHTML=es.map(e=>{const r=rec(e.path),a=r.authentication||{},bad=['spf_fail','dkim_fail','dmarc_fail'].filter(k=>a[k]);return `<article class="event" data-path="${esc(e.path)}"><div class="dot"></div><div class="card"><div class="top"><b>${esc(e.timestamp||'(unknown date)')}</b><span class="badge">${esc(e.stage)}</span><span class="badge">score ${e.score}</span>${e.precursor?'<span class="badge precursor">EARLIEST PRECURSOR</span>':''}</div><h3>${esc(e.subject||'(no subject)')}</h3><div class="meta"><span>${esc(e.sender)}</span><span>${esc(e.path)}</span><span>${esc(e.campaign_id||'no campaign')}</span></div><div class="pivots"><button class="small" onclick="pivot(${js(e.sender)})">Sender</button><button class="small" onclick="pivot(${js(e.campaign_id)})">Campaign</button><button class="small" onclick="focusPath(${js(e.path)})">Focus</button></div><details><summary>Inspect evidence</summary><div class="inspect"><section><h4>Why flagged</h4><ul class="indicator">${(e.evidence||[]).map(x=>`<li>${esc(x)}</li>`).join('')}</ul></section><section><h4>Authentication</h4>${bad.length?bad.map(x=>`<div class="auth-bad">${esc(x)}</div>`).join(''):'<div class="auth-ok">No parsed authentication failure</div>'}</section><section><h4>URLs</h4>${(r.url_analysis||[]).map(x=>`<div class="evidence"><code>${esc(x.original)}</code><div class="risk">risk ${Number(x.suspicious_score||0)}</div><div class="muted">${esc(x.registrable_domain||x.hostname||'')}</div><ul class="indicator">${(x.indicators||[]).map(i=>`<li>${esc(i)}</li>`).join('')}</ul><button class="small" onclick="copyValue(${js(x.original)})">Copy URL</button></div>`).join('')||'<span class="muted">None</span>'}</section><section><h4>Attachments</h4>${(r.attachment_details||[]).map(x=>`<div class="evidence"><b>${esc(x.filename||'(unnamed)')}</b><div class="muted">${esc(x.content_type||'')} · ${Number(x.size||0)} bytes</div><code>${esc(x.sha256||'')}</code><br><button class="small" onclick="pivot(${js(x.sha256)})">Pivot SHA-256</button></div>`).join('')||'<span class="muted">None</span>'}</section></div></details></div></article>`;}).join('')||'<div class="empty">No timeline events match the filters.</div>';}
function graph(){document.getElementById('graph').innerHTML=(DATA.graph.edges||[]).map(e=>`<div class="edge ${esc(e.strength||'contextual')}" data-strength="${esc(e.strength||'contextual')}"><span>${esc(e.source)}</span><span>→</span><span>${esc(e.target)}</span><span class="edge-label">${esc(e.relation)}: ${esc(e.indicator)}</span></div>`).join('')||'<div class="empty">No evidence links.</div>';}
function campaigns(){document.getElementById('campaigns').innerHTML=(()=>{const all=DATA.campaigns||[];const rep=all.filter(c=>c.reportable!==false).sort((a,b)=>b.campaign_score-a.campaign_score);const CAP=50;const shown=rep.slice(0,CAP);const held=[];if(rep.length>CAP)held.push(`${rep.length-CAP} further reportable campaign(s) below score ${shown.length?shown[shown.length-1].campaign_score:0}`);if(all.length-rep.length>0)held.push(`${all.length-rep.length} low-confidence cluster(s) with no shared URL domain or attachment hash`);const note=held.length?`<p class="small muted">Not listed: ${held.join('; ')}. The complete set is in the JSON report.</p>`:'';return note+`<table><thead><tr><th>Campaign</th><th>Score</th><th>Confidence</th><th>Messages</th><th>First seen</th><th>Last seen</th><th>Sender domains</th><th>URL domains</th><th>Likely origin</th></tr></thead><tbody>${shown.map(c=>`<tr><td>${esc(c.campaign_id)}</td><td>${c.campaign_score}</td><td>${esc(c.confidence)}</td><td>${c.message_count}</td><td>${esc(c.first_seen)}</td><td>${esc(c.last_seen)}</td><td>${esc((c.sender_domains||[]).join(', '))}</td><td>${esc((c.url_domains||[]).join(', '))}</td><td>${esc(c.likely_origin)}</td></tr>`).join('')}</tbody></table>`;})();}
function candidates(){const q=document.getElementById('search').value.toLowerCase().trim();const tf=document.getElementById('tierFilter').value;const rs=DATA.records.filter(r=>(!q||JSON.stringify(r).toLowerCase().includes(q))&&(!tf||String(r.tier)===tf)).sort((a,b)=>(a.tier-b.tier)||(b.score-a.score));document.getElementById('candidates').innerHTML=`<table><thead><tr><th class="sortable">Tier</th><th class="sortable">Init</th><th class="sortable">Score</th><th class="sortable">Campaign</th><th class="sortable">Date</th><th class="sortable">Sender</th><th class="sortable">Subject</th><th>File</th><th>Indicators</th><th class="sortable">ATT&CK</th><th>URLs</th><th>Preview</th></tr></thead><tbody>${rs.map(r=>`<tr><td data-sort-value="${r.tier}"><span class="badge${r.tier===1?' precursor':''}">T${r.tier}</span></td><td data-sort-value="${Number(r.initial_score||0)}">${Number(r.initial_score||0)}</td><td data-sort-value="${r.score}">${r.score}${r.likely_precursor?'<br><span class="badge precursor">PRECURSOR</span>':''}</td><td data-sort-value="${Number(r.campaign_score||0)}">${esc(r.campaign_id)}<br>${r.campaign_score}</td><td>${esc(r.date)}</td><td>${esc(r.sender)}</td><td>${esc(r.subject)}</td><td>${esc(r.path)}</td><td><ul class="indicator">${(()=>{const pv={};(r.provenance||[]).forEach(p=>{pv[p.signal]=p;});return (r.indicators||[]).map(x=>{const p=pv[x];const tag=p?` <span class="muted">[${esc(p.source||'?')}${p.weight?' +'+p.weight:''} · ${esc(p.severity||'low')}]</span>`:'';const ev=(p&&p.matched)?`<div class="small muted">evidence: <code>${esc(String(p.matched))}</code></div>`:'';return `<li>${esc(x)}${tag}${ev}</li>`;}).join('');})()}</ul></td><td data-sort-value="${(r.mitre||[]).length}">${(r.mitre||[]).map(t=>`<span class="badge" title="${esc(t.name)}">${esc(t.id)}</span>`).join(' ')}</td><td>${(r.urls||[]).map(esc).join('<br>')}</td><td><details><summary class="small">preview</summary><pre>${esc(r.preview||r.snippet||'')}</pre></details></td></tr>`).join('')}</tbody></table>`;makeSortable(document.querySelector('#candidates table'));}
function clearFilters(){document.getElementById('search').value='';document.getElementById('stage').value='';document.getElementById('onlyPrecursor').checked=false;render();}
function focusPath(path){const el=[...document.querySelectorAll('.event')].find(x=>x.dataset.path===path);if(el){const card=el.querySelector('.card');card.classList.add('selected');el.scrollIntoView({behavior:'smooth',block:'center'});setTimeout(()=>card.classList.remove('selected'),2500);}}
function pivot(v){if(!v)return;document.getElementById('search').value=String(v).toLowerCase();render();window.scrollTo({top:0,behavior:'smooth'});}
function copyValue(v){if(navigator.clipboard)navigator.clipboard.writeText(v);}
function toggleEdges(){const a=document.getElementById('strongEdges').checked,b=document.getElementById('contextEdges').checked;document.querySelectorAll('.edge.strong').forEach(x=>x.style.display=a?'':'none');document.querySelectorAll('.edge.contextual').forEach(x=>x.style.display=b?'':'none');}
render();
</script></body></html>"""
    output.write_text(html_doc.replace('__DATA__', data), encoding='utf-8')
