"""Report generation: console summaries, the interactive HTML report, JSON and
CSV exports, and the reproducibility manifest. Consumes analysis results; it is
the top layer and nothing else imports it.
"""

import csv
import hashlib
import html
import json
import os
import sys
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from postmortem.config import CONFIG, TOOL_VERSION, V7_PARSER_VERSION
from postmortem.models import EmailRecord, CampaignInfo, AttackTimelineEvent
from postmortem.utils import date_sort_key, to_utc_fields, clean_text, parse_date
from postmortem.scoring import classify_attack_stage, build_evidence_graph

# Per-message URL links and body-snippet length embedded in the HTML report
# (the JSON/CSV reports keep everything). Caps only affect the interactive page.
_HTML_URL_CAP = 15
_HTML_SNIPPET = 300


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
    print("=" * 80)
    print("CAMPAIGN CLUSTERS")
    print("=" * 80)
 
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
 
 
def print_initial_compromise(verdict: dict):
    print()
    print("=" * 80)
    print("INITIAL COMPROMISE ANALYSIS")
    print("=" * 80)
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
        for reason in initial.get("reasons", [])[:8]:
            print(f"    - {reason}")

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
    print("=" * 80)
    print("ATTACK NARRATIVE (reconstructed)")
    print("=" * 80)
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


def print_audit_summary(audit: dict):
    """Console section for an ingested M365 Unified Audit Log."""
    if not audit:
        return
    d = audit.get("derived", {})
    print()
    print("=" * 80)
    print("M365 UNIFIED AUDIT LOG (confirmed attacker activity)")
    print("=" * 80)
    print(f"  Events parsed:          {audit.get('events_parsed', 0)}")
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


def print_summary(
    records: list[EmailRecord],
    timeline: list[AttackTimelineEvent],
    precursor_verdict: dict,
):

    records_sorted = sorted(
        records,
        key=lambda r: (
            -r.score,
            date_sort_key(r),
        ),
    )
 
    print()
    print("=" * 80)
    print("BEC / PHISHING FORENSIC ANALYSIS")
    print("=" * 80)
 
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
    print("EARLIEST MALICIOUS PRECURSOR VERDICT")
    print("-" * 80)
    print("Verdict:    " + precursor_verdict.get("verdict", ""))
    print("Confidence: " + precursor_verdict.get("confidence", ""))
    if precursor_verdict.get("message_path"):
        print("Message:    " + precursor_verdict.get("message_path", ""))
        print("Timestamp:  " + precursor_verdict.get("timestamp", ""))
        print("Stage:      " + precursor_verdict.get("stage", ""))
        print("Subject:    " + precursor_verdict.get("subject", ""))
    print("Reason:     " + precursor_verdict.get("reason", ""))
 
    print()
    print("ATTACK TIMELINE")
    print("-" * 80)
    for event in timeline[:50]:
        print(f"{event.timestamp or '(unknown)':25} | {event.stage:28} | score={event.score:3} | {event.path}")
 
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
 
        print(
            f"{rank:2}. SCORE {record.score:3} | "
            f"{date} | {sender}"
        )
 
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
                tag = f"  [{p.get('source', '?')}"
                if p.get("weight"):
                    tag += f" +{p['weight']}"
                tag += f" | {p.get('severity', 'low')}]"
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
    print("=" * 80)
    print("IMPORTANT")
    print("=" * 80)
 
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
 
    records_sorted = sorted(
        records,
        key=lambda r: (
            -r.score,
            date_sort_key(r),
        ),
    )
 
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
                       campaigns, iocs, generated_utc, elapsed_seconds):
    """Reproducibility / chain-of-custody metadata recorded in every report."""
    digest, basis = corpus_fingerprint(records)
    tier_counts = Counter(r.tier for r in records)
    return {
        "tool": "postmortem",
        "tool_version": TOOL_VERSION,
        "parser_version": V7_PARSER_VERSION,
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


def print_run_manifest(manifest):
    print()
    print("=" * 80)
    print("RUN MANIFEST (reproducibility / chain of custody)")
    print("=" * 80)
    c = manifest["corpus"]
    print(f"Tool: postmortem {manifest['tool_version']} (parser {manifest['parser_version']})")
    print(f"Generated (UTC): {manifest['generated_utc']}   Elapsed: {manifest['elapsed_seconds']}s")
    print(f"Corpus: {c['message_count']} messages | SHA-256 ({c['hash_basis']}): {c['corpus_sha256']}")
    print(f"Scenario: {manifest['scenario_profile']}   Command: {manifest['command_line']}")


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
    }


def generate_html_interactive(records, campaigns, output, timeline, precursor_verdict, initial_verdict=None, limit=1000):
    # A: embed only the investigation subset (top-N by score), plus any message
    # named by the initial-email verdict so the key finding is always present.
    # The full dataset remains in the JSON/CSV reports.
    ranked = sorted(records, key=lambda r: (-r.score, date_sort_key(r)))
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
        (e for e in timeline if e.path in keep_paths),
        key=event_sort_key,
    )

    payload = {
        'events': [asdict(e) for e in sub_events],
        'records': [_html_record(r) for r in subset],
        'campaigns': [asdict(c) for c in campaigns],
        'precursor': precursor_verdict,
        'initial': initial_verdict or {},
        'graph': graph,
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
.table-wrap{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:12px}table{border-collapse:collapse;width:100%;min-width:1100px}th,td{padding:9px;border-bottom:1px solid #eaecf0;text-align:left;vertical-align:top}th{background:#17212b;color:#fff;position:sticky;top:57px}pre{white-space:pre-wrap;max-width:500px}.empty{text-align:center;padding:28px;color:var(--muted)}
@media(max-width:800px){.wrap{padding:14px}#search{min-width:180px}.edge{grid-template-columns:1fr}}
</style></head><body><div class="wrap">
<h1>BEC / Phishing Forensic Investigation</h1><p class="muted">Interactive local-only report. URLs are never visited and no external assets are loaded.</p>
<div id="dashboard" class="dashboard"></div>
<div class="controls"><input id="search" placeholder="Search sender, subject, campaign, URL, SHA-256, or file..." oninput="render()"><select id="stage" onchange="render()"><option value="">All stages</option><option>initial_contact</option><option>social_engineering</option><option>suspicious_link</option><option>credential_harvest</option><option>attachment_delivery</option><option>delivery_or_credential_harvest</option><option>payment_request</option></select><label><input id="onlyPrecursor" type="checkbox" onchange="render()"> Precursors only</label><button onclick="clearFilters()">Clear</button></div>
<h2>Initial Compromise (scenario-anchored)</h2><div id="initial" class="verdict"></div>
<h2>Attack Narrative (reconstructed)</h2><div id="narrative" class="verdict"></div>
<h2>Earliest Malicious Precursor</h2><div id="verdict" class="verdict"></div>
<h2>Attack Timeline</h2><div id="timeline" class="timeline"></div>
<h2>Evidence Graph</h2><div class="controls" style="position:static;background:transparent;border:0"><label><input id="strongEdges" type="checkbox" checked onchange="toggleEdges()"> Strong pivots</label><label><input id="contextEdges" type="checkbox" checked onchange="toggleEdges()"> Temporal/contextual links</label></div><div id="graph" class="graph"></div>
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
function render(){dashboard();initialPanel();narrativePanel();verdict();timeline();graph();campaigns();candidates();toggleEdges();}
function narrativePanel(){const n=(DATA.initial||{}).attack_narrative||{};const el=document.getElementById('narrative');if(!el)return;if(!(n.phases||[]).length){el.innerHTML='<span class="muted">No narrative reconstructed.</span>';return;}let body=`<p>${esc(n.summary||'')}</p>`;body+=(n.phases||[]).map((p,i)=>`<div class="event"><div class="card"><div class="top"><span class="badge">Phase ${i+1}</span><b>${esc(p.title||'')}</b>${p.timestamp?`<span class="badge">${esc(p.timestamp)}</span>`:''}<span class="badge">confidence ${esc(p.confidence||'low')}</span></div><p class="small">${esc(p.description||'')}</p>${(p.messages||[]).map(m=>`<div class="small"><button class="small" onclick="focusPath(${js(m.path)})">${esc(m.timestamp||'')} · ${esc(m.sender||'')} · ${esc(m.subject||'(no subject)')}</button></div>`).join('')}</div></div>`).join('');if((n.timeline||[]).length){body+=`<b>Chronological key events (UTC)</b><div class="graph">${(n.timeline||[]).map(e=>`<div class="edge contextual"><span>${esc(e.timestamp_utc||'')}</span><span class="edge-label">${esc(e.phase||'')}</span><span>${esc(e.subject||'')}</span></div>`).join('')}</div>`;}body+=`<p class="small muted">Note: ${esc(n.disclaimer||'')}</p>`;el.innerHTML=body;}
function initialPanel(){const v=DATA.initial||{};const e=v.initial_email;const el=document.getElementById('initial');if(!el)return;let body=`<div class="verdict-title">${esc(v.verdict||'NO INITIAL EMAIL IDENTIFIED')} · ${esc(v.scenario||'')} · confidence ${esc(v.confidence||'low')}</div><p class="small muted">${esc(v.scenario_reason||'')}</p>`;if(e){body+=`<p><b>Initial email:</b> <button class="small" onclick="focusPath(${js(e.path)})">${esc(e.subject||'(no subject)')}</button><br><b>Timestamp:</b> ${esc(e.timestamp||'')}<br><b>Sender:</b> ${esc(e.sender||'')}<br><b>Stage:</b> ${esc(e.stage||'')}<br><b>Initial-email score:</b> ${Number(e.initial_score||0)} (priority ${Number(e.priority_score||0)})</p>`;if((e.anchor_matches||[]).length)body+=`<p class="risk">Anchor matches: ${(e.anchor_matches||[]).map(esc).join(', ')}</p>`;body+=`<b>Why</b><ul class="indicator">${(e.reasons||[]).map(x=>`<li>${esc(x)}</li>`).join('')||'<li>—</li>'}</ul>`;}body+=`<b>Ranked candidates</b>${(v.shortlist||[]).map(x=>`<div class="small"><button class="small" onclick="focusPath(${js(x.path)})">[${Number(x.initial_score||0)}] ${esc(x.timestamp||'')} · ${esc(x.sender||'')} · ${esc(x.subject||'(no subject)')}</button></div>`).join('')||'<span class="muted">None</span>'}`;el.innerHTML=body;}
function dashboard(){const t1=DATA.records.filter(r=>r.tier===1).length;document.getElementById('dashboard').innerHTML=[['Emails shown',(DATA.shown_records||DATA.records.length)+' / '+(DATA.total_records||DATA.records.length)],['Tier 1 prime suspects',t1],['Campaigns',DATA.campaigns.length],['Timeline events',DATA.events.length],['Precursor confidence',DATA.precursor.confidence||'low']].map(x=>`<div class="metric"><div class="metric-label">${esc(x[0])}</div><div class="metric-value">${esc(x[1])}</div></div>`).join('');}
function verdict(){const p=DATA.precursor||{};document.getElementById('verdict').innerHTML=`<div class="verdict-title">${esc(p.verdict||'UNKNOWN')} · confidence ${esc(p.confidence||'low')}</div><p><b>Message:</b> <button class="small" onclick="focusPath(${js(p.message_path)})">${esc(p.message_path||'None identified')}</button><br><b>Timestamp:</b> ${esc(p.timestamp||'')}<br><b>Stage:</b> ${esc(p.stage||'')}<br><b>Reason:</b> ${esc(p.reason||'')}</p><b>Evidence</b><ul class="indicator">${(p.evidence||[]).map(x=>`<li>${esc(x)}</li>`).join('')||'<li>No explicit evidence.</li>'}</ul><b>Supporting later activity</b>${(p.follow_on_messages||[]).map(x=>`<button class="small" onclick="focusPath(${js(x.path)})">${esc(x.timestamp)} · ${esc(x.stage)} · ${esc(x.subject||'(no subject)')}</button> `).join('')||'<span class="muted"> None</span>'}`;}
function timeline(){const q=document.getElementById('search').value.toLowerCase().trim(),st=document.getElementById('stage').value,only=document.getElementById('onlyPrecursor').checked;const es=DATA.events.filter(e=>{const r=rec(e.path),blob=JSON.stringify(r).toLowerCase()+' '+JSON.stringify(e).toLowerCase();return(!q||blob.includes(q))&&(!st||e.stage===st)&&(!only||e.precursor)});document.getElementById('timeline').innerHTML=es.map(e=>{const r=rec(e.path),a=r.authentication||{},bad=['spf_fail','dkim_fail','dmarc_fail'].filter(k=>a[k]);return `<article class="event" data-path="${esc(e.path)}"><div class="dot"></div><div class="card"><div class="top"><b>${esc(e.timestamp||'(unknown date)')}</b><span class="badge">${esc(e.stage)}</span><span class="badge">score ${e.score}</span>${e.precursor?'<span class="badge precursor">EARLIEST PRECURSOR</span>':''}</div><h3>${esc(e.subject||'(no subject)')}</h3><div class="meta"><span>${esc(e.sender)}</span><span>${esc(e.path)}</span><span>${esc(e.campaign_id||'no campaign')}</span></div><div class="pivots"><button class="small" onclick="pivot(${js(e.sender)})">Sender</button><button class="small" onclick="pivot(${js(e.campaign_id)})">Campaign</button><button class="small" onclick="focusPath(${js(e.path)})">Focus</button></div><details><summary>Inspect evidence</summary><div class="inspect"><section><h4>Why flagged</h4><ul class="indicator">${(e.evidence||[]).map(x=>`<li>${esc(x)}</li>`).join('')}</ul></section><section><h4>Authentication</h4>${bad.length?bad.map(x=>`<div class="auth-bad">${esc(x)}</div>`).join(''):'<div class="auth-ok">No parsed authentication failure</div>'}</section><section><h4>URLs</h4>${(r.url_analysis||[]).map(x=>`<div class="evidence"><code>${esc(x.original)}</code><div class="risk">risk ${Number(x.suspicious_score||0)}</div><div class="muted">${esc(x.registrable_domain||x.hostname||'')}</div><ul class="indicator">${(x.indicators||[]).map(i=>`<li>${esc(i)}</li>`).join('')}</ul><button class="small" onclick="copyValue(${js(x.original)})">Copy URL</button></div>`).join('')||'<span class="muted">None</span>'}</section><section><h4>Attachments</h4>${(r.attachment_details||[]).map(x=>`<div class="evidence"><b>${esc(x.filename||'(unnamed)')}</b><div class="muted">${esc(x.content_type||'')} · ${Number(x.size||0)} bytes</div><code>${esc(x.sha256||'')}</code><br><button class="small" onclick="pivot(${js(x.sha256)})">Pivot SHA-256</button></div>`).join('')||'<span class="muted">None</span>'}</section></div></details></div></article>`;}).join('')||'<div class="empty">No timeline events match the filters.</div>';}
function graph(){document.getElementById('graph').innerHTML=(DATA.graph.edges||[]).map(e=>`<div class="edge ${esc(e.strength||'contextual')}" data-strength="${esc(e.strength||'contextual')}"><span>${esc(e.source)}</span><span>→</span><span>${esc(e.target)}</span><span class="edge-label">${esc(e.relation)}: ${esc(e.indicator)}</span></div>`).join('')||'<div class="empty">No evidence links.</div>';}
function campaigns(){document.getElementById('campaigns').innerHTML=`<table><thead><tr><th>Campaign</th><th>Score</th><th>Confidence</th><th>Messages</th><th>First seen</th><th>Last seen</th><th>Sender domains</th><th>URL domains</th><th>Likely origin</th></tr></thead><tbody>${DATA.campaigns.map(c=>`<tr><td>${esc(c.campaign_id)}</td><td>${c.campaign_score}</td><td>${esc(c.confidence)}</td><td>${c.message_count}</td><td>${esc(c.first_seen)}</td><td>${esc(c.last_seen)}</td><td>${esc((c.sender_domains||[]).join(', '))}</td><td>${esc((c.url_domains||[]).join(', '))}</td><td>${esc(c.likely_origin)}</td></tr>`).join('')}</tbody></table>`;}
function candidates(){const q=document.getElementById('search').value.toLowerCase().trim();const tf=document.getElementById('tierFilter').value;const rs=DATA.records.filter(r=>(!q||JSON.stringify(r).toLowerCase().includes(q))&&(!tf||String(r.tier)===tf)).sort((a,b)=>(a.tier-b.tier)||(b.score-a.score));document.getElementById('candidates').innerHTML=`<table><thead><tr><th>Tier</th><th>Init</th><th>Score</th><th>Campaign</th><th>Date</th><th>Sender</th><th>Subject</th><th>File</th><th>Indicators</th><th>URLs</th><th>Evidence</th></tr></thead><tbody>${rs.map(r=>`<tr><td><span class="badge${r.tier===1?' precursor':''}">T${r.tier}</span></td><td>${Number(r.initial_score||0)}</td><td>${r.score}${r.likely_precursor?'<br><span class="badge precursor">PRECURSOR</span>':''}</td><td>${esc(r.campaign_id)}<br>${r.campaign_score}</td><td>${esc(r.date)}</td><td>${esc(r.sender)}</td><td>${esc(r.subject)}</td><td>${esc(r.path)}</td><td><ul class="indicator">${(()=>{const pv={};(r.provenance||[]).forEach(p=>{pv[p.signal]=p;});return (r.indicators||[]).map(x=>{const p=pv[x];const tag=p?` <span class="muted">[${esc(p.source||'?')}${p.weight?' +'+p.weight:''} · ${esc(p.severity||'low')}]</span>`:'';const tip=(p&&p.matched)?` title="matched: ${esc(String(p.matched))}"`:'';return `<li${tip}>${esc(x)}${tag}</li>`;}).join('');})()}</ul></td><td>${(r.urls||[]).map(esc).join('<br>')}</td><td><pre>${esc(r.snippet||'')}</pre></td></tr>`).join('')}</tbody></table>`;}
function clearFilters(){document.getElementById('search').value='';document.getElementById('stage').value='';document.getElementById('onlyPrecursor').checked=false;render();}
function focusPath(path){const el=[...document.querySelectorAll('.event')].find(x=>x.dataset.path===path);if(el){const card=el.querySelector('.card');card.classList.add('selected');el.scrollIntoView({behavior:'smooth',block:'center'});setTimeout(()=>card.classList.remove('selected'),2500);}}
function pivot(v){if(!v)return;document.getElementById('search').value=String(v).toLowerCase();render();window.scrollTo({top:0,behavior:'smooth'});}
function copyValue(v){if(navigator.clipboard)navigator.clipboard.writeText(v);}
function toggleEdges(){const a=document.getElementById('strongEdges').checked,b=document.getElementById('contextEdges').checked;document.querySelectorAll('.edge.strong').forEach(x=>x.style.display=a?'':'none');document.querySelectorAll('.edge.contextual').forEach(x=>x.style.display=b?'':'none');}
render();
</script></body></html>"""
    output.write_text(html_doc.replace('__DATA__', data), encoding='utf-8')
