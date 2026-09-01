#!/usr/bin/env python3
 
"""
BEC / Phishing Email Forensic Analyzer
 
Recursively scans a directory of .eml files - or a PST/OST/MBOX mail
container - and attempts to identify emails and campaigns most likely
associated with a Business Email Compromise (BEC) / phishing incident.

Features:
    - Parses local .eml files, or explodes PST/OST/MBOX into .eml first
      (folder structure preserved for concealment detection)
    - Does not execute attachments
    - Does not visit URLs
    - Does not download remote content
    - Heuristic phishing/BEC scoring
    - Thread analysis
    - Temporal precursor analysis
    - Attachment SHA-256 hashing
    - Robust offline URL analysis
    - Attack timeline reconstruction
    - Earliest malicious precursor verdict
    - Display-name impersonation detection
    - Campaign clustering across unrelated email threads
    - Campaign-level risk scoring
    - Progress bar
    - Parallel parsing for large mail collections
    - Two-pass candidate/deep analysis
    - Persistent SQLite resumable cache
    - Streaming attachment SHA-256 hashing
    - HTML report
    - JSON report
 
Usage:
 
    python -m postmortem /path/to/emails
 
    python -m postmortem /path/to/emails -o report.html
 
    python -m postmortem /path/to/emails --json results.json
 
    python -m postmortem /path/to/emails -o report.html --json results.json
 
    python -m postmortem /path/to/emails --workers 8
 
 
Important:
    Scores are heuristic investigation priorities.
 
    A high score does NOT prove that a message is malicious.
 
    Validate findings using:
        - Authentication logs
        - Microsoft 365 / Google Workspace logs
        - Identity provider logs
        - Endpoint telemetry
        - Mail gateway logs
        - Original message headers
        - SPF/DKIM/DMARC results
        - URL/proxy telemetry
        - User reports
"""
 
 
from __future__ import annotations
 
import argparse
import concurrent.futures
import hashlib
import time
# Process-based parallelism is an optimization only. Some environments
# (restricted containers, live-forensic media, flaky/overlay filesystems) fail
# to even import it; treat it as optional and fall back to serial execution.
try:
    from concurrent.futures import ProcessPoolExecutor
except Exception:  # pragma: no cover - environment dependent
    ProcessPoolExecutor = None
import json
import os
import sys

from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
 
 
# ============================================================================
# CONFIGURATION
# ============================================================================

# Tunable weights/thresholds live in the postmortem.config module (overridable with
# --config); imported here so the rest of this file can reference them directly.
from postmortem.config import load_config, V7_PARSER_VERSION


# URL regexes, constants, and offline analysis live in postmortem.urls.
from postmortem.urls import extract_url_domains, analyze_url_robust  # noqa: E402


 
 
 
# ============================================================================
# DATA STRUCTURES
# ============================================================================
# The dataclasses live in postmortem.models; imported here so the rest of this file
# (and callers doing `import postmortem`) can reference them unchanged.


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
# Pure helpers (address/domain normalization, date parsing) live in
# postmortem.utils; imported here so the rest of this file uses them unchanged.


from postmortem.parsing import parse_eml  # noqa: E402
from postmortem.scoring import (  # noqa: E402
    classify_attack_stage, build_anchors, run_scenario_analysis,
    parse_anchor_datetime,
)
from postmortem.iocs import extract_iocs, write_iocs_csv  # noqa: E402
from postmortem.auditlog import analyze_audit_log  # noqa: E402
from postmortem.mailbox_ingest import (  # noqa: E402
    find_containers, ingest_all,
)


class AnalysisCache:
    """Small in-process cache for repeated URL/domain/hash work."""
    def __init__(self):
        self.urls = {}
        self.domains = {}
        self.attachments = {}

    def url(self, value, analyzer):
        key = value.strip()
        if key not in self.urls:
            self.urls[key] = analyzer(key)
        return dict(self.urls[key])

    def attachment(self, payload):
        key = hashlib.sha256(payload).hexdigest()
        cached = self.attachments.get(key)
        if cached is not None:
            return dict(cached)
        value = {"sha256": key, "size": len(payload)}
        self.attachments[key] = value
        return dict(value)
# ============================================================================
# PARSING
# ============================================================================
 
# ============================================================================
# BASIC ANALYSIS
# ============================================================================
 
from postmortem.scoring import (  # noqa: E402
    calculate_score, v8_candidate_score, identify_internal_domains,
    identify_known_contacts, calculate_thread_ids, analyze_temporal_signals,
    detect_possible_impersonation, build_attack_timeline,
    earliest_malicious_precursor_verdict,
)
# ============================================================================
# CAMPAIGN CLUSTERING
# ============================================================================
 
from postmortem.clustering import build_campaign_clusters  # noqa: E402
from postmortem.utils import registered_domain_approx  # noqa: E402
# ============================================================================
# ATTACK TIMELINE / PRECURSOR VERDICT
# ============================================================================
 
# ============================================================================
# PERFORMANCE / PROGRESS
# ============================================================================
 
class ProgressTracker:
    """Low-overhead progress reporting for large mailbox scans."""
    def __init__(self, total=0, callback=None):
        self.total = max(int(total or 0), 0)
        self.completed = 0
        self.phase = "initializing"
        self.started = time.monotonic()
        self.callback = callback
        self.last_emit = 0.0
        self.emit_interval = 0.20
 
    def update(self, completed=None, phase=None, force=False):
        if completed is not None:
            self.completed = min(max(int(completed), 0), self.total or int(completed))
        if phase:
            self.phase = phase
        now = time.monotonic()
        if not force and now - self.last_emit < self.emit_interval:
            return
        self.last_emit = now
        elapsed = max(now - self.started, 0.001)
        rate = self.completed / elapsed
        eta = ((self.total - self.completed) / rate) if self.total and rate > 0 else None
        payload = {
            "completed": self.completed,
            "total": self.total,
            "percent": (100.0 * self.completed / self.total) if self.total else 0.0,
            "phase": self.phase,
            "elapsed_seconds": elapsed,
            "items_per_second": rate,
            "eta_seconds": eta,
        }
        if self.callback:
            self.callback(payload)
        else:
            if self.total:
                eta_text = f", ETA {eta:.1f}s" if eta is not None else ""
                print(
                    f"\r[{payload['percent']:6.2f}%] {self.phase}: "
                    f"{self.completed}/{self.total} "
                    f"({rate:.1f}/s{eta_text})",
                    end="",
                    flush=True,
                )
 
    def finish(self, phase="complete"):
        self.update(self.total if self.total else self.completed, phase, force=True)
        if not self.callback:
            print()
 
 
 
# ============================================================================
# V7 PERSISTENT CACHE / STREAMING ARTIFACT HASHING
# ============================================================================
 
# V7_PARSER_VERSION / TOOL_VERSION are defined in postmortem.config and imported at
# the top of this file. Bump them there whenever parsing, the EmailRecord schema,
# or the analysis logic changes, so stale cache entries are never reused.
 
# The SQLite cache and whole-file hashing live in postmortem.cache.
from postmortem.cache import SQLiteRecordCache, sha256_file
def v8_cache_progress(phase, completed, total, started, extra=""):
    elapsed = max(time.monotonic() - started, 0.001)
    rate = completed / elapsed
    remaining = max(total - completed, 0)
    eta = remaining / rate if rate else 0.0
    width = 36
    fraction = completed / total if total else 1.0
    filled = int(width * fraction)
    bar = "#" * filled + "-" * (width - filled)
    print(
        f"\r[{bar}] {fraction*100:6.2f}% "
        f"{phase}: {completed}/{total} "
        f"({rate:.1f}/s ETA {eta:.1f}s){extra}",
        end="",
        flush=True,
    )
 
 
# ============================================================================
# V6 EFFICIENCY INDEXES / TWO-PASS PIPELINE
# ============================================================================
 
def v6_build_indexes(records):
    """Build correlation indexes once instead of rescanning all records."""
    indexes = {
        "url": {},
        "domain": {},
        "sha256": {},
        "sender_domain": {},
    }
 
    for idx, record in enumerate(records):
        for url_info in getattr(record, "url_analysis", []) or []:
            key = str(url_info.get("normalized_url") or url_info.get("url") or "").lower()
            if key:
                indexes["url"].setdefault(key, []).append(idx)
 
            domain = str(url_info.get("registrable_domain") or "").lower()
            if domain:
                indexes["domain"].setdefault(domain, []).append(idx)
 
        # Older records store `attachments` as filename strings, while
        # enriched records may store attachment dictionaries. Only dictionaries
        # can contribute SHA-256 pivots.
        seen_hashes = set()
 
        for attachment in getattr(record, "attachment_details", []) or []:
            if isinstance(attachment, dict):
                sha = str(attachment.get("sha256") or "").lower()
                if sha and sha not in seen_hashes:
                    indexes["sha256"].setdefault(sha, []).append(idx)
                    seen_hashes.add(sha)
 
        for attachment in getattr(record, "attachments", []) or []:
            if isinstance(attachment, dict):
                sha = str(attachment.get("sha256") or "").lower()
                if sha and sha not in seen_hashes:
                    indexes["sha256"].setdefault(sha, []).append(idx)
                    seen_hashes.add(sha)
            # Filename-only attachment records remain available on the record;
            # they simply cannot be SHA-256 indexed.
 
        sender = str(getattr(record, "sender", "") or "").lower()
        if "@" in sender:
            domain = sender.rsplit("@", 1)[-1].strip(" >")
            if domain:
                indexes["sender_domain"].setdefault(domain, []).append(idx)
 
    return indexes
 
 
# Deep enrichment and initial parsing are CPU-bound (MIME parsing, decoding,
# regex). Threads are throttled by the GIL, so above this many jobs we switch
# to real process-level parallelism. Below it, process start-up/IPC overhead
# would dominate, so we stay in-process.
_PROCESS_POOL_MIN_JOBS = 200


def parallel_map(worker, items, workers, chunksize):
    """Yield worker(item) for each item, in order.

    Uses a process pool when one is available and workers > 1; otherwise (or if
    the pool cannot be created in this environment) runs serially in-process.
    Keeping this resilient means an unusable process pool degrades performance
    but never stops the analysis.
    """
    if ProcessPoolExecutor is not None and workers and workers > 1:
        try:
            executor = ProcessPoolExecutor(max_workers=workers)
        except Exception as exc:  # pragma: no cover - environment dependent
            print(
                f"\n[!] Process pool unavailable ({type(exc).__name__}: {exc}); "
                f"using serial execution.",
                file=sys.stderr,
            )
        else:
            with executor:
                yield from executor.map(worker, items, chunksize=chunksize)
            return
    for item in items:
        yield worker(item)


def _parse_uncached_worker(path):
    """Top-level (picklable) parse worker for the process pool."""
    return path, parse_eml(path, deep=False)


def _deep_url_set(deep_record) -> list[str]:
    """All URLs to analyze for a deeply-parsed record, including links found in
    HTML hrefs (parse_eml surfaces those only inside url_analysis) and links
    embedded in attachments, so credential-phish links carried in HTML-only mail
    or inside an attachment are not missed."""
    href_urls = [
        str(a.get("url") or "")
        for a in (deep_record.url_analysis or [])
    ]
    attach_urls = [
        u
        for a in (deep_record.attachment_details or [])
        if isinstance(a, dict)
        for u in (a.get("embedded_urls") or [])
    ]
    return [
        u for u in dict.fromkeys(list(deep_record.urls) + href_urls + attach_urls)
        if u
    ]


def _deep_analyze_worker(job):
    """Top-level (picklable) deep-enrichment worker for the process pool.

    Returns only picklable data; the parent process applies it to the shared
    record list. URL analysis is deduplicated within this worker exactly as the
    in-process cache does (strip key, analyze once, hand back an independent
    copy) so results are identical regardless of pool type.
    """
    index, path = job
    deep_record = parse_eml(Path(path), deep=True)
    if deep_record is None:
        return index, None

    all_urls = _deep_url_set(deep_record)
    local_cache = {}
    url_analysis = []
    for url in all_urls:
        key = url.strip()
        if key not in local_cache:
            local_cache[key] = analyze_url_robust(key)
        url_analysis.append(dict(local_cache[key]))

    precursor_evidence = [
        indicator
        for analysis in url_analysis
        for indicator in analysis.get("indicators", [])
    ]
    return index, {
        "urls": all_urls,
        "url_domains": extract_url_domains(all_urls),
        "attachments": deep_record.attachments,
        "attachment_details": deep_record.attachment_details,
        "url_analysis": url_analysis,
        "precursor_evidence": precursor_evidence,
    }


def _apply_deep_result(records, url_cache, index, payload):
    """Apply a worker's enrichment payload to the shared record list."""
    record = records[index]
    if payload is None:
        return
    record.urls = payload["urls"]
    record.url_domains = payload["url_domains"]
    record.attachments = payload["attachments"]
    record.attachment_details = payload["attachment_details"]
    record.url_analysis = payload["url_analysis"]
    record.precursor_evidence = payload["precursor_evidence"]
    record.deep_analyzed = True
    # Re-seed the in-process URL cache so the "Unique URL cache" statistic and
    # any later in-process reuse remain accurate under process-pool execution.
    for url, analysis in zip(payload["urls"], payload["url_analysis"]):
        url_cache.urls.setdefault(url.strip(), analysis)


def v6_parallel_deep_analysis(records, candidate_indexes, max_workers, url_cache):
    """Deep-enrich only candidates.

    Uses a process pool for large candidate sets (CPU-bound work that the GIL
    would otherwise serialize) and stays in-process for small sets or a single
    worker, where the in-process URL cache avoids re-analyzing shared URLs.
    """
    if not candidate_indexes:
        return []

    # Candidates already enriched from the cache (a prior run deep-analyzed and
    # persisted them) are skipped entirely — no re-parse, no re-analysis.
    pending = [i for i in candidate_indexes if not records[i].deep_analyzed]
    cached = len(candidate_indexes) - len(pending)
    if cached:
        print(f"  ({cached} already enriched from cache; {len(pending)} to analyze)")
    if not pending:
        return []

    workers = max(1, min(int(max_workers or 1), 16))

    if workers == 1 or len(pending) < _PROCESS_POOL_MIN_JOBS:
        for index in pending:
            record = records[index]
            deep_record = parse_eml(Path(record.path), deep=True)
            if deep_record is None:
                continue
            all_urls = _deep_url_set(deep_record)
            record.urls = all_urls
            record.url_domains = extract_url_domains(all_urls)
            record.attachments = deep_record.attachments
            record.attachment_details = deep_record.attachment_details
            record.url_analysis = [
                url_cache.url(url, analyze_url_robust)
                for url in all_urls
            ]
            record.precursor_evidence = [
                indicator
                for analysis in record.url_analysis
                for indicator in analysis.get("indicators", [])
            ]
            record.deep_analyzed = True
        return pending

    jobs = [(i, records[i].path) for i in pending]
    chunksize = max(1, len(jobs) // (workers * 4))
    for index, payload in parallel_map(_deep_analyze_worker, jobs, workers, chunksize):
        _apply_deep_result(records, url_cache, index, payload)
    return pending
 
 
def v6_render_progress(phase, completed, total, started):
    elapsed = max(time.monotonic() - started, 0.001)
    rate = completed / elapsed
    percent = (100.0 * completed / total) if total else 100.0
    eta = ((total - completed) / rate) if total and rate else 0.0
    print(
        f"\r[{percent:6.2f}%] {phase}: {completed}/{total} "
        f"({rate:.1f}/s, ETA {eta:.1f}s)",
        end="",
        flush=True,
    )
 
 
# ============================================================================
# DEEP FORENSIC ENRICHMENT
# ============================================================================
 
# ============================================================================
# REPORTING
# ============================================================================
 
from postmortem.reporting import (  # noqa: E402
    print_summary, print_initial_compromise, print_campaigns,
    print_run_manifest, build_run_manifest, generate_html_interactive,
    write_json, write_csv, print_attack_narrative, print_audit_summary,
    print_top_domains, top_flagged_domains,
)
from postmortem import term  # noqa: E402
from contextlib import contextmanager  # noqa: E402


@contextmanager
def phase(label):
    """Announce a potentially slow phase and report how long it took, so the
    console never looks hung during clustering, deep analysis, geo/RDAP, etc."""
    print(term.c(f">> {label}...", "cyan"))
    start = time.monotonic()
    try:
        yield
    finally:
        print(term.c(f"   done: {label} ({time.monotonic() - start:.1f}s)", "green", "dim"))


def _merge_audit_anchors(anchors, audit_summary):
    """Union UAL-derived anchors into the analyst-supplied Anchors object.

    Explicit CLI anchors win where they conflict (compromise date); list
    anchors are unioned so nothing the analyst provided is lost.
    """
    d = audit_summary.get("derived", {})
    if anchors.compromise_date is None and d.get("compromise_date"):
        anchors.compromise_date = parse_anchor_datetime(d["compromise_date"])

    def union(existing, extra):
        seen = list(existing)
        for item in extra:
            if item and item not in seen:
                seen.append(item)
        return seen

    anchors.attacker_ips = union(anchors.attacker_ips, d.get("attacker_ips", []))
    anchors.attacker_addresses = union(
        anchors.attacker_addresses, [a.lower() for a in d.get("attacker_addresses", [])])
    anchors.attacker_domains = union(
        anchors.attacker_domains, [x.lower() for x in d.get("attacker_domains", [])])
    anchors.rule_keywords = union(
        anchors.rule_keywords, [k.lower() for k in d.get("rule_keywords", [])])
# ============================================================================
# PROGRESS BAR
# ============================================================================
 
def progress_bar(
    current: int,
    total: int,
    width: int = 35,
):
 
    if total <= 0:
        return
 
    ratio = (
        current / total
    )
 
    filled = int(
        width * ratio
    )
 
    bar = (
        "#"
        * filled
        + "-"
        * (
            width - filled
        )
    )
 
    percent = (
        ratio * 100
    )
 
    print(
        f"\r[{bar}] "
        f"{percent:6.2f}% "
        f"{current}/{total}",
        end="",
        file=sys.stderr,
        flush=True,
    )
 
    if current >= total:
        print(
            file=sys.stderr
        )
 
 
# ============================================================================
# MAIN
# ============================================================================
 


def main():
 
    parser = argparse.ArgumentParser(
        prog="postmortem",
        description=(
            "Recursively analyze .eml files for "
            "potential BEC/phishing emails and campaigns."
        )
    )
 
    parser.add_argument(
        "directory",
        type=Path,
        help="Directory of .eml files, or a PST/OST/MBOX container (or a "
             "directory containing such containers). Containers are exploded "
             "into .eml files under an extraction folder first.",
    )

    parser.add_argument(
        "--extract-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="Where to write .eml files extracted from PST/OST/MBOX containers "
             "(default: <scan root>/.postmortem_extracted).",
    )

    parser.add_argument(
        "--reingest",
        action="store_true",
        help="Re-extract containers even if a prior extraction already exists.",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write HTML report",
    )
 
    parser.add_argument(
        "--json",
        type=Path,
        help="Write JSON report",
    )

    parser.add_argument(
        "--csv",
        type=Path,
        help="Write a per-message CSV with all timestamps converted to UTC",
    )

    parser.add_argument(
        "--ioc",
        type=Path,
        help="Write a pivot-ready CSV of indicators of compromise (domains, "
             "URLs, IPs, hashes) extracted from the Tier 1/2 suspects",
    )

    parser.add_argument(
        "--html-limit",
        type=int,
        default=1000,
        help="Max messages embedded in the HTML report, highest-scoring first "
             "(default: %(default)s; 0 = all). The JSON/CSV reports always "
             "contain every message.",
    )

    parser.add_argument(
        "--config",
        type=Path,
        help="JSON file overriding scoring weights, thresholds, clustering caps, "
             "and baseline minimums (see CONFIG in the source for keys). The "
             "effective values are recorded in the run manifest.",
    )

    parser.add_argument(
        "--screen-chars",
        type=int,
        default=16000,
        help="Characters of each message body scanned during fast candidate "
             "screening (pass 1). Lower is faster on long-body mail at a small "
             "risk of missing a term buried deep in a body (default: %(default)s).",
    )
 
    parser.add_argument(
        "--workers",
        type=int,
        default=min(
            8,
            max(
                1,
                os.cpu_count()
                or 4,
            ),
        ),
        help=(
            "Number of parallel parsing workers "
            "(default: %(default)s)"
        ),
    )
 
    parser.add_argument(
        "--cache",
        type=Path,
        help="SQLite analysis cache path (default: <directory>/.postmortem_cache.sqlite3)",
    )

    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Ignore any existing cached results and re-parse every message fresh",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color in the console output (auto-disabled when not "
             "a terminal or when NO_COLOR is set).",
    )
 
    parser.add_argument(
        "--content-hash",
        action="store_true",
        help="Compute full SHA-256 for each uncached .eml for cross-path duplicate reuse",
    )
 
    parser.add_argument(
        "--candidate-threshold",
        type=int,
        default=5,
        help="Minimum V8 fast-pass score for deep analysis (default: 5)",
    )
 
    parser.add_argument(
        "--campaign-threshold",
        type=float,
        default=0.38,
        help=(
            "Campaign similarity threshold "
            "(default: %(default)s)"
        ),
    )

    # --- Incident anchors: what the investigator already knows ---------------
    anchor_group = parser.add_argument_group(
        "incident anchors",
        "Ground-truth facts to focus the search on the actual compromise.",
    )
    anchor_group.add_argument(
        "--scenario",
        choices=["auto", "ato", "impersonation"],
        default="auto",
        help=(
            "BEC scenario profile. 'ato' = account-takeover (hunt the credential "
            "phish before the compromise); 'impersonation' = external fraud/vendor "
            "compromise (hunt the fraudulent request). 'auto' infers it (default)."
        ),
    )
    anchor_group.add_argument(
        "--compromise-date",
        default="",
        help=(
            "Timestamp of the earliest known attacker action (e.g. when a malicious "
            "mailbox rule was created). ISO 8601 or an email Date. In ATO mode the "
            "initial phish is sought before this time; later mail is treated as "
            "post-compromise."
        ),
    )
    anchor_group.add_argument(
        "--impersonated",
        action="append",
        metavar="NAME_OR_EMAIL",
        help="Impersonated party (exec/vendor). Repeatable or comma-separated.",
    )
    anchor_group.add_argument(
        "--fraud-account",
        action="append",
        metavar="ACCOUNT",
        help="Known fraudulent bank account / IBAN. Repeatable or comma-separated.",
    )
    anchor_group.add_argument(
        "--attacker-domain",
        action="append",
        metavar="DOMAIN",
        help="Known attacker domain (e.g. a rule's forwarding target). Repeatable.",
    )
    anchor_group.add_argument(
        "--victim-domain",
        action="append",
        metavar="DOMAIN",
        help="The victim organization's own email domain(s), for self-spoofing "
             "detection. Repeatable/comma-separated; inferred if omitted.",
    )
    anchor_group.add_argument(
        "--attacker-ip",
        action="append",
        metavar="IP",
        help="Attacker sending IP from sign-in/audit logs (matched against each "
             "message's originating IP). Repeatable/comma-separated.",
    )
    anchor_group.add_argument(
        "--attacker-address",
        action="append",
        metavar="EMAIL",
        help="Known attacker email address (matched against sender and Reply-To). "
             "Repeatable/comma-separated.",
    )
    anchor_group.add_argument(
        "--rule-keyword",
        action="append",
        metavar="TERM",
        help="Keyword the malicious mailbox rule filtered on (surfaces messages "
             "the attacker was hiding). Repeatable/comma-separated.",
    )
    anchor_group.add_argument(
        "--audit-log",
        type=Path,
        metavar="FILE",
        help="M365 Unified Audit Log export (Purview CSV, Search-UnifiedAuditLog "
             "JSON/JSONL, or Management/Graph JSON). Anchors (compromise date, "
             "attacker IP/address/domain, rule keywords) are derived from it "
             "automatically and its attacker actions become confirmed evidence.",
    )
    anchor_group.add_argument(
        "--allowlist",
        action="append",
        metavar="DOMAIN",
        help="Known-good sending domain(s) whose weak header-hygiene noise "
             "(chronic auth failure, thin Received chain, missing Date) is "
             "suppressed -- only when the message shows no active spoofing "
             "signal. Alignment/impersonation/content checks are never "
             "suppressed. Repeatable/comma-separated.",
    )

    parser.add_argument(
        "--fail-on-tier",
        type=int,
        default=0,
        metavar="N",
        help="CI gating: exit with code 3 if any message lands in review tier N "
             "or higher (1=prime suspects, 2=+secondary). Default 0 = always "
             "exit 0 on a successful scan.",
    )

    enrich = parser.add_argument_group(
        "optional enrichment",
        "Opt-in passes over the Tier 1/2 suspects; some need extra packages or "
        "network access.")
    enrich.add_argument(
        "--check-domain-age",
        nargs="?", type=int, const=90, default=None, metavar="DAYS",
        help="ONLINE: query RDAP for each suspect sender domain's registration "
             "date and flag domains registered within DAYS of the message "
             "(default 90). Results are cached on disk. Off unless given.",
    )
    enrich.add_argument(
        "--yara-rules",
        type=Path, metavar="FILE",
        help="Scan suspect attachments with these compiled/uncompiled YARA "
             "rules (needs the yara-python package; skipped with a warning if "
             "absent).",
    )
    enrich.add_argument(
        "--scan-qr",
        action="store_true",
        help="Decode QR codes in suspect image attachments and analyze the "
             "linked URLs (needs pyzbar + Pillow; skipped with a warning if "
             "absent).",
    )
    enrich.add_argument(
        "--geoip-db",
        action="append", type=Path, metavar="FILE",
        help="Local MaxMind GeoLite2 .mmdb (City/Country and/or ASN). "
             "Geolocates originating/Received IPs of suspects; repeatable. "
             "Offline; needs the 'maxminddb' reader.",
    )
    enrich.add_argument(
        "--expected-countries",
        metavar="CC[,CC...]",
        help="ISO country codes the org normally sends/receives from (e.g. "
             "US,GB). With --geoip-db, a hop outside this set is flagged as "
             "suspicious geography.",
    )

    args = parser.parse_args()

    term.set_enabled(not args.no_color and term.supports_color())

    run_started = time.monotonic()

    if args.config:
        try:
            load_config(args.config)
            print(f"Loaded scoring config overrides from {args.config}")
        except Exception as exc:
            print(f"Error: could not load --config {args.config}: {exc}", file=sys.stderr)
            return 2

    if not args.directory.exists():

        print(
            f"Error: path does not exist: "
            f"{args.directory}",
            file=sys.stderr,
        )

        return 1

    if args.workers < 1:

        print(
            "Error: --workers must be >= 1",
            file=sys.stderr,
        )

        return 1

    # The input may be a directory of .eml, a PST/OST/MBOX container, or a
    # directory that contains such containers.
    input_is_container_file = args.directory.is_file()

    # ------------------------------------------------------------------
    # Container ingestion (PST/OST/MBOX -> .eml, folders preserved)
    # ------------------------------------------------------------------
    containers = find_containers(args.directory)
    if containers:
        base = args.directory if args.directory.is_dir() else args.directory.parent
        extract_dir = args.extract_dir or (base / ".postmortem_extracted")
        print(
            f"Detected {len(containers)} mail container(s) "
            f"({', '.join(sorted({c.suffix.lower().lstrip('.') for c in containers}))}); "
            f"extracting to {extract_dir}"
        )
        ingest = ingest_all(args.directory, extract_dir, reingest=args.reingest)
        print(
            f"Extracted {ingest['messages_written']} message(s) "
            f"from {ingest['containers_found']} container(s)"
        )
        for skip in ingest.get("skipped", []):
            print(f"[!] Skipped {Path(skip['container']).name}: {skip['note']}",
                  file=sys.stderr)
        # A bare container file: analyze only what we extracted from it, not
        # whatever else happens to sit in its parent directory.
        scan_root = extract_dir if input_is_container_file else args.directory
    elif input_is_container_file:
        print(f"Error: not an ingestable container: {args.directory}",
              file=sys.stderr)
        return 1
    else:
        scan_root = args.directory

    print(
        f"Scanning: {scan_root}"
    )

    eml_files = sorted(
        p
        for p in scan_root.rglob("*")
        if (
            p.is_file()
            and p.suffix.lower()
            == ".eml"
        )
    )

    print(
        f"Found {len(eml_files)} .eml files"
    )

    if not eml_files:

        print(
            "No .eml files found."
        )

        return 0

    # ------------------------------------------------------------------
    # V7 RESUMABLE FAST PARSE
    # ------------------------------------------------------------------
    cache_path = args.cache or (scan_root / ".postmortem_cache.sqlite3")
    cache = SQLiteRecordCache(cache_path)
 
    records = []
    cache_hits = 0
    hash_reuses = 0
    parse_jobs = []
 
    if args.no_cache:
        print("Cache disabled (--no-cache): parsing every message fresh...")
    else:
        print("Checking persistent analysis cache (metadata fast-path; no full-file hashing yet)...")
    for index, path in enumerate(eml_files, 1):
        cached = None
        if not args.no_cache:
            try:
                cached = cache.fast_get(path)
            except OSError:
                cached = None
 
        if cached:
            _, record = cached
            records.append(record)
            cache_hits += 1
        else:
            parse_jobs.append(path)
 
        progress_bar(index, len(eml_files))
 
    print()
    print(
        f"Cache reuse: {cache_hits}/{len(eml_files)} "
        f"({(100.0 * cache_hits / len(eml_files)) if eml_files else 0.0:.1f}%)"
    )
 
    if parse_jobs:
        print(f"Parsing {len(parse_jobs)} uncached file(s)...")
        parsed = []
        if args.workers == 1 or len(parse_jobs) < _PROCESS_POOL_MIN_JOBS:
            # Serial: cheap for small mailboxes and avoids process start-up cost.
            workers = 1
            chunksize = 1
        else:
            # Process pool (auto-falls back to serial if unavailable): real
            # parallelism for CPU-bound MIME parsing.
            workers = max(1, min(args.workers, 16))
            chunksize = max(1, len(parse_jobs) // (workers * 4))
        for completed, result in enumerate(
            parallel_map(_parse_uncached_worker, parse_jobs, workers, chunksize), 1
        ):
            parsed.append(result)
            progress_bar(completed, len(parse_jobs))

        print()
 
        # Content-hash only uncached/changed files. This enables moved/renamed
        # duplicate detection, but it is deliberately a separate visible phase.
        # Hashing is parallelized with the same bounded worker count.
        hash_jobs = [(path, record) for path, record in parsed if record is not None]
        hash_total = len(hash_jobs)
        hash_started = time.monotonic()
 
        if not args.content_hash:
            print(
                "Skipping full-file SHA-256 for uncached .eml files "
                "(metadata identity mode; use --content-hash to enable it)..."
            )
            hashed = []
            for completed, (path, record) in enumerate(hash_jobs, 1):
                try:
                    record._cache_file_sha256 = ""
                    records.append(record)
                except Exception as exc:
                    print(
                        f"\n[!] Cache preparation error for {path}: {exc}",
                        file=sys.stderr,
                    )
                v8_cache_progress(
                    "metadata cache preparation",
                    completed,
                    hash_total,
                    hash_started,
                )
            print()
        else:
            print(f"Hashing uncached messages ({hash_total} files)...")
 
            def hash_one(item):
                path, record = item
                return path, record, sha256_file(path)

            hashed = []
            hash_workers = max(1, min(args.workers, 16))
 
            if hash_workers == 1:
                for completed, item in enumerate(hash_jobs, 1):
                    try:
                        hashed.append(hash_one(item))
                    except Exception as exc:
                        path, record = item
                        print(
                            f"\n[!] Hash error for {path}: {exc}",
                            file=sys.stderr,
                        )
                    v8_cache_progress(
                        "content hashing", completed, hash_total, hash_started
                    )
            else:
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=hash_workers
                ) as executor:
                    future_map = {
                        executor.submit(hash_one, item): item
                        for item in hash_jobs
                    }
                    for completed, future in enumerate(
                        concurrent.futures.as_completed(future_map), 1
                    ):
                        path, record = future_map[future]
                        try:
                            hashed.append(future.result())
                        except Exception as exc:
                            print(
                                f"\n[!] Hash error for {path}: {exc}",
                                file=sys.stderr,
                            )
                        v8_cache_progress(
                            "content hashing",
                            completed,
                            hash_total,
                            hash_started,
                        )
        print()
 
        # Batch metadata records in normal mode. This avoids both full-file
        # hashing and per-record SQLite commits on the first run.
        if not args.content_hash:
            persist_started = time.monotonic()
            print(f"Persisting metadata cache ({len(hash_jobs)} records)...")
            metadata_rows = []
            batch_size = 1000
 
            for completed, (path, record) in enumerate(hash_jobs, 1):
                try:
                    st = path.stat()
                    metadata_rows.append((
                        str(path),
                        st.st_size,
                        st.st_mtime_ns,
                        "",
                        V7_PARSER_VERSION,
                        json.dumps(asdict(record), ensure_ascii=False),
                    ))
                    if len(metadata_rows) >= batch_size:
                        cache.put_batch(metadata_rows)
                        metadata_rows.clear()
                except Exception as exc:
                    print(
                        f"\n[!] Metadata cache error for {path}: {exc}",
                        file=sys.stderr,
                    )
                v8_cache_progress(
                    "metadata cache persistence",
                    completed,
                    len(hash_jobs),
                    persist_started,
                )
 
            if metadata_rows:
                cache.put_batch(metadata_rows)
            print()
        else:
            # Batch content-hash lookups first, then batch all new/updated records
            # into a small number of SQLite transactions.
            persist_started = time.monotonic()
            print(f"Updating persistent cache ({len(hashed)} records)...")
 
            hash_values = [file_hash for _, _, file_hash in hashed]
            prior_by_hash = cache.get_by_hash_batch(hash_values)
 
            cache_rows = []
            batch_size = 1000
 
            for completed, (path, record, file_hash) in enumerate(hashed, 1):
                try:
                    prior = prior_by_hash.get(file_hash)
                    if prior is not None:
                        prior.path = str(path)
                        prior.filename = path.name
                        prior._cache_file_sha256 = file_hash
                        records.append(prior)
                        hash_reuses += 1
                    else:
                        record._cache_file_sha256 = file_hash
                        records.append(record)
                        st = path.stat()
                        cache_rows.append((
                            str(path),
                            st.st_size,
                            st.st_mtime_ns,
                            file_hash,
                            V7_PARSER_VERSION,
                            json.dumps(asdict(record), ensure_ascii=False),
                        ))
 
                        if len(cache_rows) >= batch_size:
                            cache.put_batch(cache_rows)
                            cache_rows.clear()
                except Exception as exc:
                    print(
                        f"\n[!] Cache error for {path}: {exc}",
                        file=sys.stderr,
                    )
                    records.append(record)
 
                v8_cache_progress(
                    "cache persistence", completed, len(hashed), persist_started
                )
 
            if cache_rows:
                cache.put_batch(cache_rows)
 
            print()
 
    if not records:
        cache.close()
 
    if not records:
 
        print(
            "No parseable .eml files found."
        )
 
        return 0
 
    # Keep deterministic order.
    records.sort(
        key=lambda r: r.path
    )
 
    # ------------------------------------------------------------------
    # Infer organization
    # ------------------------------------------------------------------
 
    internal_domains = (
        identify_internal_domains(
            records
        )
    )
 
    known_contacts = (
        identify_known_contacts(
            records
        )
    )
 
    print()
 
    print(
        "Likely internal domains:",
        (
            ", ".join(
                sorted(
                    internal_domains
                )
            )
            if internal_domains
            else "(unable to determine)"
        ),
    )
 
    # ------------------------------------------------------------------
    # Initial scoring
    # ------------------------------------------------------------------
 
    for record in records:
 
        calculate_score(
            record,
            internal_domains,
            known_contacts,
        )
 
    # ------------------------------------------------------------------
    # Thread analysis
    # ------------------------------------------------------------------
 
    calculate_thread_ids(
        records
    )
 
    detect_possible_impersonation(
        records
    )
 
    analyze_temporal_signals(
        records
    )
 
    # ------------------------------------------------------------------
    # V6 TWO-PASS ANALYSIS
    # Pass 1 is intentionally cheap. Only candidates receive expensive
    # URL/deep enrichment in pass 2.
    # ------------------------------------------------------------------
    total_records = len(records)
    started = time.monotonic()

    print()
    print("V6 two-pass analysis")
    print("Pass 1/2: fast candidate screening")
 
    candidate_indexes = []
    for index, record in enumerate(records):
        candidate, score, reasons = v8_candidate_score(record, args.screen_chars)
        # User threshold controls normal promotion; strong independent
        # signals remain protected.
        candidate = (
            score >= args.candidate_threshold
            or candidate
        )
        record.fast_candidate_score = score
        record.fast_candidate_reasons = reasons
        if candidate:
            candidate_indexes.append(index)
 
        if (index + 1) == total_records or (index + 1) % max(1, total_records // 100 or 1) == 0:
            v6_render_progress("candidate screening", index + 1, total_records, started)
 
    print()
    print(
        f"Candidate reduction: {len(candidate_indexes)}/{total_records} "
        f"({(100.0 * len(candidate_indexes) / total_records) if total_records else 0.0:.1f}%)"
    )
 
    reason_counts = {}
    for index in candidate_indexes:
        for reason in getattr(records[index], "fast_candidate_reasons", []) or []:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
 
    if reason_counts:
        print("Candidate signal breakdown:")
        for reason, count in sorted(
            reason_counts.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            print(f"  {reason}: {count}")
 
    url_cache = AnalysisCache()
 
    # Configurable bounded concurrency. Keep this modest by default so large
    # investigations do not overwhelm disk/CPU.
    max_workers = max(
        1,
        min(
            int(os.environ.get("BEC_HUNT_WORKERS", "4")),
            16,
        ),
    )
 
    print(f"Pass 2/2: deep enrichment ({max_workers} workers)")
    analyzed_indexes = v6_parallel_deep_analysis(
        records,
        candidate_indexes,
        max_workers=max_workers,
        url_cache=url_cache,
    )
 
    # Persist fully enriched candidate records. The initial cache stage has
    # already computed file hashes, so avoid hashing the entire .eml a second
    # time. Fall back to hashing only if this record was recovered from an
    # older/in-memory path that did not expose its hash.
    print(f"Persisting deep-analysis results ({len(analyzed_indexes)} candidates)...")
    deep_persist_started = time.monotonic()
    deep_rows = []
    deep_batch_size = 1000
 
    for completed, index in enumerate(analyzed_indexes, 1):
        record = records[index]
        try:
            file_hash = getattr(record, "_cache_file_sha256", None)
            if not file_hash:
                # Metadata identity mode intentionally stores an empty hash and
                # reuses records by (path, size, mtime); only pay for full-file
                # hashing when the user explicitly requested content hashing.
                file_hash = (
                    sha256_file(Path(record.path))
                    if args.content_hash
                    else ""
                )
 
            path = Path(record.path)
            st = path.stat()
            deep_rows.append((
                str(path),
                st.st_size,
                st.st_mtime_ns,
                file_hash,
                V7_PARSER_VERSION,
                json.dumps(asdict(record), ensure_ascii=False),
            ))
 
            if len(deep_rows) >= deep_batch_size:
                cache.put_batch(deep_rows)
                deep_rows.clear()
 
        except Exception as exc:
            print(
                f"\n[!] Could not persist cache for {record.path}: {exc}",
                file=sys.stderr,
            )
 
        v8_cache_progress(
            "deep cache persistence",
            completed,
            len(analyzed_indexes),
            deep_persist_started,
        )
 
    if deep_rows:
        cache.put_batch(deep_rows)
 
    print()
 
    # Records skipped by pass 2 still receive a predictable empty structure.
    candidate_set = set(candidate_indexes)
    for index, record in enumerate(records):
        if index not in candidate_set:
            record.url_analysis = []
            record.precursor_evidence = []

    # Classify the attack stage for every record so downstream evidence
    # graphing and precursor analysis can rely on it being populated.
    for record in records:
        record.attack_stage = classify_attack_stage(record)

    with phase("Building indexed evidence relationships"):
        evidence_indexes = v6_build_indexes(records)

 
    # ------------------------------------------------------------------
    # Deduplicate indicators
    # ------------------------------------------------------------------
 
    for record in records:
 
        record.indicators = list(
            dict.fromkeys(
                record.indicators
            )
        )
 
    # ------------------------------------------------------------------
    # Campaign clustering
    # ------------------------------------------------------------------
 
    print()
    with phase("Clustering related messages"):
        campaigns = build_campaign_clusters(
            records,
            threshold=args.campaign_threshold,
        )
    print(
        f"Identified {len(campaigns)} "
        f"multi-message campaign(s)."
    )

    # ------------------------------------------------------------------
    # Scenario / anchor analysis: identify the initial malicious email
    # ------------------------------------------------------------------
    anchors = build_anchors(args)

    # Optional: ingest an M365 Unified Audit Log to derive anchors from the
    # attacker's own recorded actions and add confirmed evidence.
    audit_summary = None
    if getattr(args, "audit_log", None):
        try:
            audit_summary = analyze_audit_log(args.audit_log)
        except Exception as exc:  # noqa: BLE001 - report and continue
            print(f"[!] Could not parse --audit-log {args.audit_log}: {exc}",
                  file=sys.stderr)
            audit_summary = None
        if audit_summary:
            _merge_audit_anchors(anchors, audit_summary)
            audit_summary.pop("_compromise_dt", None)
            print_audit_summary(audit_summary)

    allowlist = []
    for value in (args.allowlist or []):
        allowlist.extend(
            registered_domain_approx(part.strip())
            for part in str(value).split(",") if part.strip()
        )
    scenario, scenario_reason, initial_verdict = run_scenario_analysis(
        records, internal_domains, anchors, audit_summary, allowlist=allowlist
    )
    if audit_summary:
        initial_verdict["audit_log"] = audit_summary
    print(f"Scenario profile:  {scenario} ({scenario_reason})")

    # Optional enrichment passes over the Tier 1/2 suspects. Each annotates and
    # can promote a confirmed hit to Tier 1; run before IOC/clustering/reporting.
    enriched = False
    if getattr(args, "check_domain_age", None) is not None:
        from postmortem.netcheck import DomainAgeChecker, annotate_records
        with phase("Domain-age lookups (RDAP, online)"):
            checker = DomainAgeChecker(
                cache_path=scan_root / ".postmortem_domain_cache.json")
            n = annotate_records(records, checker, args.check_domain_age)
        print(f"Domain-age (RDAP): {n} newly-registered sender domain(s) "
              f"(< {args.check_domain_age}d)")
        enriched = enriched or bool(n)
    if getattr(args, "yara_rules", None):
        from postmortem.yara_scan import scan_records as yara_scan
        with phase("YARA scan of suspect attachments"):
            n = yara_scan(records, args.yara_rules)
        print(f"YARA: {n} attachment match(es)")
        enriched = enriched or bool(n)
    if getattr(args, "scan_qr", False):
        from postmortem.qr_scan import scan_records as qr_scan
        with phase("QR-code decode of suspect images"):
            n = qr_scan(records)
        print(f"QR scan: {n} QR-code URL(s) in image attachments")
        enriched = enriched or bool(n)
    if getattr(args, "geoip_db", None):
        from postmortem.geoip import GeoResolver, annotate_records as geo_annotate
        from postmortem.config import CONFIG as _CFG
        with phase("GeoIP / ASN lookups"):
            resolver = GeoResolver(args.geoip_db)
            geo_n = host_n = 0
            if resolver.available():
                expected = [c for c in (args.expected_countries or "").split(",") if c.strip()]
                geo_n, host_n = geo_annotate(
                    records, resolver, expected, _CFG.get("high_abuse_asn_keywords", []))
                resolver.close()
        if resolver.available():
            print(f"GeoIP: {geo_n} suspicious-geography, {host_n} "
                  f"high-abuse-hosting message(s)")
            enriched = enriched or bool(geo_n or host_n)
    if enriched:
        initial_verdict["tier_counts"] = {
            t: sum(1 for r in records if r.tier == t) for t in (1, 2, 3)}

    # Pivot-ready indicators of compromise from the Tier 1/2 suspects.
    iocs = extract_iocs(records)
    if iocs:
        by_type = Counter(e["type"] for e in iocs)
        print("Indicators of compromise (Tier 1/2): "
              + ", ".join(f"{t}={by_type[t]}" for t in sorted(by_type)))

    timeline = build_attack_timeline(records)
    precursor_verdict = earliest_malicious_precursor_verdict(records)

    manifest = build_run_manifest(
        args, records, scenario, anchors, initial_verdict, campaigns, iocs,
        generated_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        elapsed_seconds=time.monotonic() - run_started,
    )

    print()
    print(f"Persistent cache hits: {cache_hits}")
    print(f"Content-hash cache reuse: {hash_reuses}")
    print("=" * 80)
    print("PERFORMANCE SUMMARY")
    print("=" * 80)
    print(f"Messages analyzed: {len(records)}")
    print(f"URLs analyzed:     {sum(len(r.url_analysis) for r in records)}")
    print(f"Attachments seen:  {sum(len(r.attachments) for r in records)}")
    print(f"Unique URL cache:  {len(url_cache.urls)}")
    print(f"Candidate messages: {len(candidate_indexes)}/{len(records)}")
    print(f"Workers:            {max_workers}")
    print(f"Indexed domains:    {len(evidence_indexes['domain'])}")
    print(f"Indexed SHA-256s:   {len(evidence_indexes['sha256'])}")
    print("=" * 80)
 
    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
 
    print_summary(
        records,
        timeline,
        precursor_verdict,
    )

    print_initial_compromise(initial_verdict)

    print_attack_narrative(initial_verdict.get("attack_narrative"))

    print_top_domains(top_flagged_domains(records))

    print_campaigns(
        campaigns,
        records,
    )

    print_run_manifest(manifest)

    if args.output:

        with phase("Generating interactive HTML report"):
            generate_html_interactive(
                records,
                campaigns,
                args.output,
                timeline,
                precursor_verdict,
                initial_verdict,
                limit=args.html_limit,
            )

        print(
            f"HTML report written to: "
            f"{args.output}"
        )

    if args.json:

        write_json(
            records,
            campaigns,
            timeline,
            precursor_verdict,
            args.json,
            initial_verdict,
            iocs,
            manifest,
        )

        print(
            f"JSON report written to: "
            f"{args.json}"
        )

    if args.csv:

        write_csv(records, args.csv)

        print(
            f"CSV (UTC) written to: "
            f"{args.csv}"
        )

    if args.ioc:

        write_iocs_csv(iocs, args.ioc)

        print(
            f"IOC list ({len(iocs)} indicators) written to: {args.ioc}"
        )

    # CI gating: exit non-zero (3) when suspects meet the requested tier.
    if args.fail_on_tier:
        flagged = sum(1 for r in records if r.tier <= args.fail_on_tier)
        if flagged:
            print(
                f"\n[fail-on-tier] {flagged} message(s) at tier <= "
                f"{args.fail_on_tier}; exiting 3 for CI gating.",
                file=sys.stderr,
            )
            return 3

    return 0
 
 
if __name__ == "__main__":
    raise SystemExit(
        main()
    )
