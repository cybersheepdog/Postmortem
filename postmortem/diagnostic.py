"""Sanitized diagnostic report -- shareable telemetry about a run.

The problem this solves: the corpus, the log and the report all contain client
data, so the only thing anyone outside the engagement ever sees is a
description of the output. That makes it hard to judge whether the tool is
working well, and impossible to judge it quantitatively.

What this emits instead is a statistical profile of the run: which signals
fired and how often, what the score distribution looks like, where the time
went, how the tiers came out. All of that is a property of the *tool*, not of
the client.

Three defences, because one is not enough for a file whose entire purpose is
to be sent somewhere else:

  1. Nothing is copied from the corpus. The report is built from counts,
     distributions and signal *templates* -- never from a record's fields.
  2. Every signal string is reduced to its template before it is counted:
     "External sender: acme.com" becomes "External sender: <domain>". The
     variable half is what identifies a client, and it is discarded rather
     than redacted, so there is nothing to leak.
  3. The finished document is scanned for identifier patterns before it is
     written, and the write is refused if any survive.

Read the file before sending it. It is designed to be readable precisely so
that it can be checked.
"""

import json
import platform
import re
import sys
from collections import Counter

SCHEMA = "postmortem-diagnostic/1"

# --------------------------------------------------------------------------
# Templating
#
# A signal string mixes a fixed description with client-specific values. The
# fixed half is what carries diagnostic meaning; the variable half is what
# identifies someone. Everything that could be a value is replaced by a type
# marker, so what remains is the shape of the finding.
# --------------------------------------------------------------------------

_SUBS = (
    # Timestamps first: they are the most specific pattern here, and
    # the IPv6 rule below otherwise swallows the clock half of a
    # space-separated stamp. The generic number rule cannot template
    # one at all -- \b\d[\d,]*\b fails on the 24 in "24T17" because
    # 4 and T are both word characters -- so an ISO stamp came out as
    # <n>-<n>-24T17:<n>:46Z and every distinct second became its own
    # signal. On a real corpus that split one audit finding into 197
    # rows, 79% of the table, burying everything worth reading.
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<timestamp>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}\b"), "<date>"),
    (re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\b"), "<time>"),
    # Longest and most specific first -- an email must be caught before the
    # domain pattern gets to the half of it after the @.
    (re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), "<email>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (re.compile(r"\b[0-9A-Fa-f:]{2,}:[0-9A-Fa-f:]{2,}\b"), "<ip6>"),
    (re.compile(r"https?://\S+"), "<url>"),
    (re.compile(r"\b[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+\.[A-Za-z]{2,}\b"), "<domain>"),
    (re.compile(r"\b[A-Za-z0-9\-]{2,}\.[A-Za-z]{2,24}\b"), "<domain>"),
    (re.compile(r"[A-Za-z]:\\[^\s'\"]+"), "<path>"),
    (re.compile(r"(?<![A-Za-z0-9])/[^\s'\"]{2,}"), "<path>"),
    (re.compile(r"<[^@\s>]+@[^\s>]+>"), "<message-id>"),
    (re.compile(r"'[^']{1,200}'"), "'<value>'"),
    (re.compile(r'"[^"]{1,200}"'), '"<value>"'),
    (re.compile(r"\b[A-Fa-f0-9]{32,64}\b"), "<hash>"),
    (re.compile(r"\b\d[\d,]*\b"), "<n>"),
)


def _own_vocabulary():
    """Strings the tool itself defines, which carry no client information.

    Without this every "Contains phrase: 'wire transfer'" collapses into one
    indistinguishable line, and the report loses exactly the detail it exists
    to show -- which of the term list is earning its place. These phrases are
    ours, not the client's.
    """
    safe = set()
    try:
        from postmortem.config import PHISHING_TERMS, RISKY_EXTENSIONS
        safe |= {str(k).lower() for k in PHISHING_TERMS}
        safe |= {str(x).lower() for x in RISKY_EXTENSIONS}
    except Exception:
        pass
    try:
        # Graph permission scopes and the persistence kinds are fixed
        # vocabulary -- Microsoft's and ours. Which scopes an attacker
        # asked for is the most useful thing the diagnostic can carry
        # about a consent grant, and it says nothing about the client.
        # Registered explicitly rather than left to chance: today none
        # of them happens to end in a public suffix, and a scope added
        # later might.
        from postmortem.persistence import (
            _MAIL_SCOPES, _HIGH_RISK_SCOPES, _DURABILITY_SCOPES,
            _REMEDIATION)
        safe |= {s.lower() for s in _MAIL_SCOPES}
        safe |= {s.lower() for s in _HIGH_RISK_SCOPES}
        safe |= {s.lower() for s in _DURABILITY_SCOPES}
        safe |= {k.lower() for k in _REMEDIATION}
    except Exception:
        pass
    try:
        from postmortem import scoring
        for name in ("_URGENCY_TERMS", "_PAYMENT_TERMS", "_CREDENTIAL_LURES",
                     "_BANK_CHANGE_TERMS", "_LOGIN_PATH_HINTS"):
            safe |= {str(x).lower() for x in getattr(scoring, name, ()) or ()}
    except Exception:
        pass
    return frozenset(t for t in safe if t)


_OWN_VOCABULARY = None


def _quote_sub(match, marker):
    """Keep a quoted value when it is one of the tool's own terms."""
    global _OWN_VOCABULARY
    if _OWN_VOCABULARY is None:
        _OWN_VOCABULARY = _own_vocabulary()
    inner = match.group(0)[1:-1]
    if inner.lower() in _OWN_VOCABULARY:
        return match.group(0)
    return marker


def template(text):
    """Reduce one signal to its shape, discarding every value in it."""
    out = str(text or "")
    for pattern, marker in _SUBS:
        if marker in ("'<value>'", '"<value>"'):
            out = pattern.sub(lambda m, _m=marker: _quote_sub(m, _m), out)
        else:
            out = pattern.sub(marker, out)
    return out.strip()[:160]


# Patterns that must not survive into the finished document. Deliberately
# broader than the substitutions above: this is the check, not the transform,
# and it is allowed to be paranoid.
_FORBIDDEN = (
    ("email address", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    ("IPv4 address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("URL", re.compile(r"https?://")),
    ("Windows path", re.compile(r"[A-Za-z]:\\")),
    ("UNC path", re.compile(r"\\\\[A-Za-z0-9]")),
    ("message-id", re.compile(r"<[^@\s>]+@[^\s>]+>")),
    ("hostname or domain",
     re.compile(r"\b(?!<)[A-Za-z0-9\-]{2,}\.(?:com|net|org|co|io|gov|edu|mil|"
                r"uk|de|fr|ru|cn|info|biz|us|ca|au|nl|se|ch|it|es|pl|br|in|jp)\b")),
)


def scan_for_identifiers(text):
    """Every forbidden pattern found in `text`, as (kind, example) pairs."""
    found = []
    for kind, pattern in _FORBIDDEN:
        for m in pattern.finditer(text):
            found.append((kind, m.group(0)))
            break
    return found


# --------------------------------------------------------------------------
# Distributions
# --------------------------------------------------------------------------

def _histogram(values, edges=(0, 1, 5, 10, 15, 20, 30, 40, 60, 100)):
    """Bucket counts. Buckets are fixed, so two runs are comparable."""
    buckets = Counter()
    for v in values:
        label = ">=%d" % edges[-1]
        for lo, hi in zip(edges, edges[1:]):
            if lo <= v < hi:
                label = "%d-%d" % (lo, hi - 1)
                break
        buckets[label] += 1
    order = ["%d-%d" % (lo, hi - 1) for lo, hi in zip(edges, edges[1:])]
    order.append(">=%d" % edges[-1])
    return [(k, buckets.get(k, 0)) for k in order if buckets.get(k, 0)]


def _quantiles(values):
    if not values:
        return {}
    vs = sorted(values)
    def at(q):
        return vs[min(len(vs) - 1, int(q * (len(vs) - 1)))]
    return {"min": vs[0], "p50": at(0.5), "p90": at(0.9), "p99": at(0.99),
            "max": vs[-1], "mean": round(sum(vs) / len(vs), 2)}



def _corpus_span_days(records):
    """Days between the first and last message that carries a usable date."""
    from postmortem.scoring import message_arrival_dt

    stamps = []
    for r in records or []:
        try:
            dt = message_arrival_dt(r)
        except Exception:
            dt = None
        if dt is not None:
            stamps.append(dt)
    if len(stamps) < 2:
        return None
    try:
        return (max(stamps) - min(stamps)).days
    except TypeError:
        # Mixed aware/naive datetimes: a span is not worth raising over.
        return None


def build(records, verdict=None, audit_summary=None, manifest=None,
          campaigns=None, timings=None, config=None,
          signin_summary=None, persistence=None):
    """Assemble the diagnostic. Reads counts and templates, never values."""
    verdict = verdict or {}
    records = list(records or [])
    total = len(records)

    scores = [int(getattr(r, "score", 0) or 0) for r in records]
    initial = [int(getattr(r, "scenario_score", 0) or 0) for r in records]
    tiers = Counter(int(getattr(r, "tier", 0) or 0) for r in records)

    # Which signals fire, how often, and what they contribute. This is the
    # heart of it: a signal that fires on 80% of a corpus is not a signal.
    fires = Counter()
    # Several signals fire more than once on a message (one per matched
    # phrase), so "share of corpus" has to count messages, not fires, or it
    # exceeds 100% and stops meaning anything.
    messages_with = Counter()
    weight_sum = Counter()
    categories = Counter()
    sources = Counter()
    zero_weight = Counter()
    for r in records:
        seen_here = set()
        for f in (getattr(r, "provenance", None) or []):
            if not isinstance(f, dict):
                continue
            key = template(f.get("signal", ""))
            fires[key] += 1
            seen_here.add(key)
            w = int(f.get("weight", 0) or 0)
            weight_sum[key] += w
            if w == 0:
                zero_weight[key] += 1
            categories[str(f.get("category", "?"))] += 1
            sources[str(f.get("source", "?"))] += 1
        for key in seen_here:
            messages_with[key] += 1

    signals = []
    for key, n in fires.most_common():
        msgs = messages_with[key]
        signals.append({
            "signal": key,
            "fires": n,
            "messages": msgs,
            "share_of_corpus": round(msgs / max(1, total), 4),
            "total_weight": weight_sum[key],
            "mean_weight": round(weight_sum[key] / n, 2),
            "always_zero_weight": zero_weight[key] == n,
        })

    # How often each signal appears on a Tier 1 message versus anywhere. A
    # signal that fires everywhere but never on a suspect is noise; one that
    # fires rarely and almost always on a suspect is the opposite.
    t1 = Counter()
    for r in records:
        if getattr(r, "tier", 0) != 1:
            continue
        for key in {template(f.get("signal", ""))
                    for f in (getattr(r, "provenance", None) or [])
                    if isinstance(f, dict)}:
            t1[key] += 1
    for entry in signals:
        n1 = t1.get(entry["signal"], 0)
        entry["tier1_messages"] = n1
        entry["precision_proxy"] = round(n1 / max(1, entry["messages"]), 4)

    doc = {
        "schema": SCHEMA,
        "note": ("Statistical profile of one run. Contains no addresses, "
                 "domains, hostnames, file names, paths, subjects, message "
                 "ids or IPs. Signal text is templated: values are discarded, "
                 "not redacted."),
        "tool": {
            "version": (manifest or {}).get("tool_version", ""),
            "parser_version": (manifest or {}).get("parser_version", ""),
            "python": "%d.%d" % sys.version_info[:2],
            "platform": platform.system(),
        },
        "corpus": {
            "messages": total,
            "with_attachments": sum(1 for r in records
                                    if getattr(r, "attachments", None)),
            "with_urls": sum(1 for r in records if getattr(r, "urls", None)),
            "inbound": sum(1 for r in records if getattr(r, "is_inbound", False)),
            "distinct_sender_domains": len({getattr(r, "sender_domain", "")
                                            for r in records
                                            if getattr(r, "sender_domain", "")}),
            "distinct_senders": len({getattr(r, "sender_email", "")
                                     for r in records
                                     if getattr(r, "sender_email", "")}),
            # Computed here rather than read from the manifest, which
            # never carried a span_days key -- so this reported null on
            # every run, including a corpus with 179 days of mail in it.
            "date_span_days": _corpus_span_days(records),
        },
        "tiers": {str(k): v for k, v in sorted(tiers.items())},
        "scores": {
            "priority": {"quantiles": _quantiles(scores),
                         "histogram": _histogram(scores)},
            "initial_email": {"quantiles": _quantiles(initial),
                              "histogram": _histogram(initial)},
        },
        "signals": signals[:250],
        "signal_categories": categories.most_common(),
        "signal_sources": sources.most_common(),
        "verdict": {
            "verdict": verdict.get("verdict", ""),
            "confidence": verdict.get("confidence", ""),
            "scenario": verdict.get("scenario", ""),
            "has_initial_email": bool(verdict.get("initial_email")),
            "initial_score": (verdict.get("initial_email") or {}).get(
                "initial_score", None),
            "shortlist_size": len(verdict.get("shortlist") or []),
            "reason_count": len((verdict.get("initial_email") or {}).get(
                "reasons", [])),
            "findings_with_evidence": sum(
                1 for f in ((verdict.get("initial_email") or {}).get("findings") or [])
                if f.get("matched")),
        },
        "campaigns": {
            "clusters": len(campaigns or []),
            "reportable": sum(1 for c in (campaigns or [])
                              if getattr(c, "reportable", True)),
            "size_histogram": _histogram(
                [getattr(c, "message_count", 0) for c in (campaigns or [])],
                edges=(2, 3, 5, 10, 25, 100, 1000)),
        },
        "timings_seconds": sorted(
            ((str(k), round(float(v), 2)) for k, v in (timings or {}).items()),
            key=lambda kv: -kv[1])[:30],
        "config_deltas": _config_deltas(config),
    }

    if audit_summary:
        cov = audit_summary.get("coverage") or {}
        idx = audit_summary.get("message_index") or {}
        doc["audit_log"] = {
            "events_parsed": cov.get("events_parsed", 0),
            "span_days": cov.get("span_days", 0),
            "events_without_timestamp": cov.get("events_without_timestamp", 0),
            "distinct_operations": cov.get("distinct_operations", 0),
            # Operation names are Microsoft's vocabulary, not client data.
            "operations": cov.get("operations", [])[:40],
            "mailboxes": cov.get("mailboxes", 0),
            "client_ips": cov.get("client_ips", 0),
            "messages_referenced": idx.get("messages_referenced", 0),
            "events_with_message_id": idx.get("events_with_message_id", 0),
            "coverage_warnings": [w.get("severity", "")
                                  for w in (audit_summary.get("coverage_warnings") or [])],
            "attacker_ips": sum(1 for x in (audit_summary.get("ip_activity") or [])
                                if x.get("is_attacker")),
            "attacker_operations": (
                audit_summary.get("attacker_operation_counts") or [])[:20],
        }
        for key, section in (("join", "audit_join"),
                             ("completeness", "deletion_completeness"),
                             ("authorship", "attacker_authorship"),
                             ("exposure", "exposure_scope"),
                             ("rule_replay", "rule_replay")):
            src = (verdict or {}).get(section) or {}
            doc["audit_log"][key] = {
                k: v for k, v in src.items()
                if isinstance(v, (int, float, bool)) or
                (isinstance(v, str) and len(v) < 120 and not scan_for_identifiers(v))
            }

    if signin_summary:
        cov = signin_summary.get("coverage") or {}
        lures = (verdict or {}).get("signin_lures") or {}
        doc["signin_log"] = {
            "records": signin_summary.get("records", 0),
            "files": signin_summary.get("files", 0),
            "blind": bool(cov.get("blind")),
            "have_transfer": cov.get("have_transfer", 0),
            "have_protocol": cov.get("have_protocol", 0),
            "accounts": cov.get("accounts", 0),
            "device_code_records": signin_summary.get("device_code_records", 0),
            # Which field answered, not what it said: Microsoft's vocabulary.
            "detected_by": signin_summary.get("detected_by", {}),
            "attack_groups": signin_summary.get("attack_groups", 0),
            "single_groups": len(signin_summary.get("single_groups") or []),
            "unattributed_groups": len(
                signin_summary.get("unattributed_groups") or []),
            "attacker_ips": len(signin_summary.get("attacker_ips") or []),
            # How often the victim-IP veto fired. If this is ever large the
            # leg classification is wrong, and it is the one failure here
            # that would poison every downstream attribution.
            "vetoed_ips": len(signin_summary.get("vetoed_ips") or []),
            "tokens_issued": signin_summary.get("tokens_issued", 0),
            "lure_window_minutes": lures.get("window_minutes", 0),
            "lures_confirmed": len(lures.get("confirmed") or []),
            "in_window_no_lure": len(lures.get("in_window_only") or []),
            "tokens_without_lure": len(lures.get("tokens_without_lure") or []),
        }

    if persistence:
        findings = persistence.get("findings") or []
        scopes = Counter()
        for f in findings:
            for s in (f.get("mail_scopes") or []):
                scopes[s] += 1
            for s in (f.get("high_risk_scopes") or []):
                scopes[s] += 1
        doc["persistence"] = {
            "sources": persistence.get("sources", {}),
            "findings": len(findings),
            "attacker_attributed": persistence.get("confirmed_count", 0),
            "survives_both": persistence.get("survives_both_count", 0),
            # Kind names are ours; scope names are Microsoft's. Both are the
            # whole point of the section -- which mechanisms actually turn up
            # in real cases is what decides where the next work goes.
            "by_kind": persistence.get("counts", {}),
            "scopes_requested": scopes.most_common(25),
            "unreadable_scopes": sum(
                1 for f in findings
                if f.get("kind") == "oauth_consent"
                and not f.get("scopes_readable")),
            "risk_detections": Counter(
                str(d.get("detection", "")) for d in
                (persistence.get("risk_detections") or [])).most_common(15),
            "warnings": len(persistence.get("warnings") or []),
        }

    return doc


def _config_deltas(config):
    """Only the config values that differ from the shipped defaults."""
    if not config:
        return {}
    try:
        from postmortem.config import DEFAULT_CONFIG
    except Exception:
        return {}
    out = {}
    for k, v in (config or {}).items():
        if isinstance(v, (int, float, bool, str)) and DEFAULT_CONFIG.get(k) != v:
            out[k] = v
    return out


def render(doc):
    """The document as text. Readable so that it can be checked before sending."""
    lines = []
    w = lines.append
    w("# postmortem diagnostic (sanitized)")
    w("# %s" % doc["note"])
    w("")
    w("[tool]")
    for k, v in doc["tool"].items():
        w("  %-22s %s" % (k, v))
    w("")
    w("[corpus]")
    for k, v in doc["corpus"].items():
        if v is not None:
            w("  %-22s %s" % (k, v))
    w("")
    w("[tiers]")
    for k, v in doc["tiers"].items():
        w("  tier %-17s %s" % (k, v))
    w("")
    for name, block in doc["scores"].items():
        w("[scores.%s]" % name)
        q = block.get("quantiles") or {}
        if q:
            w("  " + "  ".join("%s=%s" % (k, v) for k, v in q.items()))
        for bucket, n in block.get("histogram", []):
            w("  %-10s %s" % (bucket, n))
        w("")
    w("[signals]  fired / share of corpus / mean weight / tier-1 share")
    for s in doc["signals"]:
        w("  %6d  %6.2f%%  %+6.2f  %6.2f%%  %s"
          % (s["messages"], 100 * s["share_of_corpus"], s["mean_weight"],
             100 * s["precision_proxy"], s["signal"]))
    w("")
    w("[verdict]")
    for k, v in doc["verdict"].items():
        w("  %-22s %s" % (k, v))
    w("")
    w("[campaigns]")
    w("  %-22s %s" % ("clusters", doc["campaigns"]["clusters"]))
    w("  %-22s %s" % ("reportable", doc["campaigns"]["reportable"]))
    for bucket, n in doc["campaigns"]["size_histogram"]:
        w("  size %-17s %s" % (bucket, n))
    w("")
    # One loop for every evidence-source section: adding a source should not
    # mean remembering to teach the renderer about it as well.
    for _section in ("audit_log", "signin_log", "persistence"):
        if not doc.get(_section):
            continue
        w("[%s]" % _section)
        for k, v in doc[_section].items():
            if isinstance(v, dict):
                w("  %-22s %s" % (k, ", ".join(
                    "%s=%s" % (kk, vv) for kk, vv in sorted(v.items())) or "-"))
            elif isinstance(v, list):
                # Counter.most_common() gives (name, count) pairs, but several
                # of these sections carry flat lists too -- coverage_warnings
                # is a list of severity strings. Unpacking blind raised, and
                # because the whole diagnostic is written in one try/except
                # the result was no diagnostic at all whenever an audit log
                # produced a coverage warning.
                parts = []
                for item in v[:12]:
                    if (isinstance(item, (list, tuple)) and len(item) == 2):
                        parts.append("%s=%s" % (item[0], item[1]))
                    else:
                        parts.append(str(item))
                w("  %-22s %s" % (k, ", ".join(parts) or "-"))
            else:
                w("  %-22s %s" % (k, v))
        w("")
    w("[timings_seconds]")
    for label, secs in doc["timings_seconds"]:
        w("  %-34s %8.2f" % (label[:34], secs))
    if doc.get("config_deltas"):
        w("")
        w("[config_deltas]")
        for k, v in doc["config_deltas"].items():
            w("  %-22s %s" % (k, v))
    return "\n".join(lines) + "\n"


def write(doc, path, also_json=True):
    """Write the report, refusing if any identifier pattern survived.

    The check runs on the finished text rather than on the inputs, so it
    catches anything a templating rule missed. A refusal is a bug in the
    templating, and it says so instead of writing a file that should not
    leave the machine.
    """
    text = render(doc)
    leaks = scan_for_identifiers(text)
    if leaks:
        raise ValueError(
            "refusing to write the diagnostic: %d identifier pattern(s) "
            "survived templating (%s). This is a bug in the sanitizer, not "
            "in your data -- please report the finding text, not the value."
            % (len(leaks), ", ".join(sorted({k for k, _ in leaks}))))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    written = [path]
    if also_json:
        blob = json.dumps(doc, indent=1, sort_keys=True, default=str)
        leaks = scan_for_identifiers(blob)
        if not leaks:
            jpath = str(path).rsplit(".", 1)[0] + ".json"
            with open(jpath, "w", encoding="utf-8") as fh:
                fh.write(blob)
            written.append(jpath)
    return written
