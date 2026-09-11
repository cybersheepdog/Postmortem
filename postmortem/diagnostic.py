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


def build(records, verdict=None, audit_summary=None, manifest=None,
          campaigns=None, timings=None, config=None):
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
            "date_span_days": (manifest or {}).get("corpus", {}).get("span_days", None),
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
    if doc.get("audit_log"):
        w("[audit_log]")
        for k, v in doc["audit_log"].items():
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
