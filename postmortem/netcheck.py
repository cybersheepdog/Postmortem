"""Optional ONLINE enrichment: domain registration age via RDAP.

Used only when ``--check-domain-age`` is passed. Queries rdap.org (which routes
to the authoritative RDAP server for the TLD) over HTTPS, extracts the
``registration`` event date, and caches successful lookups on disk so re-runs
and repeated domains do not re-query. Every failure -- offline, timeout, unknown
TLD, malformed response -- degrades to "unknown" and is never cached.

A newly-registered sender domain is a strong lookalike/attacker-infrastructure
signal: legitimate correspondents rarely mail you from a domain registered days
earlier. This is the only part of the tool that reaches the network, and only
when explicitly enabled.
"""

import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

_RDAP_URL = "https://rdap.org/domain/{}"


def _parse_dt(value):
    if not value:
        return None
    s = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _registration_date(data):
    for event in (data.get("events") or []):
        if str(event.get("eventAction", "")).lower() == "registration":
            return _parse_dt(event.get("eventDate", ""))
    return None


def age_days(reg_dt, reference):
    """Whole days between a registration date and a reference time, or -1."""
    if not reg_dt:
        return -1
    return max(0, (reference - reg_dt).days)


class DomainAgeChecker:
    """RDAP domain-age lookups with an on-disk cache. Offline-safe."""

    def __init__(self, cache_path=None, timeout=6.0):
        self.timeout = timeout
        self.cache_path = Path(cache_path) if cache_path else None
        self.cache = {}
        if self.cache_path and self.cache_path.exists():
            try:
                self.cache = json.loads(self.cache_path.read_text(encoding="utf-8"))
            except Exception:
                self.cache = {}

    def registration_date(self, domain):
        domain = (domain or "").lower().strip(".")
        if not domain:
            return None
        if domain in self.cache:  # cached ISO string (successes only)
            return _parse_dt(self.cache[domain])
        try:
            req = urllib.request.Request(
                _RDAP_URL.format(domain),
                headers={"Accept": "application/rdap+json",
                         "User-Agent": "postmortem"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:
            return None  # network/parse failure -> unknown, not cached
        dt = _registration_date(data)
        if dt is not None:
            self.cache[domain] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            self._save()
        return dt

    def _save(self):
        if not self.cache_path:
            return
        try:
            self.cache_path.write_text(json.dumps(self.cache), encoding="utf-8")
        except Exception:
            pass


def annotate_records(records, checker, threshold_days, tiers=(1, 2)):
    """Flag candidate senders whose domain was registered < threshold_days ago.

    Promotes a hit to Tier 1 and records the finding with provenance. Returns
    the number of records flagged. Only Tier 1/2 senders are queried, one lookup
    per registrable domain.
    """
    from postmortem.scoring import make_finding, message_arrival_dt
    from postmortem.utils import registered_domain_approx

    flagged = 0
    seen = {}
    for r in records:
        if r.tier not in tiers or not r.sender_domain:
            continue
        dom = registered_domain_approx(r.sender_domain)
        if not dom:
            continue
        if dom not in seen:
            seen[dom] = checker.registration_date(dom)
        reg = seen[dom]
        if reg is None:
            continue
        reference = message_arrival_dt(r) or datetime.now(timezone.utc)
        days = age_days(reg, reference)
        r.sender_domain_age_days = days
        if 0 <= days < threshold_days:
            r.newly_registered_domain = True
            sig = (f"Sender domain {dom} was registered {days} day(s) "
                   "before this message")
            r.indicators = list(dict.fromkeys(list(r.indicators) + [sig]))
            r.provenance = list(r.provenance) + [make_finding(
                sig, category="identity", source="rdap",
                matched=f"{dom} registered {days}d prior", weight=8,
                severity="high")]
            r.score += 8
            r.tier = 1
            flagged += 1
    return flagged
