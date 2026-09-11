"""Entra ID sign-in log ingestion, for device code flow and token issuance.

Everything else this tool reads is mail: a message asserts things about itself
and the scorer decides how much to believe it. A sign-in log is the opposite --
it is what the identity provider recorded about an authentication it performed,
and it is the only place a device code flow is visible at all. The lure carries
no attacker-controlled domain, no credential-harvesting link and nothing for
URL analysis to bite on, so the mail corpus alone cannot see this attack.

Two things come out of here and cross into the audit-log side of the
investigation:

  attacker IPs   The audit log seeds its attacker set exclusively from
                 malicious inbox-rule events. An attacker who never made a
                 rule leaves that set empty, and with it every downstream
                 attribution -- who deleted what, who read what, who sent
                 what. A device code group with the victim in one country and
                 the polling client in another names an attacker address from
                 a recorded authentication instead of an inferred intent.

  token time     The first successful device code token issuance is the real
                 T0. The audit log's compromise date is the first suspicious
                 *action*, which is necessarily later.

Attribution here is deliberately conservative. Seeding the victim's own
address as an attacker IP would mark the mailbox owner's ordinary activity as
the intruder's throughout the report, so a leg is only called the attacker's
when the victim's leg can be positively identified and the addresses differ.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter, OrderedDict
from datetime import datetime, timezone

SCHEMA = "postmortem-signin/1"

# Field spellings differ between the portal export, the Graph beta/v1.0
# collections and a Log Analytics / Sentinel export of the same data.
FIELDS = {
    "time": ["createdDateTime", "TimeGenerated", "time", "date", "activityDateTime"],
    "user": ["userPrincipalName", "UserPrincipalName", "userDisplayName", "Identity"],
    "user_id": ["userId", "UserId"],
    "app": ["appDisplayName", "AppDisplayName", "appId", "AppId"],
    "resource": ["resourceDisplayName", "ResourceDisplayName"],
    "ip": ["ipAddress", "IPAddress", "callerIpAddress", "ipAddressFromResourceProvider"],
    "correlation": ["correlationId", "CorrelationId"],
    "interactive": ["isInteractive", "IsInteractive"],
    "transfer": ["originalTransferMethod", "OriginalTransferMethod"],
    "protocol": ["authenticationProtocol", "AuthenticationProtocol"],
    "user_agent": ["userAgent", "UserAgent"],
    "client_app": ["clientAppUsed", "ClientAppUsed"],
    "asn": ["autonomousSystemNumber", "AutonomousSystemNumber"],
    "auth_req": ["authenticationRequirement", "AuthenticationRequirement"],
    "ca_status": ["conditionalAccessStatus", "ConditionalAccessStatus"],
    "risk": ["riskLevelDuringSignIn", "RiskLevelDuringSignIn"],
    "risk_state": ["riskState", "RiskState"],
    "token_type": ["incomingTokenType", "IncomingTokenType"],
}

_DEVICE_CODE_TRANSFER = {"devicecodeflow", "device code flow", "devicecode"}
_DEVICE_CODE_PROTOCOL = {"devicecode", "device code", "devicecodeflow"}


# --------------------------------------------------------------------------
# Field access
# --------------------------------------------------------------------------

def _flatten(obj, out=None, depth=0):
    """Collapse a record to a lowercase-key map, a few levels of nesting deep.

    Portal and Log Analytics exports bury half the interesting fields under
    ``properties``, ``status``, ``location`` or ``deviceDetail``. Flattening
    means the field lookup below does not need to know which.
    """
    if out is None:
        out = {}
    if not isinstance(obj, dict) or depth > 3:
        return out
    for k, v in obj.items():
        lk = str(k).lower()
        if isinstance(v, dict):
            out.setdefault(lk, v)
            _flatten(v, out, depth + 1)
        else:
            out.setdefault(lk, v)
    return out


def get(flat, name, default=""):
    for spelling in FIELDS.get(name, [name]):
        v = flat.get(spelling.lower())
        if v not in (None, ""):
            return v
    return default


def country_of(flat):
    return str(flat.get("countryorregion") or flat.get("country") or "")


def short_location(flat):
    city = str(flat.get("city") or "")
    country = country_of(flat)
    if city and country:
        return "%s, %s" % (city, country)
    return city or country or "?"


def truthy(v):
    return str(v).strip().lower() in ("true", "1", "yes")


def status_of(flat):
    err = flat.get("errorcode")
    if err in (None, ""):
        err = flat.get("resulttype") or ""
    try:
        failed = int(err) != 0
    except (TypeError, ValueError):
        failed = bool(err) and str(err) not in ("0", "None")
    reason = (flat.get("failurereason") or flat.get("resultdescription") or "")
    if failed:
        return "FAILED(%s) %s" % (err, str(reason)[:50])
    return "success"


def succeeded(flat):
    return status_of(flat) == "success"


def short_agent(flat, width=60):
    ua = str(get(flat, "user_agent", "") or get(flat, "client_app", "") or "?")
    for token in ("python-requests", "curl", "Go-http-client", "axios",
                  "PowerShell", "okhttp", "Chrome", "Firefox", "Safari",
                  "Edg", "Electron", "Mobile"):
        if token.lower() in ua.lower():
            idx = ua.lower().index(token.lower())
            return ua[idx:idx + width]
    return ua[:width]


def parse_time(value):
    """Parse a sign-in timestamp into an aware UTC datetime, or None.

    Matches auditlog._parse_iso: both sides of the merge must be aware and
    UTC-normalized or the anchor comparison raises instead of answering.
    """
    if not value:
        return None
    s = str(value).strip().replace("Z", "+00:00")
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        dt = None
        for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S"):
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


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def iter_records(path):
    """Yield sign-in records from one file, whatever container it uses."""
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            raw = fh.read()
    except OSError:
        return

    raw = raw.strip()
    if not raw:
        return

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        doc = None

    if doc is not None:
        if isinstance(doc, list):
            for r in doc:
                if isinstance(r, dict):
                    yield r
            return
        if isinstance(doc, dict):
            for key in ("value", "records", "Records", "signIns", "data"):
                if isinstance(doc.get(key), list):
                    for r in doc[key]:
                        if isinstance(r, dict):
                            yield r
                    return
            yield doc
            return

    for line in raw.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(r, dict):
            yield r


def load(path, progress=None):
    """Read one file or a directory tree. Returns (files, [(name, flat), ...])."""
    files = []
    if os.path.isdir(path):
        for root, _dirs, names in os.walk(path):
            for n in sorted(names):
                if n.lower().endswith((".json", ".ndjson", ".jsonl")):
                    files.append(os.path.join(root, n))
    elif os.path.isfile(path):
        files = [str(path)]

    records = []
    for p in files:
        for r in iter_records(p):
            records.append((os.path.basename(p), _flatten(r)))
        if progress is not None:
            progress(os.path.basename(p), len(records))
    return files, records


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

def is_device_code(flat):
    """(bool, field) -- which field, if any, says this was a device code flow."""
    transfer = str(get(flat, "transfer", "")).strip().lower()
    if transfer in _DEVICE_CODE_TRANSFER:
        return True, "originalTransferMethod"
    protocol = str(get(flat, "protocol", "")).strip().lower()
    if protocol in _DEVICE_CODE_PROTOCOL:
        return True, "authenticationProtocol"
    return False, ""


def assess(legs):
    """Verdict and concrete mismatches for one correlation group.

    A genuine device code flow has the authorizing human and the polling
    client in roughly the same place. A phished one has them in two, because
    the code travelled and the client did not.
    """
    ips = {str(get(f, "ip", "")) for f in legs if get(f, "ip", "")}
    countries = {country_of(f) for f in legs if country_of(f)}
    asns = {str(get(f, "asn", "")) for f in legs if get(f, "asn", "")}
    agents = {short_agent(f) for f in legs if get(f, "user_agent", "")}

    differs = []
    if len(ips) > 1:
        differs.append("IP")
    if len(countries) > 1:
        differs.append("country")
    if len(asns) > 1:
        differs.append("ASN")
    if len(agents) > 1:
        differs.append("user agent")

    # Where the legs came from is the finding. A different user agent alone is
    # weak -- a browser and a broker client legitimately differ -- so it is
    # reported but does not by itself make a group an attack.
    located = [m for m in differs if m in ("IP", "country", "ASN")]
    if located:
        verdict = "attack"
    elif len(legs) == 1:
        verdict = "single"
    else:
        verdict = "consistent"
    return verdict, differs


def classify_legs(legs):
    """Split one group into the victim's legs and the attacker's.

    The victim types the code into a browser, so their leg is the interactive
    one; the attacker's client is polling the token endpoint and is not. That
    single field is the only positive identification available, and without it
    no attribution is asserted at all -- naming the wrong leg would seed the
    mailbox owner's own address as the attacker's and mislabel every action
    they took for the rest of the report.

    Returns (victim_legs, attacker_legs, basis).
    """
    interactive = [f for f in legs if truthy(get(f, "interactive", ""))]
    has_field = any(get(f, "interactive", "") not in ("", None) for f in legs)
    if not has_field or not interactive:
        return [], [], ""
    non_interactive = [f for f in legs if not truthy(get(f, "interactive", ""))]
    if not non_interactive:
        return interactive, [], "isInteractive"
    return interactive, non_interactive, "isInteractive"


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def _leg_row(f):
    return {
        "time": str(get(f, "time", ""))[:19].replace("T", " "),
        "interactive": truthy(get(f, "interactive", "")),
        "ip": str(get(f, "ip", "?")),
        "location": short_location(f),
        "asn": str(get(f, "asn", "")),
        "agent": short_agent(f),
        "app": str(get(f, "app", "?")),
        "resource": str(get(f, "resource", "")),
        "auth_requirement": str(get(f, "auth_req", "")),
        "ca_status": str(get(f, "ca_status", "")),
        "token_type": str(get(f, "token_type", "")),
        "ok": succeeded(f),
        "status": status_of(f),
    }


def _victim_addresses(records, affected_users):
    """Every IP seen on an interactive sign-in for an affected account.

    Used as a veto list. An address the account demonstrably signs in from
    interactively is the user's own, whatever leg of a device code group it
    later turns up on.
    """
    out = set()
    lowered = {u.lower() for u in affected_users if u}
    for _src, f in records:
        user = str(get(f, "user", "")).lower()
        if user and user in lowered and truthy(get(f, "interactive", "")):
            ip = str(get(f, "ip", ""))
            if ip:
                out.add(ip)
    return out


def analyze_signin_logs(path):
    """Parse an Entra sign-in export and derive what the mail side can use.

    Shape mirrors analyze_audit_log so __main__ can treat the two the same
    way. Returns {} when the path yields nothing readable.
    """
    files, records = load(path)
    if not records:
        return {}

    have_transfer = sum(1 for _s, f in records if get(f, "transfer", ""))
    have_protocol = sum(1 for _s, f in records if get(f, "protocol", ""))
    blind = have_transfer == 0 and have_protocol == 0

    hits = []
    detected_by = Counter()
    for src, f in records:
        ok, field = is_device_code(f)
        if ok:
            hits.append((src, f))
            detected_by[field] += 1

    buckets = OrderedDict()
    for _src, f in sorted(hits, key=lambda x: str(get(x[1], "time", ""))):
        cid = str(get(f, "correlation", "")) or "(no correlation id)"
        buckets.setdefault(cid, []).append(f)

    affected_users = sorted({str(get(f, "user", "")) for _s, f in hits
                             if get(f, "user", "")})
    victim_ips = _victim_addresses(records, affected_users)

    groups = []
    attacker_ips = set()
    vetoed_ips = set()
    unattributed = []
    token_events = []

    for cid, legs in buckets.items():
        verdict, differs = assess(legs)
        victim_legs, attacker_legs, basis = classify_legs(legs)
        user = str(get(legs[0], "user", "")) or "(unknown)"

        named = []
        if verdict == "attack" and attacker_legs:
            victim_leg_ips = {str(get(f, "ip", "")) for f in victim_legs
                              if get(f, "ip", "")}
            for f in attacker_legs:
                ip = str(get(f, "ip", ""))
                if not ip or ip in victim_leg_ips:
                    continue
                if ip in victim_ips:
                    # The account signs in interactively from here. Whatever
                    # this leg is, it is not an outsider.
                    vetoed_ips.add(ip)
                    continue
                named.append(ip)
                attacker_ips.add(ip)
                if succeeded(f):
                    token_events.append({
                        "time": str(get(f, "time", "")),
                        "_dt": parse_time(get(f, "time", "")),
                        "user": user,
                        "ip": ip,
                        "location": short_location(f),
                        "asn": str(get(f, "asn", "")),
                        "app": str(get(f, "app", "")),
                        "resource": str(get(f, "resource", "")),
                        "correlation": cid,
                        "agent": short_agent(f),
                    })
        elif verdict == "attack" and not basis:
            unattributed.append({
                "correlation": cid, "user": user,
                "reason": "isInteractive absent; cannot tell which leg is the "
                          "victim's, so no address is attributed",
                "ips": sorted({str(get(f, "ip", "")) for f in legs
                               if get(f, "ip", "")}),
            })

        rows = [_leg_row(f) for f in sorted(
            legs, key=lambda x: str(get(x, "time", "")))]
        groups.append({
            "correlation": cid,
            "verdict": verdict,
            "differs": differs,
            "user": user,
            "time": rows[0]["time"] if rows else "",
            "legs": rows,
            "attribution_basis": basis,
            "attacker_ips": sorted(set(named)),
            "any_success": any(r["ok"] for r in rows),
            "tokens_issued": verdict == "attack" and any(r["ok"] for r in rows),
        })

    token_events.sort(key=lambda e: e["time"])
    dated = [e["_dt"] for e in token_events if e["_dt"]]
    earliest = min(dated) if dated else None

    times = sorted(str(get(f, "time", "")) for _s, f in records
                   if get(f, "time", ""))
    accounts = {str(get(f, "user", "")) for _s, f in records if get(f, "user", "")}

    # Single-leg device code groups are unresolved, not clean: one leg means
    # the export did not record the other, or the attacker shared the victim's
    # apparent location. They are handed back so the audit log's own attacker
    # addresses can resolve them.
    singles = [{"correlation": g["correlation"], "user": g["user"],
                "time": g["time"],
                "ips": sorted({l["ip"] for l in g["legs"] if l["ip"] != "?"})}
               for g in groups if g["verdict"] == "single"]

    warnings = []
    if blind:
        warnings.append(
            "Neither originalTransferMethod nor authenticationProtocol is "
            "present in this export. It cannot answer the device code "
            "question at all; a clean result here is not a negative.")
    if hits and not attacker_ips and not unattributed:
        warnings.append(
            "Device code sign-ins are present but none shows a location split, "
            "so no attacker address was derived. A residential proxy in the "
            "victim's own country produces exactly this picture.")
    if vetoed_ips:
        warnings.append(
            "%d candidate address(es) were withheld because the account also "
            "signs in interactively from them." % len(vetoed_ips))

    return {
        "available": True,
        "schema": SCHEMA,
        "source": str(path),
        "files": len(files),
        "records": len(records),
        "coverage": {
            "first_event": times[0][:19].replace("T", " ") if times else "",
            "last_event": times[-1][:19].replace("T", " ") if times else "",
            "accounts": len(accounts),
            "have_transfer": have_transfer,
            "have_protocol": have_protocol,
            "blind": blind,
        },
        "device_code_records": len(hits),
        "detected_by": dict(detected_by),
        "groups": groups,
        "attack_groups": sum(1 for g in groups if g["verdict"] == "attack"),
        "single_groups": singles,
        "unattributed_groups": unattributed,
        "affected_users": affected_users,
        "attacker_ips": sorted(attacker_ips),
        "vetoed_ips": sorted(vetoed_ips),
        "token_events": token_events,
        "tokens_issued": len(token_events),
        "earliest_token": earliest.strftime("%Y-%m-%dT%H:%M:%SZ") if earliest else "",
        "_earliest_token_dt": earliest,
        "warnings": warnings,
    }


def resolve_single_groups(signin_summary, audit_attacker_ips):
    """Second pass: a one-leg group whose address the audit log already knows.

    The two sources derive attacker addresses from unrelated evidence -- a
    location split in an authentication, and the client address on a malicious
    rule. Either can resolve what the other left open.
    """
    if not signin_summary or not audit_attacker_ips:
        return {"resolved": 0, "groups": []}
    known = set(audit_attacker_ips)
    resolved = []
    by_cid = {g["correlation"]: g for g in signin_summary.get("groups", [])}
    for single in list(signin_summary.get("single_groups", [])):
        overlap = sorted(set(single["ips"]) & known)
        if not overlap:
            continue
        resolved.append({**single, "matched_ips": overlap})
        g = by_cid.get(single["correlation"])
        if g is not None:
            g["verdict"] = "attack"
            g["attribution_basis"] = "audit log attacker IP"
            g["attacker_ips"] = sorted(set(g["attacker_ips"]) | set(overlap))
    if resolved:
        done = {r["correlation"] for r in resolved}
        signin_summary["single_groups"] = [
            s for s in signin_summary.get("single_groups", [])
            if s["correlation"] not in done]
        signin_summary["attacker_ips"] = sorted(
            set(signin_summary.get("attacker_ips", [])) | known)
        signin_summary["attack_groups"] = sum(
            1 for g in signin_summary.get("groups", [])
            if g["verdict"] == "attack")
    return {"resolved": len(resolved), "groups": resolved}
