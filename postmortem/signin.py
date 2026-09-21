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


# --------------------------------------------------------------------------
# Single-record assessment
#
# The two-leg rule assumed a phished flow shows the authorising human in one
# place and the polling client in another. Syynimaa (aadinternals) records the
# opposite outcome: "from the Azure AD point-of-view the login takes place
# where the authentication was INITIATED" -- his test produced one sign-in
# carrying the attacker VM's address, not the victim's. So a device code
# phish can legitimately be a single record with a single IP, and requiring a
# split turns the attack's own shape into a clean result.
#
# inversecos detects the same attack on one record, from a field combination
# rather than a correlation. Those fields are what this scores.
# --------------------------------------------------------------------------

# Clients whose legitimate use of device code flow is routine. Device code
# exists for exactly this: a shell on a headless box, a console with no
# browser, a meeting-room display. Presence alone is worthless as evidence --
# a real corpus carried 875 device code sign-ins across 664 accounts -- so the
# question is never "was device code used" but "by what, and is that normal
# HERE". Both halves matter: this list, and the per-tenant baseline below it.
_DEVICE_CODE_EXPECTED = {
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Azure CLI",
    "1950a258-227b-4e31-a9cf-717495945fc2": "Azure PowerShell",
}

# Clients with no device code use case at all. Office desktop does not
# authenticate this way, which is precisely why both write-ups show this
# client id being abused: it is a family-of-client-IDs member, so its refresh
# token redeems for Exchange, SharePoint and Graph, and it reads as innocuous
# in a log. A device code flow claiming to be one of these is the highest
# precision signal available from a single record.
_DEVICE_CODE_NEVER = {
    "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
}

# Resource identifiers worth naming when they appear on a device code flow.
_RESOURCE_NAMES = {
    "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
    "00000002-0000-0000-c000-000000000000": "Azure AD Graph",
    "00000002-0000-0ff1-ce00-000000000000": "Office 365 Exchange Online",
}

# Non-browser clients. A device code flow is authorised in a browser by a
# human; the polling half is not, and neither is a replayed token.
_AUTOMATION_AGENTS = ("python-requests", "curl", "go-http-client", "axios",
                      "okhttp", "powershell", "libwww", "wget", "httpie",
                      "restsharp", "java/", "node-fetch")

# Weight, reason. Scored rather than counted: four weak observations should
# not outrank one decisive one, which is what a bare len(reasons) >= 2 did.
_NEVER_CLIENT_W = 6
_SINGLE_FACTOR_W = 3
_TOKEN_CLAIM_W = 3
_RARE_CLIENT_W = 3
_DESKTOP_CLIENT_W = 1
_AGENT_W = 2
_CA_W = 2
_SUCCESS_W = 1

# At or above this, the record is reported as an indicated attack rather than
# a review item. Reachable by one decisive signal plus corroboration, never by
# accumulating weak ones.
SINGLE_RECORD_FLOOR = 6


def app_id_of(flat):
    for key in ("appid", "applicationid", "clientappid"):
        v = flat.get(key)
        if v:
            return str(v).strip().lower()
    return ""


def resource_id_of(flat):
    for key in ("resourceid", "resourceappid"):
        v = flat.get(key)
        if v:
            return str(v).strip().lower()
    return ""


def is_single_factor(flat):
    """The authentication satisfied MFA without the user performing it.

    inversecos calls this out twice: "Authentication Requirement:
    Single-factor authentication (because it was as we used a token)" and
    "MFA requirement satisfied by claim in the token". Either says the
    credential presented was already minted, which on a device code flow is
    the token the victim's authorisation produced.
    """
    req = str(get(flat, "auth_req", "")).strip().lower().replace(" ", "")
    return req in ("singlefactorauthentication", "singlefactor")


def token_claim_satisfied(flat):
    tok = str(get(flat, "token_type", "")).strip().lower()
    return bool(tok) and tok not in ("none", "primaryrefreshtoken")


def device_code_client_baseline(hits):
    """Which client ids use device code flow in THIS tenant, and how often.

    A shipped list cannot know that this tenant runs a fleet of Teams Rooms,
    or that its developers live on Azure CLI. The tenant's own log can. A
    client that accounts for a meaningful share of device code activity here
    is normal here whatever it is; one that appears once among hundreds is
    the outlier worth reading.
    """
    counts = Counter()
    for _src, f in hits:
        app = app_id_of(f) or str(get(f, "app", "")).strip().lower()
        if app:
            counts[app] += 1
    return counts


def assess_single_leg(flat, baseline=None, total=0):
    """Score one device code record on its own merits.

    Returns (score, reasons). Nothing here attributes by itself -- the caller
    decides what a score means -- but unlike the previous version this is a
    first-class detection path rather than a quarantined heuristic, because
    the single-record shape is what the attack actually produces.
    """
    reasons, score = [], 0
    expected_client = ""

    app = app_id_of(flat)
    app_name = str(get(flat, "app", "")).strip()
    if app in _DEVICE_CODE_NEVER:
        reasons.append("client has no device code use case (%s)"
                       % _DEVICE_CODE_NEVER[app])
        score += _NEVER_CLIENT_W
    elif app and app in _DEVICE_CODE_EXPECTED:
        # Not merely neutral: suppressing. Azure CLI on a headless box is a
        # non-browser client, shows as a desktop client, runs without
        # conditional access and presents a cached token -- four of the
        # signals below, all of them innocent here. Left neutral it scored 9
        # on a synthetic corpus and was reported as an attack, which is the
        # exact false positive this list exists to prevent.
        expected_client = _DEVICE_CODE_EXPECTED[app]
    elif baseline and total:
        seen = baseline.get(app or app_name.lower(), 0)
        if seen and seen <= max(2, 0.01 * total):
            reasons.append("client rare for device code in this tenant "
                           "(%d of %d)" % (seen, total))
            score += _RARE_CLIENT_W

    if is_single_factor(flat):
        reasons.append("single-factor: MFA satisfied by a claim, not by the user")
        score += _SINGLE_FACTOR_W
    if token_claim_satisfied(flat):
        reasons.append("presented an existing token (%s)"
                       % str(get(flat, "token_type", ""))[:24])
        score += _TOKEN_CLAIM_W

    client_app = str(get(flat, "client_app", "")).strip().lower()
    if "mobile apps and desktop clients" in client_app:
        reasons.append("client app: Mobile Apps and Desktop clients")
        score += _DESKTOP_CLIENT_W

    agent = str(get(flat, "user_agent", "") or get(flat, "client_app", "")).lower()
    if agent and any(a in agent for a in _AUTOMATION_AGENTS):
        reasons.append("non-browser client (%s)" % short_agent(flat, 40))
        score += _AGENT_W

    ca = str(get(flat, "ca_status", "")).strip().lower()
    if ca in ("notapplied", "not applied", "disabled"):
        reasons.append("conditional access not applied")
        score += _CA_W

    if succeeded(flat):
        reasons.append("token issued")
        score += _SUCCESS_W

    res = resource_id_of(flat)
    if res in _RESOURCE_NAMES:
        reasons.append("resource: %s" % _RESOURCE_NAMES[res])

    if expected_client:
        # Held below the reporting floor. It stays in the review list with its
        # reasons intact, so nothing is hidden -- it simply cannot be called
        # an indicated attack on signals that are normal for this client.
        score = min(score, SINGLE_RECORD_FLOOR - 1)
        reasons.insert(0, "device code is routine for this client (%s)"
                       % expected_client)

    return score, reasons


def _single_leg_findings(buckets, victim_ips, hits=(), limit=50):
    """Device code records scored individually, ranked, split by confidence."""
    baseline = device_code_client_baseline(hits)
    total = sum(baseline.values())

    out = []
    for cid, legs in buckets.items():
        if len(legs) != 1:
            continue
        f = legs[0]
        ip = str(get(f, "ip", ""))
        if ip and ip in victim_ips:
            continue          # the account signs in interactively from here
        score, reasons = assess_single_leg(f, baseline, total)
        if score < 3:
            continue
        row = _leg_row(f)
        row.update({"correlation": cid, "reasons": reasons, "score": score,
                    "indicated": score >= SINGLE_RECORD_FLOOR,
                    "app_id": app_id_of(f),
                    "user": str(get(f, "user", "")) or "(unknown)"})
        out.append(row)
    out.sort(key=lambda r: (-r["score"], r.get("time") or ""))
    return out[:limit]


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

    # Counted over every device code sign-in, not only attributed ones.
    # tokens_issued is downstream of a group being judged an attack, so it is
    # structurally 0 whenever attribution failed -- which reads in a report as
    # "no token was ever issued" when it means "none was tied to an attacker".
    successes = sum(1 for _s, f in hits if succeeded(f))

    token_events.sort(key=lambda e: e["time"])
    dated = [e["_dt"] for e in token_events if e["_dt"]]
    earliest = min(dated) if dated else None

    single_leg = _single_leg_findings(buckets, victim_ips, hits)

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
    if hits and len(singles) >= 0.8 * max(1, len(buckets)):
        warnings.append(
            "%d of %d device code correlation groups contain a single leg. "
            "That is not necessarily a collection gap: Entra records the "
            "sign-in where the authentication was INITIATED, so a phished "
            "flow can produce one record carrying the attacker's address and "
            "no second leg to compare it against. Those records are scored "
            "individually below rather than reported as nothing. If the "
            "export was interactive-only, re-exporting with non-interactive "
            "sign-ins included adds the polling leg and strengthens the "
            "result -- Entra retains 30 days, and expiry is not retroactive."
            % (len(singles), len(buckets)))
    elif hits and not attacker_ips and not unattributed:
        warnings.append(
            "Device code sign-ins are present but none shows a location split, "
            "so no attacker address was derived. A residential proxy in the "
            "victim's own country produces exactly this picture.")
    _indicated = [r for r in single_leg if r["indicated"]]
    if _indicated:
        warnings.append(
            "%d device code sign-in(s) match the published single-record "
            "profile for device code phishing (a client with no device code "
            "use case, or MFA satisfied by a claim rather than by the user). "
            "These are individually assessed, not corroborated by a location "
            "split, so they are an indication rather than a confirmation."
            % len(_indicated))

    if hits and not attacker_ips and successes:
        warnings.append(
            "%d of %d device code sign-in(s) succeeded, but none is attributed "
            "to an attacker. Device code flow has legitimate uses, so a "
            "success is not a finding on its own -- but 'tokens issued: 0' in "
            "this report counts ATTRIBUTED tokens only, not tokens."
            % (successes, len(hits)))
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
        "device_code_successes": successes,
        # Every address that authenticated at all, device code or not. The
        # token-replay test needs the full set, not the device code subset.
        "all_signin_ips": sorted({str(get(f, "ip", "")) for _s, f in records
                                  if get(f, "ip", "")}),
        "single_leg_findings": single_leg,
        "single_leg_count": len(single_leg),
        "indicated_count": sum(1 for r in single_leg if r["indicated"]),
        "earliest_token": earliest.strftime("%Y-%m-%dT%H:%M:%SZ") if earliest else "",
        "_earliest_token_dt": earliest,
        "warnings": warnings,
    }


# Mailbox operations are the only record left when a refresh token is used:
# "access tokens acquired using the refresh token do not appear in sign-in
# log" (aadinternals). One device code authorisation yields a refresh token
# to a family-of-client-IDs member, which redeems silently for Exchange,
# SharePoint and Graph -- Syynimaa's own timeline logs a sign-in at 07:23 and
# nothing at all for the Exchange access at 07:27.
#
# So the sign-in log structurally undercounts, and the gap is itself the
# evidence: an address performing mailbox operations that never authenticated
# is holding a token it did not obtain here.

# Operations that need a token. A message trace or a service-side event can
# carry an address that never signed in for ordinary reasons, so the test is
# scoped to things a client does with a credential in hand.
_TOKEN_BEARING_OPS = {
    "mailitemsaccessed", "messagebind", "send", "sendas", "sendonbehalf",
    "harddelete", "softdelete", "movetodeleteditems", "movetofolder", "move",
    "update", "create", "new-inboxrule", "set-inboxrule", "updateinboxrules",
    "add-mailboxpermission", "set-mailbox",
}


def find_token_replay(signin_summary, audit_summary, min_events=3):
    """Addresses that acted on a mailbox without ever authenticating here.

    Requires the sign-in export to cover the audit window. If it does not,
    every audit address looks unauthenticated and the finding is meaningless
    -- so coverage is checked first and the result says so rather than
    inventing a list.
    """
    s, a = signin_summary or {}, audit_summary or {}
    if not s.get("available") or not a:
        return {"assessed": False,
                "reason": "Needs both a sign-in log and an audit log."}

    activity = a.get("ip_activity") or []
    if not activity:
        return {"assessed": False,
                "reason": "The audit log yielded no per-address activity."}

    cov = s.get("coverage") or {}
    first, last = cov.get("first_event", ""), cov.get("last_event", "")
    # coverage renders its stamps with a space separator; the audit log keeps
    # the ISO "T". Comparing them as strings put every audit row outside the
    # window, because " " sorts below "T" at the tenth character -- the test
    # silently excluded everything it was meant to assess.
    win_first, win_last = parse_time(first), parse_time(last)
    if not (first and last):
        return {"assessed": False,
                "reason": "The sign-in export does not state its own window, "
                          "so it cannot be compared against the audit log."}

    authenticated = {str(ip) for ip in (s.get("all_signin_ips") or ())}
    if not authenticated:
        return {"assessed": False,
                "reason": "No addresses were read from the sign-in export."}

    replay, outside = [], 0
    for row in activity:
        ip = str(row.get("ip") or "")
        if not ip or ip in authenticated:
            continue
        ops = {str(k).lower().replace(" ", "") for k, _n in (row.get("operations") or [])}
        if not (ops & _TOKEN_BEARING_OPS):
            continue
        if int(row.get("events") or 0) < min_events:
            continue
        # Only claim it for activity the sign-in export actually covers.
        rf = str(row.get("first_seen") or "")
        rl = str(row.get("last_seen") or "")
        d_first, d_last = parse_time(rf), parse_time(rl)
        if win_first and win_last and (d_first or d_last):
            ends_before = bool(d_last and d_last < win_first)
            starts_after = bool(d_first and d_first > win_last)
            if ends_before or starts_after:
                outside += 1
                continue
        replay.append({
            "ip": ip, "events": row.get("events"),
            "users": row.get("users"), "first": rf, "last": rl,
            "is_attacker": bool(row.get("is_attacker")),
            "country": row.get("country", ""), "asn": row.get("asn", ""),
            "operations": (row.get("operations") or [])[:6],
        })

    replay.sort(key=lambda r: -(r["events"] or 0))
    return {
        "assessed": True,
        "signin_window": [first, last],
        "authenticated_ips": len(authenticated),
        "replay": replay,
        "replay_count": len(replay),
        "outside_window": outside,
        "note": ("Each address below performed mailbox operations inside the "
                 "sign-in log's own window without any authentication being "
                 "recorded for it. A token obtained by refreshing an earlier "
                 "one leaves exactly this trace: the access happens, and "
                 "Entra logs nothing. Addresses whose activity falls outside "
                 "the sign-in window are excluded rather than claimed."),
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
