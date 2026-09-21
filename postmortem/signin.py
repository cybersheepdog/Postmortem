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
from datetime import datetime, timedelta, timezone

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
    # deviceDetail is flattened, so its keys land at the top level.
    "device_id": ["deviceId", "DeviceId"],
    "device_name": ["displayName", "DeviceName", "deviceDisplayName"],
    "trust_type": ["trustType", "TrustType"],
    "managed": ["isManaged", "IsManaged"],
    "compliant": ["isCompliant", "IsCompliant"],
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


# --------------------------------------------------------------------------
# Forged events
#
# A sign-in log is trusted here as the record of what the identity provider
# did. That trust has a limit: an attacker with a compromised AD FS server --
# or, on a cloud-only tenant, a Global Administrator who registers a FAKE
# health agent -- can inject events into it through the Azure AD Connect
# Health pipeline, controlling the timestamp, the account and THE IP ADDRESS
# (inversecos, "Detecting Fake Events in Azure Sign-in Logs").
#
# That last field is aimed squarely at the attribution below. _victim_
# addresses() treats every address seen on an interactive sign-in for a
# compromised account as the owner's and vetoes it, so that the mailbox
# owner is never labelled the intruder. An attacker who forges ONE
# interactive sign-in for the victim from their own address puts that address
# in the veto set and the tool then refuses to name it: the conservatism
# becomes the bypass. Forged records are therefore kept out of the veto.
#
# The tells are cheap and specific -- a forged event cannot populate the
# application and resource fields the real pipeline fills in.
_FORGED_APP = {"notapplicable", "not applicable", "notset", "not set", ""}
_FORGED_RESOURCE_ID = "urn:federation:microsoftonline"
_FORGED_AUTH_METHOD = "forms authentication"
_FORGED_ISSUER = "federated (adfs)"


def forged_markers(flat):
    """(strong, weak) published indicators that this record was injected.

    The split matters. A genuine AD FS sign-in IS issued by AD FS and DOES
    use forms authentication, so those two together describe every federated
    tenant on earth -- a first cut counted them as two markers and flagged a
    legitimate record as forged. They are corroboration only.

    The decisive ones are the fields the forging pipeline cannot populate:
    an event injected through Connect Health has no application or resource
    to name, so it arrives as NotApplicable / NotSet with the federation
    resource id standing in.
    """
    strong, weak = [], []
    app = str(get(flat, "app", "")).strip().lower()
    res = str(get(flat, "resource", "")).strip().lower()
    if app in _FORGED_APP:
        strong.append("application is %s" % (app or "empty"))
    if res in _FORGED_APP:
        strong.append("resource is %s" % (res or "empty"))
    if resource_id_of(flat) == _FORGED_RESOURCE_ID:
        strong.append("resource id urn:federation:MicrosoftOnline")
    for key in ("tokenissuertype", "issuertype"):
        if str(flat.get(key, "")).strip().lower() == _FORGED_ISSUER:
            weak.append("token issuer type Federated (ADFS)")
            break
    for key in ("authenticationmethod", "authmethod"):
        if str(flat.get(key, "")).strip().lower() == _FORGED_AUTH_METHOD:
            weak.append("forms authentication")
            break
    return strong, weak


def looks_forged(flat):
    """At least one decisive marker, and at least two in total."""
    strong, weak = forged_markers(flat)
    return bool(strong) and (len(strong) + len(weak)) >= 2


def owner_device_addresses(records, affected_users, devices=None,
                           compromise_dt=None, log_last=None):
    """Addresses the affected accounts signed in from on their OWN devices.

    The mobile-phone false positive: a phone syncs the mailbox by folder,
    from a residential address that changes daily, and that reads exactly
    like an attacker pulling the mailbox down whole. What separates them is
    the device. A sign-in carrying a deviceId that is registered to this
    user in the tenant -- or managed, or compliant -- is their device, and
    every address it signed in from is theirs.

    Returns (addresses, evidence) where evidence maps address -> the device
    that vouched for it, so the report can say WHY an address was excused.
    """
    # Scope: the accounts under investigation when known; otherwise every
    # account, because the vouch is per-user anyway -- a device registered
    # to X excuses only X's addresses -- and this set is only ever used to
    # EXCLUDE from attribution.
    affected = {u.lower() for u in (affected_users or ()) if u}

    # A device the attacker registered is persistence, and it must not
    # vouch for the attacker's own address -- the same trap as a forged
    # sign-in event. Devices registered after the compromise are excluded;
    # with no compromise date, the last 30 days of the log are.
    cutoff = compromise_dt
    if cutoff is None and log_last is not None:
        cutoff = log_last - timedelta(days=30)
    registered, too_new = {}, 0
    for d in (devices or []):
        did = str(d.get("device_id") or "").strip().lower()
        if not did:
            continue
        reg = d.get("_dt")
        if cutoff is not None and reg is not None and reg >= cutoff:
            too_new += 1
            continue
        registered[did] = d

    out, why = set(), {}
    for _src, f in records:
        user = str(get(f, "user", "")).lower()
        if not user or (affected and user not in affected) or not succeeded(f):
            continue
        ip = str(get(f, "ip", ""))
        if not ip:
            continue
        # A device only vouches for a fresh, interactive authentication on
        # it. A replayed token presented "from" a device is the attacker.
        if token_claim_satisfied(f) and not truthy(get(f, "interactive", "")):
            continue
        did = str(get(f, "device_id", "")).strip().lower()
        vouch = ""
        if did and did in registered:
            d = registered[did]
            owner = str(d.get("owner") or "").lower()
            if not owner or user in owner or owner in user:
                vouch = "registered device %s" % (d.get("name") or did[:8])
            else:
                continue          # someone else's device; not the owner's
        elif truthy(get(f, "managed", "")) or truthy(get(f, "compliant", "")):
            vouch = "managed/compliant device%s" % (
                " " + str(get(f, "device_name", "")) if get(f, "device_name", "") else "")
        elif did and str(get(f, "trust_type", "")).strip().lower() in (
                "azuread", "azure ad joined", "hybrid azure ad joined",
                "azureadjoined", "hybridazureadjoined"):
            vouch = "%s device" % get(f, "trust_type", "")
        if vouch:
            out.add(ip)
            why.setdefault(ip, vouch)
    why["_devices_excluded_as_too_new"] = too_new
    return out, why


def _victim_addresses(records, affected_users):
    """Every IP seen on an interactive sign-in for an affected account.

    Used as a veto list. An address the account demonstrably signs in from
    interactively is the user's own, whatever leg of a device code group it
    later turns up on.
    """
    out, forged = set(), set()
    lowered = {u.lower() for u in affected_users if u}
    for _src, f in records:
        user = str(get(f, "user", "")).lower()
        if user and user in lowered and truthy(get(f, "interactive", "")):
            ip = str(get(f, "ip", ""))
            if not ip:
                continue
            # An injected event's IP is attacker-chosen. Letting it into the
            # veto would let the attacker exempt their own address from every
            # attribution in the report.
            if looks_forged(f):
                forged.add(ip)
                continue
            out.add(ip)
    return out, forged


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


# --------------------------------------------------------------------------
# Entry vectors beyond device code
#
# Device code is well covered above. The two vectors that dominate current
# caseloads were not covered at all: adversary-in-the-middle (Evilginx,
# EvilProxy, Tycoon), where the victim types real credentials and real MFA
# into a proxy and the attacker replays the resulting session; and legacy
# authentication, which never asks for MFA in the first place. Neither
# leaves anything for the device code rules to find.
# --------------------------------------------------------------------------

# ClientAppUsed values that mean legacy (basic) authentication. Conditional
# access and MFA do not apply to these protocols, which is the whole reason
# an attacker with a password uses them. "Other clients" is the catch-all
# Entra uses for legacy protocols it does not name.
_LEGACY_CLIENT_APPS = ("imap4", "pop3", "authenticated smtp", "smtp",
                       "exchange activesync", "exchange web services",
                       "other clients", "mapi over http", "offline address book",
                       "exchange online powershell", "autodiscover",
                       "reporting web services")
# The user agent Outlook-for-Android's basic-auth path sends, and the string
# every legacy-auth spray tool copies because Entra lets it through.
_LEGACY_AGENTS = ("bav2ropc",)

# Error codes that mean the password was RIGHT and only the second factor
# stood in the way. A run of these for one account from one address, ending
# in a success, is MFA fatigue: the attacker had the password and pushed
# prompts until one was approved.
_MFA_GATE_CODES = {"50074", "50076", "500121", "50079", "50072"}
# Wrong password. Many of these across many accounts from one address is a
# spray; many for one account is brute force.
_BAD_PASSWORD_CODES = {"50126", "50053", "50055", "50057"}

_AITM_FLOOR = 6


def error_code_of(flat):
    err = flat.get("errorcode")
    if err in (None, ""):
        err = flat.get("resulttype") or ""
    s = str(err).strip()
    return "" if s in ("0", "None") else s


def user_profiles(records):
    """Per-user: where and how they normally sign in, from the log itself.

    No shipped list can know that this user works from two countries or
    always uses Edge. Their own successful sign-ins can. An ASN or country
    that first appears on the event under assessment, and accounts for a
    small share of that user's sign-ins overall, is the outlier -- the same
    principle as the device code client baseline.
    """
    prof = {}
    for _src, f in records:
        user = str(get(f, "user", "")).lower()
        if not user or not succeeded(f):
            continue
        p = prof.setdefault(user, {"asn": Counter(), "country": Counter(),
                                   "agent": Counter(), "n": 0})
        p["n"] += 1
        asn = str(get(f, "asn", ""))
        if asn:
            p["asn"][asn] += 1
        c = country_of(f)
        if c:
            p["country"][c] += 1
        ua = short_agent(f, 30)
        if ua and ua != "?":
            p["agent"][ua] += 1
    return prof


_MIN_HISTORY = 5


def _is_rare(counter, key, n, share=0.05, floor=2):
    """Rare against THIS user's history -- which has to exist first.

    With no successful sign-ins on record every ASN, country and client is
    "new", and three location signals alone reached the reporting floor on a
    user whose only prior events were failures. Nothing is rare against
    nothing; below the minimum the location signals stay silent and the
    token evidence has to carry the finding on its own.
    """
    if not key or n < _MIN_HISTORY:
        return False
    seen = counter.get(key, 0)
    return seen <= max(floor, share * n)


def assess_aitm(flat, profiles):
    """Score one successful sign-in on the adversary-in-the-middle profile.

    The victim authenticated for real -- real password, real MFA -- through
    a proxy, and the attacker then presented the captured session. What the
    log shows is a SUCCESSFUL sign-in that performed no fresh authentication
    (MFA satisfied by a claim, or an incoming session token) from a place the
    user has never signed in from. No single field is decisive; the
    combination is.
    """
    if not succeeded(flat):
        return 0, []
    if is_device_code(flat)[0]:
        return 0, []                 # covered by its own rules
    reasons, score = [], 0
    user = str(get(flat, "user", "")).lower()
    p = profiles.get(user) or {"asn": Counter(), "country": Counter(),
                               "agent": Counter(), "n": 0}

    if token_claim_satisfied(flat):
        reasons.append("presented an existing session token (%s)"
                       % str(get(flat, "token_type", ""))[:24])
        score += 3
    if is_single_factor(flat):
        reasons.append("MFA satisfied by a claim, not performed")
        score += 2

    asn = str(get(flat, "asn", ""))
    if asn and _is_rare(p["asn"], asn, p["n"]):
        reasons.append("ASN %s not seen for this user before" % asn)
        score += 3
    c = country_of(flat)
    if c and _is_rare(p["country"], c, p["n"]):
        reasons.append("country %s not seen for this user before" % c)
        score += 2
    ua = short_agent(flat, 30)
    if ua and ua != "?" and _is_rare(p["agent"], ua, p["n"]):
        reasons.append("client %s not seen for this user before" % ua)
        score += 1

    risk = str(get(flat, "risk", "")).strip().lower()
    if risk in ("medium", "high"):
        reasons.append("Identity Protection risk: %s" % risk)
        score += 2
    return score, reasons


def aitm_candidates(records, profiles, victim_ips, limit=50):
    """Successful sign-ins that fit the AiTM profile, ranked."""
    out = []
    for _src, f in records:
        ip = str(get(f, "ip", ""))
        if ip and ip in victim_ips:
            continue
        score, reasons = assess_aitm(f, profiles)
        if score < 3:
            continue
        row = _leg_row(f)
        row.update({"user": str(get(f, "user", "")) or "(unknown)",
                    "score": score, "reasons": reasons,
                    "indicated": score >= _AITM_FLOOR,
                    "_dt": parse_time(get(f, "time", ""))})
        out.append(row)
    out.sort(key=lambda r: (-r["score"], r.get("time") or ""))
    return out[:limit]


def legacy_auth(records, affected_users=(), attacker_ips=()):
    """Sign-ins over protocols that never ask for MFA.

    Every one is reported, because legacy auth should be disabled and a
    tenant that still allows it wants to know. The ones that matter are
    successes for an affected account, or from an attacker address.
    """
    affected = {u.lower() for u in (affected_users or ()) if u}
    attacker_ips = set(attacker_ips or ())
    rows = []
    for _src, f in records:
        app = str(get(f, "client_app", "")).strip().lower()
        ua = str(get(f, "user_agent", "")).lower()
        legacy = any(a == app or a in app for a in _LEGACY_CLIENT_APPS) \
            or any(a in ua for a in _LEGACY_AGENTS)
        if not legacy:
            continue
        user = str(get(f, "user", "")).lower()
        ip = str(get(f, "ip", ""))
        row = _leg_row(f)
        row.update({
            "user": user or "(unknown)",
            "protocol": str(get(f, "client_app", "")) or "BAV2ROPC",
            "ok": succeeded(f),
            "affected_user": user in affected,
            "from_attacker": bool(ip and ip in attacker_ips),
        })
        rows.append(row)
    rows.sort(key=lambda r: (not (r["ok"] and (r["affected_user"] or r["from_attacker"])),
                             not r["ok"], r.get("time") or ""))
    hits = [r for r in rows if r["ok"] and (r["affected_user"] or r["from_attacker"])]
    return {
        "available": bool(rows),
        "total": len(rows),
        "successes": sum(1 for r in rows if r["ok"]),
        "protocols": Counter(r["protocol"] for r in rows).most_common(6),
        "indicated": hits[:50],
        "indicated_count": len(hits),
        "rows": rows[:50],
    }


def failed_login_patterns(records, window_minutes=60, fatigue_min=5,
                          spray_min_users=5):
    """MFA fatigue and password spray, from the failure codes.

    Fatigue: for one account from one address, a run of MFA-gate failures
    (the password was right) followed by a success. Spray: from one address,
    wrong-password failures across many accounts inside a window.
    """
    span = timedelta(minutes=window_minutes)
    by_pair = {}
    by_ip = {}
    for _src, f in records:
        code = error_code_of(f)
        user = str(get(f, "user", "")).lower()
        ip = str(get(f, "ip", ""))
        dt = parse_time(get(f, "time", ""))
        if not (user and ip and dt):
            continue
        by_pair.setdefault((user, ip), []).append((dt, code, succeeded(f), f))
        if code in _BAD_PASSWORD_CODES:
            by_ip.setdefault(ip, []).append((dt, user))

    fatigue = []
    for (user, ip), evs in by_pair.items():
        evs.sort(key=lambda x: x[0])
        gate = [e for e in evs if e[1] in _MFA_GATE_CODES]
        if len(gate) < fatigue_min:
            continue
        # a success that follows the run, within the window of its last prompt
        last_gate = gate[-1][0]
        after = [e for e in evs if e[2] and e[0] >= last_gate
                 and e[0] - last_gate <= span]
        # the prompts themselves must be dense, not spread over a month
        dense = (gate[-1][0] - gate[0][0]) <= span * 4
        if after and dense:
            fatigue.append({
                "user": user, "ip": ip,
                "prompts": len(gate),
                "first_prompt": gate[0][0].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "last_prompt": last_gate.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "approved_at": after[0][0].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "location": short_location(after[0][3]),
                "codes": sorted({e[1] for e in gate}),
            })
    fatigue.sort(key=lambda r: -r["prompts"])

    spray = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda x: x[0])
        # sliding window: the most users hit inside any span-long stretch
        best, best_start = 0, None
        j = 0
        for i in range(len(evs)):
            while evs[i][0] - evs[j][0] > span:
                j += 1
            users = {u for _d, u in evs[j:i + 1]}
            if len(users) > best:
                best, best_start = len(users), evs[j][0]
        if best >= spray_min_users:
            spray.append({
                "ip": ip, "users_hit": best, "failures": len(evs),
                "window_start": best_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "first": evs[0][0].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "last": evs[-1][0].strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
    spray.sort(key=lambda r: -r["users_hit"])
    return {"available": bool(by_pair), "fatigue": fatigue[:20],
            "fatigue_count": len(fatigue), "spray": spray[:20],
            "spray_count": len(spray)}


def analyze_signin_logs(path, devices=None):
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
    victim_ips, forged_veto_ips = _victim_addresses(records, affected_users)
    # The owner's own devices vouch for more addresses than interactive
    # sign-ins alone: a phone that only ever syncs never signs in
    # interactively, so its addresses never reached the veto.
    _log_last = max((parse_time(get(f, "time", "")) for _s, f in records
                     if get(f, "time", "")), default=None)
    device_ips, device_why = owner_device_addresses(
        records, affected_users, devices, compromise_dt=None, log_last=_log_last)
    victim_ips = set(victim_ips) | device_ips

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

    forged = []
    for _s, f in records:
        if not looks_forged(f):
            continue
        _strong, _weak = forged_markers(f)
        row = _leg_row(f)
        row.update({"user": str(get(f, "user", "")) or "(unknown)",
                    "markers": _strong + _weak})
        forged.append(row)
    forged.sort(key=lambda r: r.get("time") or "")

    single_leg = _single_leg_findings(buckets, victim_ips, hits)

    profiles = user_profiles(records)
    aitm = aitm_candidates(records, profiles, victim_ips)
    legacy = legacy_auth(records, affected_users, attacker_ips)
    failures = failed_login_patterns(records)

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
    if forged:
        warnings.append(
            "%d sign-in record(s) carry the published markers of a FORGED "
            "event -- an application of NotApplicable, a resource of NotSet, "
            "or the urn:federation:MicrosoftOnline resource id. Events can be "
            "injected into this log through the Azure AD Connect Health "
            "pipeline, from a compromised AD FS server or a fake health agent "
            "registered by a global administrator, and the injected record's "
            "timestamp, account and IP are all attacker-chosen. Treat every "
            "conclusion drawn from this export as provisional until the AD FS "
            "Security event log (Event ID 1200) is compared against it -- and "
            "compare on ADDRESS, not on time, because time is spoofed."
            % len(forged))
    if forged_veto_ips:
        warnings.append(
            "%d address(es) were kept OUT of the victim-address veto because "
            "the interactive sign-in asserting them looks forged. A single "
            "injected event naming the attacker's own address as the victim's "
            "would otherwise exempt it from attribution for the whole report."
            % len(forged_veto_ips))

    _ai = sum(1 for r in aitm if r["indicated"])
    if _ai:
        warnings.append(
            "%d successful sign-in(s) fit the adversary-in-the-middle profile: "
            "no fresh authentication performed (a session token presented, or "
            "MFA satisfied by a claim) from an ASN or country this account has "
            "not signed in from before. The victim authenticated for real "
            "through a proxy; this is the attacker replaying the result. "
            "Corroborate with a lure carrying a link in the minutes before."
            % _ai)
    if legacy.get("indicated_count"):
        warnings.append(
            "%d successful LEGACY-protocol sign-in(s) for an affected account "
            "or from an attacker address (%s). Legacy authentication never "
            "asks for MFA; a password alone is enough. Disable it tenant-wide."
            % (legacy["indicated_count"],
               ", ".join(p for p, _n in legacy["protocols"][:3])))
    if failures.get("fatigue_count"):
        warnings.append(
            "%d MFA-fatigue pattern(s): a run of MFA prompts for one account "
            "from one address, then an approval. The password was already "
            "known; the prompts were pushed until one was accepted."
            % failures["fatigue_count"])
    if failures.get("spray_count"):
        warnings.append(
            "%d password-spray source(s): wrong-password failures across "
            "many accounts from one address inside an hour."
            % failures["spray_count"])

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
        "forged_events": forged[:50],
        "forged_count": len(forged),
        "forged_veto_ips": sorted(forged_veto_ips),
        # Addresses the affected accounts sign in from interactively, with
        # forged records already excluded. The audit side uses this the same
        # way this module does: an owner address never seeds attribution.
        "owner_ips": sorted(victim_ips),
        "owner_device_ips": sorted(device_ips),
        "owner_device_evidence": device_why,
        # Every address that authenticated at all, device code or not. The
        # token-replay test needs the full set, not the device code subset.
        "all_signin_ips": sorted({str(get(f, "ip", "")) for _s, f in records
                                  if get(f, "ip", "")}),
        "single_leg_findings": single_leg,
        "single_leg_count": len(single_leg),
        "indicated_count": sum(1 for r in single_leg if r["indicated"]),
        # Where each account normally signs in from, by the account's own
        # record. The audit-log GeoIP pass uses this ahead of the global
        # --expected-countries: a user who works from two countries is not
        # an anomaly in either of them.
        "user_countries": {
            u: dict(p["country"], _n=p["n"])
            for u, p in profiles.items() if p["n"] >= _MIN_HISTORY},
        "aitm": [{k: v for k, v in r.items() if not k.startswith("_")}
                 for r in aitm],
        "aitm_indicated": sum(1 for r in aitm if r["indicated"]),
        "legacy_auth": legacy,
        "login_failures": failures,
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

    # The service's own background processes never sign in, so an address
    # whose every operation is RESTSystem/Substrate is not replaying anything.
    # An application reading through Graph or EWS on its own credentials
    # does not sign in as the user either -- but that is ALSO what an
    # attacker's consent-granted app looks like, so it is labelled, not
    # excused: the analyst checks the app id against the OAuth grants.
    cp = a.get("client_profile") or {}
    system_only = set(cp.get("system_only_ips") or ())
    app_access = set(cp.get("app_access_ips") or ())
    by_ip = {r["ip"]: r for r in (cp.get("addresses") or [])}

    replay, outside, excused = [], 0, []
    for row in activity:
        ip = str(row.get("ip") or "")
        if not ip or ip in authenticated:
            continue
        if ip in system_only:
            excused.append({"ip": ip, "events": row.get("events"),
                            "why": "every operation from an Exchange "
                                   "background client (RESTSystem/Substrate)"})
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
        prof = by_ip.get(ip) or {}
        replay.append({
            "ip": ip, "events": row.get("events"),
            "app_access": ip in app_access,
            "app_ids": [a for a, _n in (prof.get("app_ids") or [])],
            "client": prof.get("top_client", ""),
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
        "excused_system": excused,
        "app_access_count": sum(1 for r in replay if r["app_access"]),
        "note": ("Each address below performed mailbox operations inside the "
                 "sign-in log's own window without any authentication being "
                 "recorded for it. A token obtained by refreshing an earlier "
                 "one leaves exactly this trace: the access happens, and "
                 "Entra logs nothing. Addresses whose activity falls outside "
                 "the sign-in window are excluded rather than claimed, and so "
                 "are addresses whose every operation came from an Exchange "
                 "background client. An address marked APP reached the "
                 "mailbox through Graph or EWS on an application's own "
                 "credentials: an archiver or a ticketing system does that, "
                 "and so does an attacker's consent-granted app -- check the "
                 "app id against the OAuth grants."),
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
