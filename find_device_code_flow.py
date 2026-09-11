#!/usr/bin/env python3
"""Find device code flow sign-ins in an Entra ID sign-in log export.

Postmortem detects the *lure* -- the mail that talks a user into entering a
code at a genuine Microsoft URL. It cannot tell you whether anyone actually
did it, because the flow leaves no trace in the mailbox. That evidence lives
in the Entra ID sign-in logs, and this script is how you read it.

What a successful device code flow attack looks like in the logs
----------------------------------------------------------------
The attacker starts a device authorization grant against a first-party
Microsoft client and gets back a user code. The victim enters that code at
microsoft.com/devicelogin and authenticates for real -- MFA included. The
resulting tokens are issued to the *attacker*, who has been polling the token
endpoint the whole time.

Both halves share one correlation ID:

  leg A   isInteractive = true    the victim's browser, MFA satisfied,
                                  the victim's usual IP and user agent
  leg B   isInteractive = false   the attacker polling for the token,
                                  typically a different IP, country, ASN
                                  and user agent

So a correlation ID whose legs disagree about *where they came from* is the
finding. A matched pair from one IP is usually a real admin enrolling a
genuine shared device.

Because no password is ever learned, a password reset does not evict the
attacker. Only revoking refresh tokens does.

Usage
-----
    python find_device_code_flow.py <folder-with-json-files>
    python find_device_code_flow.py <folder> --csv findings.csv
    python find_device_code_flow.py <folder> --all-signins-for user@corp.com

Reads only. Nothing leaves the machine. No third-party packages.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import defaultdict, Counter

# --------------------------------------------------------------------------
# Field lookup
#
# Entra sign-in records reach disk in several shapes: Graph API JSON
# (camelCase), portal "Download JSON" (camelCase, sometimes nested
# differently), Log Analytics / Sentinel export (PascalCase, and properties
# hoisted to the top level). Rather than guess which one this is, every field
# is resolved case-insensitively against a list of known spellings.
# --------------------------------------------------------------------------

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


def _flatten(obj, out=None, depth=0):
    """Collapse a record to a lowercase-key map, one level of nesting deep.

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
            if lk not in out:
                out[lk] = v
            _flatten(v, out, depth + 1)
        elif isinstance(v, list):
            if lk not in out:
                out[lk] = v
        else:
            if lk not in out:
                out[lk] = v
    return out


def get(flat, name, default=""):
    for spelling in FIELDS.get(name, [name]):
        v = flat.get(spelling.lower())
        if v not in (None, ""):
            return v
    return default


def location_of(flat):
    city = flat.get("city") or ""
    state = flat.get("state") or ""
    country = flat.get("countryorregion") or flat.get("country") or ""
    parts = [p for p in (city, state, country) if p]
    return ", ".join(parts)


def status_of(flat):
    err = flat.get("errorcode")
    if err in (None, ""):
        err = flat.get("resultType") or flat.get("resulttype") or ""
    try:
        failed = int(err) != 0
    except (TypeError, ValueError):
        failed = bool(err) and str(err) not in ("0", "None")
    reason = (flat.get("failurereason") or flat.get("resultdescription") or "")
    if failed:
        return "FAIL(%s) %s" % (err, str(reason)[:60])
    return "success"


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def iter_records(path):
    """Yield sign-in records from one file, whatever container it uses."""
    try:
        raw = open(path, "r", encoding="utf-8-sig", errors="replace").read()
    except OSError as exc:
        print("  ! cannot read %s: %s" % (path, exc), file=sys.stderr)
        return

    raw = raw.strip()
    if not raw:
        return

    # Whole-file JSON: a bare array, a Graph {"value": [...]} envelope, or a
    # single record.
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

    # NDJSON / JSON-lines.
    n = 0
    for line in raw.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(r, dict):
            n += 1
            yield r
    if n == 0:
        print("  ! %s: no JSON records recognised" % os.path.basename(path),
              file=sys.stderr)


def load_folder(folder):
    files = []
    for root, _dirs, names in os.walk(folder):
        for n in sorted(names):
            if n.lower().endswith((".json", ".ndjson", ".jsonl")):
                files.append(os.path.join(root, n))
    if not files:
        print("No .json/.ndjson/.jsonl files under %s" % folder, file=sys.stderr)
        return [], []

    records = []
    for p in files:
        before = len(records)
        for r in iter_records(p):
            records.append((os.path.basename(p), _flatten(r)))
        print("  %-52s %6d records" % (os.path.basename(p)[:52],
                                       len(records) - before))
    return files, records


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

def is_device_code(flat):
    transfer = str(get(flat, "transfer", "")).strip().lower()
    if transfer in ("devicecodeflow", "device code flow", "devicecode"):
        return True, "originalTransferMethod"
    protocol = str(get(flat, "protocol", "")).strip().lower()
    if protocol in ("devicecode", "device code", "devicecodeflow"):
        return True, "authenticationProtocol"
    return False, ""


def truthy(v):
    return str(v).strip().lower() in ("true", "1", "yes")


def main():
    ap = argparse.ArgumentParser(
        description="Find device code flow sign-ins in an Entra sign-in log export.")
    ap.add_argument("folder", help="folder containing the exported JSON files")
    ap.add_argument("--csv", default="device_code_flow_findings.csv",
                    help="where to write the findings CSV")
    ap.add_argument("--all-signins-for", default="",
                    help="also dump every sign-in for this UPN, device code or not")
    args = ap.parse_args()

    if not os.path.isdir(args.folder):
        print("Not a folder: %s" % args.folder, file=sys.stderr)
        return 2

    print("Reading %s" % os.path.abspath(args.folder))
    files, records = load_folder(args.folder)
    if not records:
        return 1
    print("\n%d records from %d file(s)\n" % (len(records), len(files)))

    # ------------------------------------------------------------------
    # Did this export even carry the fields the detection needs? An export
    # that lacks the column must not be read as "no device code flow found".
    # ------------------------------------------------------------------
    have_transfer = sum(1 for _, f in records if get(f, "transfer", "") != "")
    have_protocol = sum(1 for _, f in records if get(f, "protocol", "") != "")
    have_correlation = sum(1 for _, f in records if get(f, "correlation", "") != "")

    print("Field coverage")
    print("  originalTransferMethod present in %d of %d records" %
          (have_transfer, len(records)))
    print("  authenticationProtocol present in %d of %d records" %
          (have_protocol, len(records)))
    print("  correlationId present in %d of %d records" %
          (have_correlation, len(records)))
    if have_transfer == 0 and have_protocol == 0:
        print("""
  *** Neither field is present in this export. ***

  This export CANNOT answer the device code flow question -- a clean result
  here would mean the column is missing, not that the attack did not happen.
  Re-export the sign-in logs including originalTransferMethod (Graph API
  /auditLogs/signIns carries it; the portal's "Download JSON" does too, the
  CSV download does not), or query Log Analytics if sign-ins are shipped
  there.
""")

    hits = [(src, f) for src, f in records if is_device_code(f)[0]]

    if not hits:
        print("\nNo device code flow sign-ins found in %d records." % len(records))
        if have_transfer or have_protocol:
            print("The export does carry the field, so this is a real negative")
            print("for the window and users it covers. Check that the window")
            print("spans the suspected compromise date before concluding.")
        return 0

    print("\n%d device code flow sign-in record(s)\n" % len(hits))

    # ------------------------------------------------------------------
    # Pair the legs. Both halves of one flow share a correlation ID; the
    # interesting case is legs that disagree about where they came from.
    # ------------------------------------------------------------------
    groups = defaultdict(list)
    for src, f in hits:
        groups[str(get(f, "correlation", "(no correlation id)"))].append((src, f))

    rows = []
    suspicious = []

    for cid, legs in sorted(
            groups.items(),
            key=lambda kv: str(get(kv[1][0][1], "time", ""))):
        ips = {str(get(f, "ip", "")) for _, f in legs if get(f, "ip", "")}
        countries = {location_of(f).split(", ")[-1] for _, f in legs if location_of(f)}
        agents = {str(get(f, "user_agent", "")) for _, f in legs if get(f, "user_agent", "")}
        asns = {str(get(f, "asn", "")) for _, f in legs if get(f, "asn", "")}

        flags = []
        if len(ips) > 1:
            flags.append("IP MISMATCH")
        if len(countries) > 1:
            flags.append("COUNTRY MISMATCH")
        if len(asns) > 1:
            flags.append("ASN MISMATCH")
        if len(agents) > 1:
            flags.append("USER-AGENT MISMATCH")
        interactive_states = {truthy(get(f, "interactive", "")) for _, f in legs}
        if len(interactive_states) > 1:
            flags.append("interactive + non-interactive pair")

        verdict = "REVIEW"
        if any(x in flags for x in ("IP MISMATCH", "COUNTRY MISMATCH", "ASN MISMATCH")):
            verdict = "LIKELY ATTACK"
            suspicious.append(cid)
        elif len(legs) == 1:
            verdict = "single leg only"

        user = get(legs[0][1], "user", "(unknown)")
        print("-" * 78)
        print("correlationId %s" % cid)
        print("  user     : %s" % user)
        print("  verdict  : %s%s" % (verdict, ("  [" + ", ".join(flags) + "]") if flags else ""))
        for src, f in sorted(legs, key=lambda x: str(get(x[1], "time", ""))):
            print("    %s  interactive=%-5s  %s" % (
                str(get(f, "time", ""))[:19],
                truthy(get(f, "interactive", "")),
                status_of(f)))
            print("        app  : %s -> %s" % (get(f, "app", "?"), get(f, "resource", "?")))
            print("        from : %s  %s  ASN %s" % (
                get(f, "ip", "?"), location_of(f) or "?", get(f, "asn", "?")))
            print("        agent: %s" % str(get(f, "user_agent", "?"))[:96])
            print("        auth : %s / CA %s / risk %s" % (
                get(f, "auth_req", "?"), get(f, "ca_status", "?"), get(f, "risk", "?")))
            rows.append({
                "correlationId": cid,
                "verdict": verdict,
                "flags": "; ".join(flags),
                "time": get(f, "time", ""),
                "user": get(f, "user", ""),
                "isInteractive": truthy(get(f, "interactive", "")),
                "status": status_of(f),
                "app": get(f, "app", ""),
                "resource": get(f, "resource", ""),
                "ip": get(f, "ip", ""),
                "location": location_of(f),
                "asn": get(f, "asn", ""),
                "userAgent": get(f, "user_agent", ""),
                "clientApp": get(f, "client_app", ""),
                "authRequirement": get(f, "auth_req", ""),
                "conditionalAccess": get(f, "ca_status", ""),
                "risk": get(f, "risk", ""),
                "riskState": get(f, "risk_state", ""),
                "detectedVia": is_device_code(f)[1],
                "sourceFile": src,
            })

    # ------------------------------------------------------------------
    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    by_user = Counter(get(f, "user", "(unknown)") for _, f in hits)
    for user, n in by_user.most_common():
        print("  %-44s %3d device code sign-in record(s)" % (user, n))

    print("\n  %d correlation group(s); %d with a location mismatch between legs"
          % (len(groups), len(suspicious)))

    if suspicious:
        print("""
  A correlation group whose two legs came from different IPs, countries or
  ASNs is the signature of this attack: one leg is the victim completing MFA
  in their browser, the other is the attacker collecting the token.

  If any of these succeeded, treat the account as compromised and note that a
  password reset alone does NOT evict the attacker -- the tokens are already
  issued. Revoke refresh tokens (Revoke-MgUserSignInSession, or "Revoke
  sessions" on the user in Entra), then reset the password, then review the
  mailbox for rules and forwarding created after the timestamps above.""")

    out = os.path.abspath(args.csv)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("\n  CSV written: %s" % out)

    if args.all_signins_for:
        target = args.all_signins_for.strip().lower()
        same = [(s, f) for s, f in records
                if str(get(f, "user", "")).lower() == target]
        print("\n" + "=" * 78)
        print("ALL SIGN-INS FOR %s  (%d)" % (args.all_signins_for, len(same)))
        print("=" * 78)
        for _s, f in sorted(same, key=lambda x: str(get(x[1], "time", ""))):
            dcf, _ = is_device_code(f)
            print("  %s  %-9s %-28s %-16s %s%s" % (
                str(get(f, "time", ""))[:19],
                status_of(f)[:9],
                str(get(f, "app", ""))[:28],
                str(get(f, "ip", ""))[:16],
                location_of(f)[:28],
                "   <== DEVICE CODE" if dcf else ""))

    return 0


if __name__ == "__main__":
    sys.exit(main())
