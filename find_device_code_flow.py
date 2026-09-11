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
    python find_device_code_flow.py <folder> --verbose
    python find_device_code_flow.py <folder> --csv findings.csv
    python find_device_code_flow.py <folder> --all-signins-for user@corp.com
    python find_device_code_flow.py <folder> --no-color

Note it is a script, not a module: run it WITHOUT ``-m``.

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
# Colour
#
# Severity is the one thing worth seeing before reading a word, so it is
# carried by colour rather than by more text. Everything degrades to plain
# ASCII when stdout is redirected, when --no-color is passed, or when the
# terminal cannot do VT sequences -- the markers ([!!], [!], [ok]) carry the
# same information on their own, so a piped run loses nothing.
# --------------------------------------------------------------------------

class C:
    RED = BRED = YEL = GRN = CYA = DIM = BOLD = OFF = ""

    @classmethod
    def enable(cls):
        cls.RED, cls.BRED = "\033[31m", "\033[1;31m"
        cls.YEL, cls.GRN = "\033[33m", "\033[32m"
        cls.CYA, cls.DIM = "\033[36m", "\033[2m"
        cls.BOLD, cls.OFF = "\033[1m", "\033[0m"


def setup_color(disabled: bool) -> None:
    if disabled or not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return
    if os.name == "nt":
        # Windows 10+ consoles support VT sequences but do not enable them by
        # default for a plain python.exe. Without this the output is littered
        # with raw escape codes, which is worse than no colour at all.
        try:
            import ctypes
            k = ctypes.windll.kernel32
            handle = k.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if not k.GetConsoleMode(handle, ctypes.byref(mode)):
                return
            if not k.SetConsoleMode(handle, mode.value | 0x0004):
                return
        except Exception:
            return
    C.enable()


def rule(char="-", width=74):
    return char * width


# --------------------------------------------------------------------------
# Field lookup
#
# Entra sign-in records reach disk in several shapes: Graph API JSON
# (camelCase), portal "Download JSON" (camelCase, sometimes nested
# differently), Log Analytics / Sentinel export (PascalCase, properties
# hoisted). Rather than guess which one this is, every field is resolved
# case-insensitively against a list of known spellings.
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


def location_of(flat):
    parts = [p for p in (flat.get("city") or "", flat.get("state") or "",
                         country_of(flat)) if p]
    return ", ".join(parts)


def short_location(flat):
    city = str(flat.get("city") or "")
    country = country_of(flat)
    if city and country:
        return "%s, %s" % (city, country)
    return city or country or "?"


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
        return "FAILED(%s) %s" % (err, str(reason)[:50])
    return "success"


def succeeded(flat):
    return status_of(flat) == "success"


def truthy(v):
    return str(v).strip().lower() in ("true", "1", "yes")


def short_agent(flat, width=34):
    ua = str(get(flat, "user_agent", "") or get(flat, "client_app", "") or "?")
    # Full user-agent strings are the single biggest source of wall-of-text
    # here and the interesting part is almost always the client family.
    for token in ("python-requests", "curl", "Go-http-client", "axios",
                  "PowerShell", "okhttp", "Chrome", "Firefox", "Safari",
                  "Edg", "Electron", "Mobile"):
        if token.lower() in ua.lower():
            idx = ua.lower().index(token.lower())
            return ua[idx:idx + width]
    return ua[:width]


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
        print("  %s! %s: no JSON records recognised%s"
              % (C.YEL, os.path.basename(path), C.OFF), file=sys.stderr)


def load_folder(folder, verbose):
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
        if verbose:
            print("  %s%-52s%s %6d records"
                  % (C.DIM, os.path.basename(p)[:52], C.OFF,
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


def assess(legs):
    """Verdict and concrete mismatches for one correlation group."""
    ips = {str(get(f, "ip", "")) for _, f in legs if get(f, "ip", "")}
    countries = {country_of(f) for _, f in legs if country_of(f)}
    asns = {str(get(f, "asn", "")) for _, f in legs if get(f, "asn", "")}
    agents = {short_agent(f) for _, f in legs if get(f, "user_agent", "")}

    mismatches = []
    if len(ips) > 1:
        mismatches.append("IP")
    if len(countries) > 1:
        mismatches.append("country")
    if len(asns) > 1:
        mismatches.append("ASN")
    if len(agents) > 1:
        mismatches.append("user-agent")

    paired = len({truthy(get(f, "interactive", "")) for _, f in legs}) > 1
    located = [m for m in mismatches if m in ("IP", "country", "ASN")]

    if located:
        verdict = "LIKELY ATTACK"
    elif len(legs) == 1:
        verdict = "SINGLE LEG"
    else:
        verdict = "REVIEW"
    return verdict, mismatches, paired, ips, countries, asns, agents


VERDICT_STYLE = {
    "LIKELY ATTACK": ("[!!]", lambda: C.BRED),
    "SINGLE LEG":    ("[! ]", lambda: C.YEL),
    "REVIEW":        ("[ok]", lambda: C.GRN),
}


def print_group(cid, legs, verdict, mismatches, paired, diff_fields, verbose):
    marker, colour = VERDICT_STYLE[verdict]
    col = colour()
    user = get(legs[0][1], "user", "(unknown)")
    when = str(get(legs[0][1], "time", ""))[:16].replace("T", " ")

    print("%s%s %-44s%s %s%s%s"
          % (col, marker, user[:44], C.OFF, C.DIM, when, C.OFF))

    for _src, f in sorted(legs, key=lambda x: str(get(x[1], "time", ""))):
        interactive = truthy(get(f, "interactive", ""))
        role = "browser " if interactive else "polling "
        # The polling leg is the attacker's half when the legs disagree, so it
        # is the one that gets the colour.
        lead = col if (not interactive and verdict == "LIKELY ATTACK") else C.DIM

        def mark(value, field, width):
            # Pad before colouring: escape sequences count toward a %-Ns field
            # width, so colouring first knocks every later column out of line.
            cell = str(value)[:width].ljust(width)
            if field in mismatches and verdict == "LIKELY ATTACK":
                return "%s%s%s" % (col, cell, C.OFF)
            return cell

        ok = succeeded(f)
        st = ("%ssuccess%s" % (C.RED if not interactive and
                               verdict == "LIKELY ATTACK" else C.DIM, C.OFF)
              if ok else "%s%s%s" % (C.YEL, status_of(f)[:22], C.OFF))

        print("     %s%s%s %s %s %s %s %s"
              % (lead, role, C.OFF,
                 mark(get(f, "ip", "?"), "IP", 15),
                 mark(short_location(f), "country", 18),
                 mark("AS" + str(get(f, "asn", "?")), "ASN", 9),
                 mark(short_agent(f, 26), "user-agent", 26),
                 st))
        if verbose:
            print("       %sapp %s -> %s | auth %s | CA %s | risk %s%s"
                  % (C.DIM, get(f, "app", "?"), get(f, "resource", "?"),
                     get(f, "auth_req", "?"), get(f, "ca_status", "?"),
                     get(f, "risk", "?"), C.OFF))

    bits = []
    if mismatches:
        bits.append("%sdiffers: %s%s" % (col, " ".join(mismatches), C.OFF))
    if paired:
        bits.append("%sinteractive+polling pair%s" % (C.DIM, C.OFF))
    if verdict == "SINGLE LEG":
        bits.append("%sonly one leg in this export%s" % (C.DIM, C.OFF))
    if any(succeeded(f) for _, f in legs) and verdict == "LIKELY ATTACK":
        bits.append("%sTOKENS ISSUED%s" % (C.BRED, C.OFF))
    if bits:
        print("     %s%s" % (C.DIM + "cid " + cid[:20] + C.OFF + "  ",
                             " | ".join(bits)))
    else:
        print("     %scid %s%s" % (C.DIM, cid[:20], C.OFF))
    print()


def main():
    ap = argparse.ArgumentParser(
        description="Find device code flow sign-ins in an Entra sign-in log export.")
    ap.add_argument("folder", help="folder containing the exported JSON files")
    ap.add_argument("--csv", default="device_code_flow_findings.csv",
                    help="where to write the findings CSV")
    ap.add_argument("--all-signins-for", default="",
                    help="also dump every sign-in for this UPN, device code or not")
    ap.add_argument("--verbose", action="store_true",
                    help="per-file counts and per-leg app/CA/risk detail")
    ap.add_argument("--no-color", action="store_true", help="plain output")
    args = ap.parse_args()

    setup_color(args.no_color)

    if not os.path.isdir(args.folder):
        print("Not a folder: %s" % args.folder, file=sys.stderr)
        return 2

    files, records = load_folder(args.folder, args.verbose)
    if not records:
        return 1

    have_transfer = sum(1 for _, f in records if get(f, "transfer", "") != "")
    have_protocol = sum(1 for _, f in records if get(f, "protocol", "") != "")

    print("%s%d records from %d file(s)%s"
          % (C.DIM, len(records), len(files), C.OFF))

    # An export that lacks the field cannot answer the question, and a clean
    # result from one would be the most dangerous output this script could
    # produce. So that case is loud, and it is the only time coverage is
    # discussed at all.
    if have_transfer == 0 and have_protocol == 0:
        print()
        print("%s%s THIS EXPORT CANNOT ANSWER THE QUESTION %s" % (C.BRED, "[!!]", C.OFF))
        print("    Neither originalTransferMethod nor authenticationProtocol is")
        print("    present in any record, so a clean result here would mean the")
        print("    column is missing -- not that the attack did not happen.")
        print("    Re-export including originalTransferMethod: the Graph API")
        print("    (/auditLogs/signIns) and the portal's Download JSON both carry")
        print("    it; the portal's CSV download does not.")
        print()
        return 1

    hits = [(src, f) for src, f in records if is_device_code(f)[0]]

    if not hits:
        print()
        print("%s[ok] No device code flow sign-ins in %d records.%s"
              % (C.GRN, len(records), C.OFF))
        print("     %sThe field is present, so this is a real negative for the"
              % C.DIM)
        print("     window and users this export covers -- check that window"
              " spans")
        print("     the suspected compromise date before concluding.%s" % C.OFF)
        return 0

    groups = defaultdict(list)
    for src, f in hits:
        groups[str(get(f, "correlation", "(no correlation id)"))].append((src, f))

    assessed = []
    for cid, legs in groups.items():
        verdict, mismatches, paired, ips, countries, asns, agents = assess(legs)
        assessed.append((cid, legs, verdict, mismatches, paired))

    order = {"LIKELY ATTACK": 0, "SINGLE LEG": 1, "REVIEW": 2}
    assessed.sort(key=lambda x: (order[x[2]], str(get(x[1][0][1], "time", ""))))

    counts = Counter(a[2] for a in assessed)
    print("%s%d device code sign-in record(s) in %d correlation group(s)%s"
          % (C.BOLD, len(hits), len(groups), C.OFF))
    print("  %s%d likely attack%s   %s%d single leg%s   %s%d benign-looking%s"
          % (C.BRED, counts.get("LIKELY ATTACK", 0), C.OFF,
             C.YEL, counts.get("SINGLE LEG", 0), C.OFF,
             C.GRN, counts.get("REVIEW", 0), C.OFF))
    print()

    last_verdict = None
    for cid, legs, verdict, mismatches, paired in assessed:
        if verdict != last_verdict:
            col = VERDICT_STYLE[verdict][1]()
            label = {
                "LIKELY ATTACK": "LIKELY ATTACK -- legs came from different places",
                "SINGLE LEG": "SINGLE LEG -- no pair to compare against",
                "REVIEW": "CONSISTENT -- one origin, most likely a real enrolment",
            }[verdict]
            print("%s%s%s" % (col, label, C.OFF))
            print("%s%s%s" % (C.DIM, rule(), C.OFF))
            last_verdict = verdict
        print_group(cid, legs, verdict, mismatches, paired,
                    None, args.verbose)

    if counts.get("LIKELY ATTACK"):
        print("%s%s%s" % (C.BRED, rule("="), C.OFF))
        print("%sWHAT TO DO%s" % (C.BOLD, C.OFF))
        print("%s%s%s" % (C.BRED, rule("="), C.OFF))
        print("  One leg is the victim completing MFA in their browser; the")
        print("  other is the attacker collecting the token.")
        print()
        print("  %sA password reset does NOT evict them%s -- no password was ever"
              % (C.BRED, C.OFF))
        print("  learned and the tokens are already issued. In order:")
        print("    1. Revoke refresh tokens  (Revoke-MgUserSignInSession, or")
        print("       \"Revoke sessions\" on the user in Entra)")
        print("    2. Reset the password")
        print("    3. Review the mailbox for rules and forwarding created")
        print("       after the timestamps above")
        print()

    rows = []
    for cid, legs, verdict, mismatches, paired in assessed:
        for src, f in sorted(legs, key=lambda x: str(get(x[1], "time", ""))):
            rows.append({
                "correlationId": cid,
                "verdict": verdict,
                "mismatches": "; ".join(mismatches),
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

    out = os.path.abspath(args.csv)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("%sFull detail for all %d record(s): %s%s" % (C.DIM, len(rows), out, C.OFF))

    by_user = Counter(get(f, "user", "(unknown)") for _, f in hits)
    if len(by_user) > 1:
        print("%sAffected accounts: %s%s"
              % (C.DIM, ", ".join(u for u, _ in by_user.most_common()), C.OFF))

    if args.all_signins_for:
        target = args.all_signins_for.strip().lower()
        same = [(s, f) for s, f in records
                if str(get(f, "user", "")).lower() == target]
        print()
        print("%sALL SIGN-INS FOR %s (%d)%s"
              % (C.BOLD, args.all_signins_for, len(same), C.OFF))
        print("%s%s%s" % (C.DIM, rule(), C.OFF))
        for _s, f in sorted(same, key=lambda x: str(get(x[1], "time", ""))):
            dcf = is_device_code(f)[0]
            line = "  %s  %-9s %-26s %-15s %s" % (
                str(get(f, "time", ""))[:16].replace("T", " "),
                status_of(f)[:9], str(get(f, "app", ""))[:26],
                str(get(f, "ip", ""))[:15], short_location(f)[:22])
            print("%s%s%s" % (C.RED if dcf else C.DIM, line,
                              ("   <== DEVICE CODE" if dcf else "")) + C.OFF)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # Piping to `more`, `head` or a pager that exits early is a normal way
        # to read this; a traceback on top of the output is not helpful.
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
