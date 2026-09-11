"""Discover and route the output of Microsoft-Extractor-Suite.

MES (invictus-ir) collects from a tenant with one command and writes a tree of
files whose names identify what they are. Rather than make the analyst pass a
separate flag per artefact -- five paths typed correctly, in the right order,
every run -- this walks the tree and decides what each file is.

Identification is by filename first and header second, because the filename is
how MES distinguishes its outputs but a renamed or re-exported file still has
to be recognised. A file that matches nothing is reported as unrecognised
rather than silently skipped: an analyst who exported something and does not
see it counted needs to know the tool did not read it.

The dispatcher never parses; it decides what a file IS. Parsing stays in the
module that owns the format, so pointing an explicit flag at a single file and
letting the dispatcher find that same file take exactly the same code path.
"""

from __future__ import annotations

import io
import os
import re

# kind -> (filename patterns, header columns that confirm it)
#
# Header sets are deliberately small and specific: enough to tell two MES
# outputs apart, not a schema. MES adds columns between releases and matching
# on a full header would break on every upgrade.
_RECOGNISERS = [
    ("signin_logs",
     (r"signin", r"sign-in", r"interactivesignin", r"noninteractivesignin"),
     ("originaltransfermethod", "authenticationprotocol", "correlationid",
      "isinteractive")),
    ("entra_audit",
     (r"auditlog", r"entraaudit", r"directoryaudit", r"graphentraaudit"),
     ("activitydisplayname", "initiatedby", "targetresources")),
    ("unified_audit",
     (r"\bual\b", r"unifiedaudit", r"auditrecords"),
     ("auditdata", "recordtype", "creationtime")),
    ("oauth_permissions",
     (r"oauth", r"permission", r"consent", r"serviceprincipal", r"applications"),
     ("permission", "permissions", "consenttype", "clientdisplayname",
      "applicationname")),
    ("mfa",
     (r"\bmfa\b", r"authenticationmethod", r"securityinfo"),
     ("mfaenabled", "mfamethods", "authenticationmethods")),
    ("devices",
     (r"device",),
     ("trusttype", "operatingsystem", "deviceid", "iscompliant")),
    ("role_activity",
     (r"\brole", r"\bpim\b", r"roleactivity", r"adminusers", r"privileged"),
     ("rolename", "roledisplayname", "assignmenttype", "directoryrole")),
    ("risk_detections",
     (r"risky", r"riskdetection", r"riskyusers", r"identityprotection"),
     ("riskeventtype", "risklevel", "riskstate", "riskdetail")),
    ("message_trace",
     (r"messagetrace", r"-mtl", r"\bmtl\b"),
     ("recipientaddress", "senderaddress", "messagetraceid")),
    ("mailbox_rules",
     (r"inboxrule", r"mailboxrule"),
     ("ruleidentity", "rulename", "forwardto", "redirectto")),
    ("transport_rules",
     (r"transportrule",),
     ("redirectmessageto", "blindcopyto", "state")),
    ("mailbox_permissions",
     (r"mailboxpermission", r"delegat", r"recipientpermission"),
     ("accessrights", "trustee", "identity")),
    ("users",
     (r"\busers\b", r"getusers", r"accounts", r"adminusers"),
     ("userprincipalname", "accountenabled", "usertype", "displayname")),
    ("accepted_domains",
     (r"accepteddomain", r"\bdomains?\b", r"tenantdomain"),
     ("domainname", "domaintype", "default")),
    ("mailbox_audit_status",
     (r"mailboxauditstatus", r"auditstatus", r"auditconfig"),
     ("auditenabled", "auditowner", "auditdelegate", "auditlogagelimit")),
]

_EXTENSIONS = (".csv", ".json", ".jsonl", ".ndjson")

# Only these are consumed today. The rest are recognised and counted so the
# report can say what was collected but not yet used, which is more honest
# than silence and tells the analyst what a later version will pick up.
CONSUMED = {"entra_audit", "oauth_permissions", "mfa", "devices",
            "role_activity", "risk_detections",
            "users", "accepted_domains", "mailbox_rules",
            "transport_rules", "mailbox_permissions",
            "mailbox_audit_status"}

# Recognised here but parsed by the module that owns the format, so the
# manifest can say "routed" rather than implying it went unread.
ROUTED = {"signin_logs": "postmortem.signin",
          "unified_audit": "postmortem.auditlog"}


def _header_of(path, limit=8192):
    """Lowercased column names, whether the file is CSV or JSON."""
    try:
        with io.open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            head = fh.read(limit)
    except OSError:
        return set()
    if not head.strip():
        return set()
    if head.lstrip()[:1] in "[{":
        # Keys appear as "key": in the first object; good enough to identify.
        return {m.lower() for m in re.findall(r'"([A-Za-z0-9_@.]+)"\s*:', head)}
    line = head.splitlines()[0] if head.splitlines() else ""
    return {c.strip().strip('"').lower() for c in re.split(r"[,;\t|]", line)}


def identify(path):
    """What this file is, or "" -- filename first, header as the tiebreak."""
    name = os.path.basename(path).lower()
    header = None
    filename_hits = []

    for kind, patterns, columns in _RECOGNISERS:
        if any(re.search(p, name) for p in patterns):
            filename_hits.append((kind, columns))

    if len(filename_hits) == 1:
        return filename_hits[0][0]

    # Either nothing matched the name, or several did ("AuditLogs" matches both
    # the directory audit and the unified audit log). The header decides.
    header = _header_of(path)
    if not header:
        return filename_hits[0][0] if filename_hits else ""

    candidates = filename_hits or [(k, c) for k, _p, c in _RECOGNISERS]
    best, best_score = "", 0
    for kind, columns in candidates:
        score = sum(1 for c in columns if c in header)
        if score > best_score:
            best, best_score = kind, score
    if best_score:
        return best
    return filename_hits[0][0] if filename_hits else ""


def discover(root):
    """Walk an MES output tree. Returns (by_kind, unrecognised, files_seen).

    `by_kind` maps kind -> [paths]; MES splits large collections across files
    per user or per day, so several paths per kind is the normal case.
    """
    by_kind = {}
    unrecognised = []
    seen = 0

    if os.path.isfile(root):
        paths = [str(root)]
    else:
        paths = []
        for dirpath, _dirs, names in os.walk(root):
            for n in sorted(names):
                if n.lower().endswith(_EXTENSIONS):
                    paths.append(os.path.join(dirpath, n))

    for p in paths:
        seen += 1
        kind = identify(p)
        if kind:
            by_kind.setdefault(kind, []).append(p)
        else:
            unrecognised.append(p)
    return by_kind, unrecognised, seen


def collect(root, overrides=None):
    """Load every consumable source under `root`, applying explicit overrides.

    An override replaces whatever discovery found for that kind, so an analyst
    who points --entra-audit at a specific file gets that file even when the
    tree holds three others that also look like directory audits.
    """
    from postmortem import persistence as P
    from postmortem import directory as D

    by_kind, unrecognised, seen = ({}, [], 0)
    if root:
        by_kind, unrecognised, seen = discover(root)

    for kind, path in (overrides or {}).items():
        if path:
            by_kind[kind] = [str(path)]

    parsers = {
        "entra_audit": P.parse_entra_audit,
        "oauth_permissions": P.parse_oauth_permissions,
        "mfa": P.parse_mfa,
        "devices": P.parse_devices,
        "role_activity": P.parse_role_activity,
        "risk_detections": P.parse_risk_detections,
        "users": D.parse_users,
        "accepted_domains": D.parse_accepted_domains,
        "mailbox_rules": D.parse_mailbox_rules,
        "transport_rules": D.parse_transport_rules,
        "mailbox_permissions": D.parse_mailbox_permissions,
        "mailbox_audit_status": D.parse_mailbox_audit_status,
    }

    sources = {}
    manifest = []
    for kind, paths in sorted(by_kind.items()):
        rows_total = 0
        parsed_total = 0
        for p in paths:
            rows = P.load_rows(p)
            rows_total += len(rows)
            if kind in parsers:
                parsed = parsers[kind](rows)
                parsed_total += len(parsed)
                # Audit status is keyed by mailbox, not a list: several
                # files merge into one map rather than concatenating.
                if isinstance(parsed, dict):
                    sources.setdefault(kind, {}).update(parsed)
                else:
                    sources.setdefault(kind, []).extend(parsed)
        manifest.append({
            "kind": kind, "files": len(paths), "rows": rows_total,
            "findings": parsed_total if kind in parsers else None,
            "consumed": kind in CONSUMED,
            "routed_to": ROUTED.get(kind, ""),
            "paths": [os.path.basename(p) for p in paths[:6]],
        })

    return {
        "sources": sources,
        "manifest": manifest,
        "files_seen": seen,
        "unrecognised": [os.path.basename(p) for p in unrecognised[:20]],
        "unrecognised_count": len(unrecognised),
        "signin_paths": by_kind.get("signin_logs", []),
        "unified_audit_paths": by_kind.get("unified_audit", []),
    }
