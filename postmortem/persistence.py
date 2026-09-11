"""Persistence mechanisms: what keeps the attacker in after remediation.

Every other part of this tool is retrospective. The mail already arrived, the
deletions already happened, and analysing them next month gives the same
answer. This module is the exception: what it finds may still be live, and a
report that omits it can state something false -- "contained and remediated"
while an application the attacker consented to still reads the mailbox.

The organising idea is what each mechanism SURVIVES, because that is what
decides whether the client's remediation actually worked:

                        password reset      token revocation
  OAuth consent grant       survives            survives      <- the worst case
  Service principal cred    survives            survives
  Registered MFA method     conditional         survives
  Role assignment           survives            survives
  Registered device         no                  partially
  Inbox rule / forwarding   survives            survives

Only the first two hold access with no user credential at all: the
application authenticates as itself. Revoking every session in the tenant and
resetting every password leaves them untouched, which is exactly why they are
the mechanism of choice and why they have to be named individually, with the
command that removes them, rather than summarised.

Attribution reuses what the sign-in and audit log ingestion already
established -- the attacker addresses and the compromise anchor -- so a
consent grant from a known attacker address inside the compromise window is
confirmed rather than suspected. Nothing here invents a new inference: an
event is either tied to the attacker by a recorded address and time, or it is
reported as unattributed and left for the analyst.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter
from datetime import datetime, timezone

SCHEMA = "postmortem-persistence/1"

# --------------------------------------------------------------------------
# Graph permission scopes that matter in a BEC
# --------------------------------------------------------------------------
# Mailbox reach. An application holding any of these can read, send or alter
# mail without the user being present and without satisfying MFA.
_MAIL_SCOPES = {
    "mail.read", "mail.readbasic", "mail.readwrite", "mail.send",
    "mail.read.shared", "mail.readwrite.shared", "mail.send.shared",
    "mailboxsettings.read", "mailboxsettings.readwrite",
    "imap.accessasuser.all", "pop.accessasuser.all", "smtp.send",
    "ews.accessasuser.all", "full_access_as_app",
}
# Reach beyond the mailbox, and the scope that makes any of it durable.
_HIGH_RISK_SCOPES = {
    "files.read.all", "files.readwrite.all", "sites.read.all",
    "sites.readwrite.all", "sites.fullcontrol.all",
    "directory.read.all", "directory.readwrite.all", "directory.accessasuser.all",
    "user.read.all", "user.readwrite.all", "group.readwrite.all",
    "application.readwrite.all", "approleassignment.readwrite.all",
    "roleassignmentschedule.readwrite.directory",
    "privilegedaccess.readwrite.azuread",
    "chat.read", "chat.readwrite", "chatmessage.read",
}
# Not dangerous alone, but it is what turns a one-time consent into standing
# access: without it the application must re-obtain consent interactively.
_DURABILITY_SCOPES = {"offline_access"}


# --------------------------------------------------------------------------
# Directory-audit activities worth reporting
# --------------------------------------------------------------------------
# (kind, survives_password_reset, survives_token_revocation, what it grants)
#
# Matched as a lowercase substring of activityDisplayName: Microsoft has
# renamed several of these over the years ("Consent to application" vs "Add
# delegated permission grant") and both spellings still appear in exports.
_ACTIVITIES = [
    ("consent to application", "oauth_consent", "survives", "survives",
     "An application holds standing delegated access to the mailbox."),
    ("add delegated permission grant", "oauth_consent", "survives", "survives",
     "An application holds standing delegated access to the mailbox."),
    ("add app role assignment grant to user", "oauth_consent", "survives",
     "survives", "An application holds an assigned application permission."),
    ("add app role assignment to service principal", "oauth_consent",
     "survives", "survives",
     "An application holds an application-level permission, which needs no "
     "signed-in user at all."),
    ("add service principal credentials", "sp_credential", "survives",
     "survives",
     "A secret or certificate was added to an application, letting the holder "
     "authenticate as that application indefinitely."),
    ("add service principal", "service_principal", "survives", "survives",
     "An application identity was created in the tenant."),
    ("update application - certificates and secrets management",
     "sp_credential", "survives", "survives",
     "A credential was added to an application registration."),
    ("certificates and secrets management", "sp_credential", "survives",
     "survives", "A credential was added to an application registration."),
    ("user registered security info", "mfa_method", "conditional", "survives",
     "An authentication method was registered. If it is the attacker's, they "
     "can satisfy MFA, and self-service password reset may let them recover "
     "the account after a password change."),
    ("admin registered security info", "mfa_method", "conditional", "survives",
     "An authentication method was registered on the account by an admin."),
    ("user changed default security info", "mfa_method", "conditional",
     "survives", "The default authentication method was changed."),
    ("user deleted security info", "mfa_removed", "no", "no",
     "An authentication method was removed -- often the legitimate owner's, "
     "to stop them being prompted."),
    ("add member to role", "role_assignment", "survives", "survives",
     "A directory role was granted, which may include the ability to read "
     "other mailboxes or to reset credentials."),
    ("add eligible member to role", "role_assignment", "survives", "survives",
     "A directory role was made eligible for activation."),
    ("add member to group", "group_membership", "survives", "survives",
     "Group membership was changed, which may carry access or policy "
     "exclusions with it."),
    ("add device", "device", "no", "partial",
     "A device was registered, which can hold a Primary Refresh Token."),
    ("add registered owner to device", "device", "no", "partial",
     "An owner was added to a registered device."),
    ("update conditional access policy", "ca_policy", "survives", "survives",
     "A Conditional Access policy was modified -- possibly the control that "
     "would otherwise have blocked this access."),
    ("delete conditional access policy", "ca_policy", "survives", "survives",
     "A Conditional Access policy was deleted."),
    ("add conditional access policy", "ca_policy", "survives", "survives",
     "A Conditional Access policy was created."),
    ("disable strong authentication", "mfa_weakened", "survives", "survives",
     "Strong authentication was disabled for the account."),
    ("set company information", "tenant_config", "survives", "survives",
     "Tenant-level configuration was changed."),
]

# The remediation each kind requires, and what does NOT fix it. The negative
# half matters more than the positive half: the common failure is a client who
# resets passwords, revokes sessions, declares the incident closed, and leaves
# a consent grant in place.
_REMEDIATION = {
    "oauth_consent": (
        "Revoke the grant and disable the application: "
        "Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <id>, then "
        "Update-MgServicePrincipal -ServicePrincipalId <id> "
        "-AccountEnabled:$false",
        "A password reset and a session revocation do NOT remove this. The "
        "application authenticates as itself and will obtain fresh tokens."),
    "sp_credential": (
        "Remove the added secret/certificate from the application "
        "registration, then rotate any remaining credentials.",
        "Revoking user sessions does NOT affect an application credential."),
    "service_principal": (
        "Review the application, and disable it if it was not authorised: "
        "Update-MgServicePrincipal -ServicePrincipalId <id> "
        "-AccountEnabled:$false",
        "Not addressed by any user-level remediation."),
    "mfa_method": (
        "Remove the authentication method from the user in Entra ID > "
        "Authentication methods, then confirm self-service password reset "
        "cannot be used to re-register it.",
        "A password reset alone does NOT remove a registered method, and if "
        "SSPR is enabled the method can be used to set a new password."),
    "mfa_removed": (
        "Confirm with the account owner whether they removed this method. If "
        "not, re-register their own method and investigate.",
        ""),
    "role_assignment": (
        "Remove the role assignment: "
        "Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId <id> "
        "-DirectoryObjectId <id>",
        "A role assignment persists through password resets and session "
        "revocation."),
    "group_membership": (
        "Remove the group membership and check what access or policy "
        "exclusion the group carries.",
        ""),
    "device": (
        "Disable or delete the device object: Update-MgDevice -DeviceId <id> "
        "-AccountEnabled:$false",
        "Revoking sessions invalidates the current Primary Refresh Token but "
        "leaves the device registered."),
    "ca_policy": (
        "Review the policy against its last known-good state and restore it.",
        "Not addressed by any user-level remediation."),
    "mfa_weakened": (
        "Re-enable strong authentication for the account.",
        ""),
    "tenant_config": (
        "Review the change against the tenant's known-good configuration.",
        ""),
    "inbox_rule": (
        "Remove the rule: Remove-InboxRule -Mailbox <upn> -Identity <rule>",
        "A rule survives a password reset and a session revocation."),
    "forwarding": (
        "Clear the forwarding address: Set-Mailbox <upn> "
        "-ForwardingSmtpAddress $null -ForwardingAddress $null, and check the "
        "tenant's remote-domain and transport rules for the same address.",
        "Forwarding survives a password reset and a session revocation."),
}

_SEVERITY_ORDER = {"survives": 0, "partial": 1, "conditional": 1, "no": 2}


# --------------------------------------------------------------------------
# Loading: MES writes CSV for most extractors and JSON for the Graph ones
# --------------------------------------------------------------------------

def _parse_dt(value):
    """Parse a timestamp into an aware UTC datetime, or None.

    Must agree with auditlog._parse_iso and signin.parse_time: all three feed
    one chronology, and a naive datetime among aware ones raises on compare.
    """
    if not value:
        return None
    s = str(value).strip()
    if not s or s.lower() in ("null", "none", "n/a"):
        return None
    s = s.replace("Z", "+00:00")
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        dt = None
        for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%Y-%m-%d %H:%M:%S",
                    "%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
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


def _flatten(obj, out=None, depth=0):
    """Lowercase-key map, a few levels deep, with lists of dicts kept whole."""
    if out is None:
        out = {}
    if not isinstance(obj, dict) or depth > 4:
        return out
    for k, v in obj.items():
        lk = str(k).lower()
        if isinstance(v, dict):
            out.setdefault(lk, v)
            _flatten(v, out, depth + 1)
        else:
            out.setdefault(lk, v)
    return out


def load_rows(path):
    """Read one MES output file. Returns a list of flattened dicts.

    MES writes CSV for the Exchange/PowerShell extractors and JSON for the
    Graph ones, and which is which has changed between releases, so the
    container is detected rather than assumed.
    """
    try:
        with io.open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            raw = fh.read()
    except OSError:
        return []
    raw = raw.strip()
    if not raw:
        return []

    if raw[0] in "[{":
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            doc = None
        if isinstance(doc, list):
            return [_flatten(r) for r in doc if isinstance(r, dict)]
        if isinstance(doc, dict):
            for key in ("value", "records", "Records", "data", "results"):
                if isinstance(doc.get(key), list):
                    return [_flatten(r) for r in doc[key] if isinstance(r, dict)]
            return [_flatten(doc)]

    # JSON lines
    if raw[0] == "{" or raw.lstrip().startswith("{"):
        rows = []
        for line in raw.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(r, dict):
                rows.append(_flatten(r))
        if rows:
            return rows

    # CSV. MES uses comma by default; a semicolon export is common in EU
    # locales and sniffing costs nothing.
    sample = raw[:4096]
    delim = ","
    try:
        delim = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except csv.Error:
        pass
    try:
        reader = csv.DictReader(io.StringIO(raw), delimiter=delim)
        return [{(k or "").strip().lower(): v for k, v in r.items()}
                for r in reader]
    except csv.Error:
        return []


def _get(row, *names, default=""):
    """First non-empty value among several possible column spellings."""
    for n in names:
        v = row.get(n.lower())
        if v not in (None, "", "null"):
            return v
    return default


def _scopes(value):
    """Split a permission string into individual lowercase scopes."""
    if not value:
        return []
    text = str(value)
    parts = re.split(r"[\s,;]+", text)
    return [p.strip().strip('"\'').lower() for p in parts if p.strip()]


def scopes_were_readable(value):
    """True when the permission text contains something scope-shaped.

    Needed to tell 'this application asked for nothing dangerous' from
    'this export did not record what it asked for'. The first is noise
    and should be dropped; the second must be kept and reviewed, because
    silently discarding an unparsed consent is exactly the failure this
    module exists to prevent.
    """
    return any(re.match(r"^[a-z][a-z0-9]*\.[a-z]", s) or s in _DURABILITY_SCOPES
               for s in _scopes(value))


def classify_scopes(value):
    """(mail, high_risk, durable) scopes found in a permission string."""
    found = set(_scopes(value))
    return (sorted(found & _MAIL_SCOPES),
            sorted(found & _HIGH_RISK_SCOPES),
            sorted(found & _DURABILITY_SCOPES))


# --------------------------------------------------------------------------
# Per-source parsing
# --------------------------------------------------------------------------

def _match_activity(name):
    """(kind, survives_pw, survives_token, grants) for a directory activity."""
    low = str(name or "").strip().lower()
    for needle, kind, pw, tok, grants in _ACTIVITIES:
        if needle in low:
            return kind, pw, tok, grants
    return None


def _initiator(row):
    """(actor, ip) from a directory-audit record, whatever shape it arrived in."""
    actor = _get(row, "userprincipalname", "initiatedby_user_userprincipalname",
                 "initiatedby", "actor", "user", "displayname_initiatedby")
    ip = _get(row, "ipaddress", "initiatedby_user_ipaddress", "clientip",
              "ip")
    init = row.get("initiatedby")
    if isinstance(init, dict):
        user = init.get("user") or init.get("app") or {}
        if isinstance(user, dict):
            actor = actor or (user.get("userPrincipalName")
                              or user.get("displayName") or "")
            ip = ip or (user.get("ipAddress") or "")
    if isinstance(actor, str) and actor.startswith("{"):
        # Some CSV exports stringify the whole object into the column.
        m = re.search(r"userPrincipalName=([^;,}\s]+)", actor)
        actor = m.group(1) if m else actor[:80]
    return str(actor or ""), str(ip or "")


def _targets(row):
    """Readable target names and any permission text carried with them."""
    names, permissions = [], []
    tr = row.get("targetresources")
    if isinstance(tr, str) and tr.strip():
        names.append(tr.strip()[:200])
        permissions.append(tr)
    elif isinstance(tr, list):
        for t in tr:
            if not isinstance(t, dict):
                continue
            label = t.get("displayName") or t.get("id") or ""
            if label:
                names.append(str(label))
            for mp in (t.get("modifiedProperties") or []):
                if not isinstance(mp, dict):
                    continue
                # Values only. The property's own displayName is things like
                # "ConsentAction.Permissions", which is scope-SHAPED without
                # being a scope -- reading it as one made an unreadable
                # consent look fully parsed, and a consent that looks parsed
                # and empty gets dropped as benign. That is the exact failure
                # this module must not have.
                permissions.append(" ".join(
                    str(mp.get(k, "")) for k in ("newValue", "oldValue")))
    flat = _get(row, "targetdisplayname", "target", "objectid",
                "modifiedproperties")
    if flat and not names:
        names.append(str(flat)[:200])
    if flat:
        permissions.append(str(flat))
    return names, " ".join(permissions)


def parse_entra_audit(rows):
    """Directory audit events that represent a persistence mechanism."""
    out = []
    for row in rows:
        activity = _get(row, "activitydisplayname", "activity",
                        "operationname", "operation")
        hit = _match_activity(activity)
        if not hit:
            continue
        kind, pw, tok, grants = hit
        result = str(_get(row, "result", "resultstatus", "status",
                          default="success")).lower()
        if result in ("failure", "failed"):
            continue
        actor, ip = _initiator(row)
        names, permission_text = _targets(row)
        mail, high, durable = classify_scopes(permission_text)
        when = _parse_dt(_get(row, "activitydatetime", "createddatetime",
                              "timegenerated", "date", "time"))
        out.append({
            "kind": kind, "activity": str(activity),
            "time": when.strftime("%Y-%m-%dT%H:%M:%SZ") if when else "",
            "_dt": when, "actor": actor, "ip": ip,
            "targets": names[:4],
            "mail_scopes": mail, "high_risk_scopes": high,
            "durable_scopes": durable,
            "scopes_readable": scopes_were_readable(permission_text),
            "survives_password_reset": pw, "survives_token_revocation": tok,
            "grants": grants, "source": "entra_audit",
        })
    return out


def parse_oauth_permissions(rows):
    """Current OAuth grants, as they stand now rather than as they were made.

    The audit log says a consent happened; this says a consent still exists.
    A grant with no corresponding audit event predates the log window and is
    the more dangerous of the two, because nothing else would surface it.
    """
    out = []
    for row in rows:
        app = _get(row, "applicationname", "clientdisplayname", "appdisplayname",
                   "displayname", "application", "clientid")
        perms = _get(row, "permission", "permissions", "scope", "scopes",
                     "consentedpermissions", "approle", "value")
        if not app and not perms:
            continue
        mail, high, durable = classify_scopes(perms)
        if not (mail or high):
            continue  # an app with only benign scopes is not a finding
        out.append({
            "kind": "oauth_consent", "activity": "Existing OAuth grant",
            "time": "", "_dt": _parse_dt(_get(row, "createddatetime",
                                              "consentdate", "grantdate")),
            "actor": _get(row, "principaldisplayname", "userprincipalname",
                          "principal", default=""),
            "ip": "",
            "targets": [str(app)],
            "app_id": str(_get(row, "clientid", "appid", "applicationid",
                               "serviceprincipalid", default="")),
            "grant_id": str(_get(row, "id", "grantid",
                                 "oauth2permissiongrantid", default="")),
            "permission_type": str(_get(row, "permissiontype", "type",
                                        default="")),
            "consent_type": str(_get(row, "consenttype", default="")),
            "mail_scopes": mail, "high_risk_scopes": high,
            "durable_scopes": durable,
            "survives_password_reset": "survives",
            "survives_token_revocation": "survives",
            "grants": "An application holds standing access to this tenant.",
            "source": "oauth_permissions",
        })
    return out


def parse_mfa(rows):
    """Registered authentication methods per account."""
    out = []
    for row in rows:
        user = _get(row, "userprincipalname", "user", "upn", "displayname")
        methods = _get(row, "mfamethods", "authenticationmethods", "methods",
                       "mfatype", "defaultmfamethod", "strongauthentication")
        if not user:
            continue
        out.append({
            "kind": "mfa_state", "user": str(user),
            "methods": str(methods),
            "mfa_enabled": str(_get(row, "mfaenabled", "mfastatus",
                                    "isMfaRegistered", default="")),
            "source": "mfa",
        })
    return out


def parse_devices(rows):
    """Registered device objects."""
    out = []
    for row in rows:
        name = _get(row, "displayname", "devicename", "name")
        if not name:
            continue
        reg = _parse_dt(_get(row, "registrationdatetime", "createddatetime",
                             "approximatelastsignindatetime"))
        out.append({
            "kind": "device", "activity": "Registered device",
            "name": str(name),
            "device_id": str(_get(row, "deviceid", "id", default="")),
            "os": str(_get(row, "operatingsystem", "os", default="")),
            "trust_type": str(_get(row, "trusttype", "jointype", default="")),
            "owner": str(_get(row, "userprincipalname", "registeredowners",
                              "owner", default="")),
            "enabled": str(_get(row, "accountenabled", "enabled", default="")),
            "compliant": str(_get(row, "iscompliant", "compliant", default="")),
            "time": reg.strftime("%Y-%m-%dT%H:%M:%SZ") if reg else "",
            "_dt": reg,
            "survives_password_reset": "no",
            "survives_token_revocation": "partial",
            "grants": "A registered device can hold a Primary Refresh Token.",
            "source": "devices",
        })
    return out


def parse_role_activity(rows):
    """Directory role assignments and PIM activity."""
    out = []
    for row in rows:
        role = _get(row, "rolename", "roledisplayname", "role",
                    "directoryrole")
        user = _get(row, "userprincipalname", "principaldisplayname", "user",
                    "member", "displayname")
        if not role:
            continue
        when = _parse_dt(_get(row, "assignmentdatetime", "createddatetime",
                              "starttime", "activitydatetime"))
        out.append({
            "kind": "role_assignment", "activity": "Directory role assignment",
            "role": str(role), "user": str(user),
            "assignment_type": str(_get(row, "assignmenttype", "state",
                                        "membertype", default="")),
            "time": when.strftime("%Y-%m-%dT%H:%M:%SZ") if when else "",
            "_dt": when,
            "survives_password_reset": "survives",
            "survives_token_revocation": "survives",
            "grants": "A directory role, which may permit reading other "
                      "mailboxes or resetting credentials.",
            "source": "role_activity",
        })
    return out


def parse_risk_detections(rows):
    """Identity Protection detections -- corroboration from another engine."""
    out = []
    for row in rows:
        kind = _get(row, "riskeventtype", "risktype", "detectiontype",
                    "riskdetail")
        user = _get(row, "userprincipalname", "user", "userdisplayname")
        if not kind and not user:
            continue
        when = _parse_dt(_get(row, "detecteddatetime", "activitydatetime",
                              "createddatetime", "lastupdateddatetime"))
        out.append({
            "detection": str(kind), "user": str(user),
            "level": str(_get(row, "risklevel", "riskleveldduringsignin",
                              "riskleveldaggregated", "risklevelaggregated",
                              default="")),
            "state": str(_get(row, "riskstate", "state", default="")),
            "ip": str(_get(row, "ipaddress", "ip", default="")),
            "location": str(_get(row, "location", "city", "countryorregion",
                                 default="")),
            "time": when.strftime("%Y-%m-%dT%H:%M:%SZ") if when else "",
            "_dt": when,
            "source": "risk_detections",
        })
    return out


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def _attribute(entry, attacker_ips, window_start, window_end, victim_users):
    """Tie an event to the attacker, or say plainly that it is not tied.

    Two independent grounds, and nothing weaker: the recorded address is one
    the sign-in or audit log already established as the attacker's, or the
    event falls inside the compromise window and touches a compromised
    account. A guess here would put a remediation instruction in front of a
    client for something their own administrator did.
    """
    ip = str(entry.get("ip") or "")
    if ip and ip in attacker_ips:
        return True, "recorded from attacker address %s" % ip

    dt = entry.get("_dt")
    if dt and window_start and dt >= window_start:
        if window_end is None or dt <= window_end:
            actor = str(entry.get("actor") or entry.get("user") or "").lower()
            if actor and any(u and u in actor for u in victim_users):
                return True, "inside the compromise window, by the compromised account"
            return False, "inside the compromise window, actor not confirmed"
    return False, ""


def _severity(entry):
    pw = entry.get("survives_password_reset", "no")
    tok = entry.get("survives_token_revocation", "no")
    if pw == "survives" and tok == "survives":
        return "high"
    if "survives" in (pw, tok) or "conditional" in (pw, tok):
        return "medium"
    return "low"


def analyze_persistence(sources, attacker_ips=(), compromise_dt=None,
                        window_end=None, victim_users=()):
    """Build the persistence findings and the remediation list.

    `sources` is {name: [rows]} as produced by the parsers above. Everything
    is optional: a run with one file works, and a run with none returns an
    unavailable result rather than an empty-looking clean one.
    """
    sources = sources or {}
    attacker_ips = {str(i) for i in (attacker_ips or ()) if i}
    victim_users = {str(u).lower() for u in (victim_users or ()) if u}

    findings = []
    for entry in (sources.get("entra_audit") or []):
        findings.append(entry)
    for entry in (sources.get("oauth_permissions") or []):
        findings.append(entry)
    for entry in (sources.get("role_activity") or []):
        findings.append(entry)
    for entry in (sources.get("devices") or []):
        # A device is only interesting if it was registered in the window or
        # by an attacker address; the tenant's ordinary laptops are not a
        # finding and would bury the ones that are.
        if entry.get("_dt") and compromise_dt and entry["_dt"] >= compromise_dt:
            findings.append(entry)
        elif str(entry.get("ip") or "") in attacker_ips and entry.get("ip"):
            findings.append(entry)

    for entry in findings:
        attributed, why = _attribute(entry, attacker_ips, compromise_dt,
                                     window_end, victim_users)
        entry["by_attacker"] = attributed
        entry["attribution"] = why
        entry["severity"] = _severity(entry)
        fix, ineffective = _REMEDIATION.get(entry["kind"], ("", ""))
        entry["remediation"] = fix
        entry["not_fixed_by"] = ineffective

    # An existing grant for an application the attacker was recorded
    # consenting to is the same act seen from two angles: the audit log
    # says it happened, the grant export says it is STILL THERE. The
    # second is the one that decides whether remediation is finished, so
    # it inherits the attribution rather than sitting in review.
    _attacker_apps = {
        t.strip().lower()
        for e in findings if e.get("by_attacker") and e["kind"] == "oauth_consent"
        for t in e.get("targets", []) if t
    }
    for e in findings:
        if e.get("source") != "oauth_permissions" or e.get("by_attacker"):
            continue
        if any(str(t).strip().lower() in _attacker_apps
               for t in e.get("targets", [])):
            e["by_attacker"] = True
            e["attribution"] = ("still present, and the consent was recorded from an attacker address")

    # A consent for an application with no mailbox or high-risk scope,
    # from an address that is not the attacker's, is ordinary tenant
    # administration. Dropping it keeps the list short enough to act on.
    # Only ever dropped when the scopes were actually readable: an
    # unparsed consent stays, because not knowing is not the same as
    # knowing it is harmless.
    findings = [
        e for e in findings
        if not (e["kind"] == "oauth_consent"
                and not e.get("by_attacker")
                and not e.get("mail_scopes")
                and not e.get("high_risk_scopes")
                and e.get("scopes_readable"))
    ]

    # Attacker-attributed first, then by what survives, then by time.
    findings.sort(key=lambda e: (
        not e.get("by_attacker"),
        _SEVERITY_ORDER.get(e.get("survives_password_reset", "no"), 3),
        _SEVERITY_ORDER.get(e.get("survives_token_revocation", "no"), 3),
        e.get("time") or "",
    ))

    counts = Counter(e["kind"] for e in findings)
    confirmed = [e for e in findings if e.get("by_attacker")]
    survives_both = [e for e in findings
                     if e.get("survives_password_reset") == "survives"
                     and e.get("survives_token_revocation") == "survives"]

    warnings = []
    if not sources:
        warnings.append(
            "No persistence data was supplied. Whether the attacker retains "
            "access CANNOT be assessed from mail and audit data alone: an "
            "OAuth consent grant leaves no trace in either.")
    else:
        if not sources.get("oauth_permissions"):
            warnings.append(
                "No current OAuth grant export (Get-OAuthPermissionsGraph). "
                "The directory audit log only shows consents granted inside "
                "its window; one granted earlier is invisible without it.")
        if not sources.get("entra_audit"):
            warnings.append(
                "No directory audit log (Get-GraphEntraAuditLogs). MFA "
                "registration, role changes and device joins cannot be seen.")
        if not attacker_ips:
            warnings.append(
                "No attacker address was established, so nothing below is "
                "attributed. Findings are listed on their own merits and need "
                "an analyst to confirm each against known administrative "
                "activity.")

    return {
        "available": bool(sources),
        "schema": SCHEMA,
        "sources": {k: len(v or []) for k, v in sources.items()},
        "findings": findings,
        "counts": dict(counts),
        "confirmed_count": len(confirmed),
        "survives_both_count": len(survives_both),
        "mfa_state": sources.get("mfa") or [],
        "risk_detections": sorted(
            (sources.get("risk_detections") or []),
            key=lambda d: d.get("time") or ""),
        "warnings": warnings,
    }


def remediation_plan(persistence, audit_summary=None, drift=None):
    """One ordered action list, from every source that found persistence.

    Malicious rules and SMTP forwarding come from the audit log rather than
    from here, but they belong in the same list: a client working through
    remediation needs one page, not a page per data source. Ordered by what
    survives the remediation they are most likely to have already done.
    """
    actions = []

    for entry in (persistence or {}).get("findings", []):
        if not entry.get("remediation"):
            continue
        target = ", ".join(entry.get("targets", [])) or entry.get("role") \
            or entry.get("name") or entry.get("user") or ""
        detail = []
        if entry.get("mail_scopes"):
            detail.append("mailbox scopes: " + ", ".join(entry["mail_scopes"]))
        if entry.get("high_risk_scopes"):
            detail.append("other scopes: " + ", ".join(entry["high_risk_scopes"]))
        if entry.get("durable_scopes"):
            detail.append("offline_access (standing, not session-bound)")
        if entry.get("app_id"):
            detail.append("app id " + entry["app_id"])
        if entry.get("grant_id"):
            detail.append("grant id " + entry["grant_id"])
        fix = entry["remediation"]
        # A command with <id> in it is a command the analyst has to go
        # and look up. Where the export gave us the identifier, put it in.
        if entry.get("grant_id"):
            fix = fix.replace("-OAuth2PermissionGrantId <id>",
                              "-OAuth2PermissionGrantId %s" % entry["grant_id"])
        if entry.get("app_id"):
            fix = fix.replace("-ServicePrincipalId <id>",
                              "-ServicePrincipalId %s" % entry["app_id"])
        if entry.get("device_id"):
            fix = fix.replace("-DeviceId <id>",
                              "-DeviceId %s" % entry["device_id"])
        actions.append({
            "kind": entry["kind"],
            "target": target,
            "when": entry.get("time", ""),
            "by_attacker": entry.get("by_attacker", False),
            "attribution": entry.get("attribution", ""),
            "grants": entry.get("grants", ""),
            "action": fix,
            "not_fixed_by": entry.get("not_fixed_by", ""),
            "detail": "; ".join(detail),
            "survives_password_reset": entry.get("survives_password_reset", "no"),
            "survives_token_revocation": entry.get("survives_token_revocation", "no"),
        })

    audit = audit_summary or {}
    for rule in (audit.get("malicious_rules") or []):
        fix, nofix = _REMEDIATION["inbox_rule"]
        actions.append({
            "kind": "inbox_rule",
            "target": "%s on %s" % (
                ", ".join(rule.get("keywords") or []) or "rule",
                rule.get("user", "")),
            "when": rule.get("time", ""), "by_attacker": True,
            "attribution": "created from %s" % (rule.get("client_ip") or "?"),
            "grants": "Incoming mail is hidden or destroyed before the owner "
                      "sees it.",
            "action": fix, "not_fixed_by": nofix, "detail": "",
            "survives_password_reset": "survives",
            "survives_token_revocation": "survives",
        })
    for fwd in (audit.get("forwarding_rules") or []):
        fix, nofix = _REMEDIATION["forwarding"]
        actions.append({
            "kind": "forwarding",
            "target": ", ".join(fwd.get("forwards") or []) or fwd.get("user", ""),
            "when": fwd.get("time", ""), "by_attacker": True,
            "attribution": "set from %s" % (fwd.get("client_ip") or "?"),
            "grants": "A copy of every message reaches an external address.",
            "action": fix, "not_fixed_by": nofix, "detail": "",
            "survives_password_reset": "survives",
            "survives_token_revocation": "survives",
        })

    # Configuration that exists now but was never recorded being created.
    # It carries by_attacker=False deliberately: it predates the window
    # rather than being attributed, and most tenants have some of it.
    if drift:
        from postmortem.directory import drift_remediation
        actions.extend(drift_remediation(drift))

    # One action per mechanism. The findings list deliberately shows a consent
    # twice -- the audit log says it was granted, the grant export says it is
    # still there, and both are worth reading. As ACTIONS they are one thing:
    # a client told to revoke the same application twice loses confidence in
    # the whole list, and the duplicate lacking the real identifiers is the
    # one they would try first.
    merged = {}
    for a in actions:
        key = (a["kind"], str(a["target"]).strip().lower())
        prior = merged.get(key)
        if prior is None:
            merged[key] = a
            continue
        # Keep whichever carries the resolved command, then take the strongest
        # attribution and the earliest time across both.
        best, other = ((a, prior) if ("<id>" in prior["action"]
                                      and "<id>" not in a["action"])
                       else (prior, a))
        best["by_attacker"] = prior["by_attacker"] or a["by_attacker"]
        for field in ("when", "attribution", "detail"):
            if not best.get(field) and other.get(field):
                best[field] = other[field]
        if (best.get("when") and other.get("when")
                and other["when"] < best["when"]):
            best["when"] = other["when"]
            best["attribution"] = (other.get("attribution")
                                   or best.get("attribution"))
        merged[key] = best
    actions = list(merged.values())

    actions.sort(key=lambda a: (
        not a["by_attacker"],
        _SEVERITY_ORDER.get(a["survives_password_reset"], 3),
        _SEVERITY_ORDER.get(a["survives_token_revocation"], 3),
        a["when"] or "",
    ))
    for i, a in enumerate(actions, 1):
        a["priority"] = i
    return actions


def persistence_timeline_events(persistence):
    """(time, kind, summary, actor, ip, evidence) for the shared chronology."""
    out = []
    for e in (persistence or {}).get("findings", []):
        if not e.get("time"):
            continue
        target = ", ".join(e.get("targets", [])) or e.get("role") \
            or e.get("name") or ""
        summary = e.get("activity", e["kind"])
        if target:
            summary = "%s: %s" % (summary, target)
        evidence = [e.get("grants", "")]
        if e.get("mail_scopes"):
            evidence.append("Mailbox scopes: " + ", ".join(e["mail_scopes"]))
        if e.get("attribution"):
            evidence.append(e["attribution"].capitalize())
        out.append({
            "time": e["time"], "kind": e["kind"], "summary": summary,
            "actor": str(e.get("actor") or e.get("user") or ""),
            "ip": str(e.get("ip") or ""),
            "evidence": [x for x in evidence if x],
            "by_attacker": e.get("by_attacker", False),
        })
    return out


def strip_private(persistence):
    """A JSON-safe copy: the parsed datetimes are working values only."""
    if not persistence:
        return persistence
    def clean(seq):
        return [{k: v for k, v in e.items() if not k.startswith("_")}
                for e in seq]
    out = dict(persistence)
    out["findings"] = clean(persistence.get("findings", []))
    out["risk_detections"] = clean(persistence.get("risk_detections", []))
    return out
