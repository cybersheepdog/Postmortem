"""Tenant facts: who actually works there, and what the mailbox is configured to do.

Almost everything else this tool knows about the client's own organisation is
inferred from the corpus. Internal domains are guessed from which domains
appear on both sides of enough messages; known contacts are whoever sent mail
often enough to look established. Those inferences are load-bearing -- they
decide what counts as external, what counts as a stranger, and whose display
name it is that an attacker copied -- and they are wrong in two predictable
ways:

  A legitimate colleague who rarely emails this mailbox never becomes
  "frequent", so mail from them scores as an unfamiliar external sender.

  A display-name impersonation can only be described as "resembles a known
  contact", because the corpus has no record of how that person's name is
  actually spelled or what address really belongs to them.

A directory export replaces both guesses with fact. It also carries the
mailbox's current configuration, which answers a question the audit log
cannot: a rule or a delegation that EXISTS but was never recorded being
created predates the log window, and is the persistence most likely to be
missed -- the audit log can only report what happened while it was watching.

Nothing here scores. It supplies ground truth to the parts that do, and
reports configuration drift as evidence in its own right.
"""

from __future__ import annotations

import re
from collections import Counter

from postmortem.persistence import _get

SCHEMA = "postmortem-directory/1"

# Folder names a concealment rule typically files mail into. Shared with the
# audit-log side, restated here because a rule read from a live export has no
# audit event to inherit the judgement from.
# Folders with essentially no legitimate rule target. A rule filing mail into
# one of these is worth reporting on its own.
_STRONG_HIDDEN = ("rss feeds", "rss subscriptions", "conversation history",
                  "notes", "sync issues")
# Folders people genuinely file mail into. An attacker uses them too, but a
# live config export carries no attribution, so on their own these are
# ordinary mail management -- reporting every "Archive old" rule as suspected
# persistence is how an action list stops being read.
_WEAK_HIDDEN = ("archive", "junk", "deleted items", "trash", "clutter")

_NAME_NOISE = re.compile(r"[^a-z0-9]+")


def _norm_name(value):
    """Collapse a display name for comparison: case, spacing and punctuation.

    "Jane Q. Doe", "jane doe" and "Doe, Jane" must all match the directory's
    "Jane Doe", because an attacker choosing a display name is copying what a
    human reads, not what the directory stores.
    """
    s = _NAME_NOISE.sub(" ", str(value or "").lower()).strip()
    if not s:
        return ""
    parts = [p for p in s.split() if len(p) > 1 or p.isdigit()]
    return " ".join(sorted(parts))


def _norm_addr(value):
    return str(value or "").strip().lower()


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def parse_users(rows):
    """Directory accounts. UPN, the name a recipient actually sees, and role."""
    out = []
    for row in rows:
        upn = _norm_addr(_get(row, "userprincipalname", "upn", "mail",
                              "emailaddress", "primarysmtpaddress"))
        display = _get(row, "displayname", "name", "fullname")
        if not upn and not display:
            continue
        out.append({
            "upn": upn,
            "display_name": str(display or ""),
            "given_name": str(_get(row, "givenname", "firstname", default="")),
            "surname": str(_get(row, "surname", "lastname", default="")),
            "title": str(_get(row, "jobtitle", "title", default="")),
            "department": str(_get(row, "department", default="")),
            "manager": _norm_addr(_get(row, "manager", "managerupn", default="")),
            "enabled": str(_get(row, "accountenabled", "enabled", default="")),
            "user_type": str(_get(row, "usertype", "type", default="")),
            "created": str(_get(row, "createddatetime", "whencreated", default="")),
            # Aliases matter: an attacker who writes to a secondary address is
            # still writing to this person, and the corpus would not know.
            "proxy_addresses": [
                _norm_addr(a).replace("smtp:", "")
                for a in re.split(r"[;,]", str(_get(
                    row, "proxyaddresses", "emailaddresses", default="")))
                if "@" in a
            ],
        })
    return out


def parse_accepted_domains(rows):
    """The tenant's own domains, as the tenant declares them."""
    out = []
    for row in rows:
        d = _get(row, "domainname", "domain", "name", "id", "acceptedDomain")
        if d and "." in str(d):
            out.append(str(d).strip().lower().lstrip("@"))
    return sorted(set(out))


def parse_mailbox_rules(rows):
    """Inbox rules as they exist now, not as the audit log saw them created."""
    out = []
    for row in rows:
        name = _get(row, "rulename", "name", "identity", "ruleidentity")
        mailbox = _norm_addr(_get(row, "mailbox", "userprincipalname",
                                  "mailboxownerid", "primarysmtpaddress"))
        forwards = [a.strip().lower() for a in re.split(r"[;,]", str(_get(
            row, "forwardto", "redirectto", "forwardasattachmentto",
            default=""))) if "@" in a]
        move_to = str(_get(row, "movetofolder", "copytofolder", default=""))
        delete = str(_get(row, "deletemessage", "softdeletemessage",
                          default="")).strip().lower() in ("true", "1", "yes")
        keywords = [w.strip() for w in re.split(r"[;,]", str(_get(
            row, "subjectcontainswords", "bodycontainswords",
            "subjectorbodycontainswords", default=""))) if w.strip()]
        if not (name or mailbox):
            continue
        folder = move_to.strip().lower()
        # Forwarding out or destroying mail is concealment on its own. Filing
        # it away only counts when the folder has no ordinary use, or when the
        # rule also deletes or selects on concealment keywords -- otherwise
        # every "Archive old" rule in the tenant lands in the action list.
        hides = bool(
            delete or forwards
            or (folder and folder in _STRONG_HIDDEN)
            or (folder in _WEAK_HIDDEN and keywords)
        )
        out.append({
            "name": str(name or "(unnamed)"), "mailbox": mailbox,
            "enabled": str(_get(row, "enabled", "isenabled", default="")),
            "forwards": forwards, "move_to": move_to, "delete": delete,
            "keywords": keywords, "conceals": hides,
        })
    return out


def parse_transport_rules(rows):
    """Tenant-wide mail flow rules. A BEC actor with admin reach uses these."""
    out = []
    for row in rows:
        name = _get(row, "name", "identity", "rulename")
        if not name:
            continue
        redirect = [a.strip().lower() for a in re.split(r"[;,]", str(_get(
            row, "redirectmessageto", "blindcopyto", "copyto",
            default=""))) if "@" in a]
        out.append({
            "name": str(name),
            "state": str(_get(row, "state", "enabled", default="")),
            "redirects_to": redirect,
            "description": str(_get(row, "description", default=""))[:300],
            "conceals": bool(redirect),
        })
    return out


def parse_mailbox_permissions(rows):
    """Delegated mailbox access: who else can read or send as this mailbox."""
    out = []
    for row in rows:
        mailbox = _norm_addr(_get(row, "identity", "mailbox",
                                  "primarysmtpaddress", "userprincipalname"))
        trustee = _norm_addr(_get(row, "user", "trustee", "granteename",
                                  "accessrightsholder"))
        rights = str(_get(row, "accessrights", "rights", "permission",
                          default=""))
        if not (mailbox and trustee):
            continue
        if trustee.startswith("nt authority") or trustee.endswith("\\self"):
            continue
        out.append({
            "mailbox": mailbox, "trustee": trustee, "rights": rights,
            "inherited": str(_get(row, "isinherited", "inherited", default="")),
        })
    return out


def parse_mailbox_audit_status(rows):
    """Whether mailbox auditing was on, per mailbox.

    This is what turns E4's honest-but-unsatisfying UNKNOWN into an answer.
    """
    out = {}
    for row in rows:
        mailbox = _norm_addr(_get(row, "identity", "mailbox",
                                  "userprincipalname", "primarysmtpaddress"))
        if not mailbox:
            continue
        enabled = str(_get(row, "auditenabled", "auditlogenabled",
                           "defaultauditset", default="")).strip().lower()
        owner = str(_get(row, "auditowner", default=""))
        delegate = str(_get(row, "auditdelegate", default=""))
        admin = str(_get(row, "auditadmin", default=""))
        combined = " ".join((owner, delegate, admin)).lower()
        out[mailbox] = {
            "audit_enabled": enabled in ("true", "1", "yes"),
            "audit_enabled_raw": enabled,
            "records_mail_access": "mailitemsaccessed" in combined,
            "owner_actions": owner, "delegate_actions": delegate,
            "admin_actions": admin,
            "retention_days": str(_get(row, "auditlogagelimit",
                                       "retention", default="")),
        }
    return out


# --------------------------------------------------------------------------
# The directory itself
# --------------------------------------------------------------------------

class Directory:
    """Lookup over a tenant's real people and domains.

    Built once and consulted by the scorer. Every method answers with a fact
    from the export or with nothing -- it never guesses, because the whole
    point is to replace guessing.
    """

    def __init__(self, users=None, accepted_domains=None):
        self.users = list(users or [])
        self.accepted_domains = set(accepted_domains or ())
        self.by_upn = {}
        self.by_address = {}
        self.by_name = {}
        for u in self.users:
            if u["upn"]:
                self.by_upn[u["upn"]] = u
                self.by_address[u["upn"]] = u
            for alias in u.get("proxy_addresses", []):
                self.by_address.setdefault(alias, u)
            key = _norm_name(u["display_name"])
            if key:
                self.by_name.setdefault(key, []).append(u)
        # A domain the tenant declares, plus any domain its own accounts sign
        # in under: an export that omits accepted domains still tells us.
        for addr in self.by_address:
            if "@" in addr:
                self.accepted_domains.add(addr.rsplit("@", 1)[1])

    def __bool__(self):
        return bool(self.users or self.accepted_domains)

    def is_internal_domain(self, domain):
        return _norm_addr(domain) in self.accepted_domains

    def person_for_address(self, address):
        return self.by_address.get(_norm_addr(address))

    def people_named(self, display_name):
        """Directory accounts whose name a sender's display name matches."""
        return list(self.by_name.get(_norm_name(display_name), []))

    def impersonation_of(self, display_name, sender_email):
        """The person this display name belongs to, when the sender is not them.

        Returns a dict naming the real account, or None. This is the fact the
        corpus could never supply: "resembles a known contact" becomes "this
        is Jane Doe's name, Jane Doe is jane.doe@acme.com, and this message
        did not come from her."
        """
        matches = self.people_named(display_name)
        if not matches:
            return None
        addr = _norm_addr(sender_email)
        if any(addr == m["upn"] or addr in (m.get("proxy_addresses") or [])
               for m in matches):
            return None  # it really is them
        real = matches[0]
        return {
            "display_name": real["display_name"],
            "real_address": real["upn"],
            "title": real.get("title", ""),
            "department": real.get("department", ""),
            "observed_address": addr,
            "other_matches": [m["upn"] for m in matches[1:3]],
        }

    def stats(self):
        return {
            "users": len(self.users),
            "accepted_domains": sorted(self.accepted_domains),
            "addresses_indexed": len(self.by_address),
            "distinct_names": len(self.by_name),
            "enabled": sum(1 for u in self.users
                           if str(u.get("enabled", "")).lower() in ("true", "1", "yes")),
        }


def build_directory(sources):
    """Directory from parsed sources, or an empty one."""
    return Directory(users=sources.get("users") or [],
                     accepted_domains=sources.get("accepted_domains") or [])


# --------------------------------------------------------------------------
# Configuration drift
# --------------------------------------------------------------------------

def _rule_recorded(rule, audit_rules):
    """Did the audit log record this rule being created or changed?

    Matched on what the rule DOES rather than on its name, because the name is
    the one part an attacker picks freely and often changes.
    """
    targets = {str(a).lower() for a in rule.get("forwards", [])}
    keywords = {str(k).lower() for k in rule.get("keywords", [])}
    for entry in audit_rules:
        if targets and targets & {str(a).lower()
                                  for a in (entry.get("forwards") or [])}:
            return True
        if keywords and keywords & {str(k).lower()
                                    for k in (entry.get("keywords") or [])}:
            return True
        if (rule.get("move_to") and entry.get("move_to")
                and str(rule["move_to"]).lower() == str(entry["move_to"]).lower()):
            return True
    return False


def config_drift(sources, audit_summary=None, directory=None):
    """Configuration that exists but was never recorded being created.

    The audit log can only report what happened while it was watching. A rule
    forwarding mail to an external address, a delegation granting another
    account full access, a transport rule copying every message elsewhere --
    any of these can predate the window, and then the audit log's silence
    about them reads exactly like their absence.

    Everything reported here is stated as unexplained rather than malicious.
    Most tenants have some legitimate configuration nobody remembers setting
    up, and calling it an attack would be the same error in the other
    direction.
    """
    audit = audit_summary or {}
    recorded = list(audit.get("malicious_rules") or []) + \
        list(audit.get("forwarding_rules") or [])
    internal = directory.accepted_domains if directory else set()

    unexplained_rules = []
    for rule in (sources.get("mailbox_rules") or []):
        if not rule.get("conceals"):
            continue
        if _rule_recorded(rule, recorded):
            continue
        external = [a for a in rule.get("forwards", [])
                    if "@" in a and a.rsplit("@", 1)[1] not in internal]
        unexplained_rules.append({**rule, "external_forwards": external})

    unexplained_transport = [
        t for t in (sources.get("transport_rules") or []) if t.get("conceals")]

    delegations = []
    for perm in (sources.get("mailbox_permissions") or []):
        rights = perm["rights"].lower()
        if not any(k in rights for k in ("fullaccess", "sendas",
                                         "sendonbehalf", "readpermission")):
            continue
        trustee_domain = (perm["trustee"].rsplit("@", 1)[1]
                          if "@" in perm["trustee"] else "")
        delegations.append({
            **perm,
            "external": bool(trustee_domain and trustee_domain not in internal),
        })

    external_forwarders = [r for r in unexplained_rules if r["external_forwards"]]
    external_delegates = [d for d in delegations if d["external"]]

    return {
        "available": bool(sources.get("mailbox_rules")
                          or sources.get("mailbox_permissions")
                          or sources.get("transport_rules")),
        "unexplained_rules": unexplained_rules,
        "unexplained_transport_rules": unexplained_transport,
        "delegations": delegations,
        "external_forwarders": len(external_forwarders),
        "external_delegates": len(external_delegates),
        "rules_seen": len(sources.get("mailbox_rules") or []),
        "permissions_seen": len(sources.get("mailbox_permissions") or []),
        "transport_rules_seen": len(sources.get("transport_rules") or []),
        "note": ("Listed because the audit log does not record them being "
                 "created, which usually means they predate its window. That "
                 "is not proof of anything: confirm each with the "
                 "administrator before treating it as attacker activity."),
    }


def drift_remediation(drift):
    """Config drift as remediation actions, in the shape remediation_plan uses."""
    from postmortem.persistence import _REMEDIATION

    out = []
    for rule in (drift or {}).get("unexplained_rules", []):
        fix, nofix = _REMEDIATION["inbox_rule"]
        target = rule["name"]
        if rule.get("mailbox"):
            target += " on " + rule["mailbox"]
        grants = ("Forwards to " + ", ".join(rule["external_forwards"])
                  if rule.get("external_forwards")
                  else "Hides or deletes matching mail before the owner sees it.")
        out.append({
            "kind": "inbox_rule", "target": target, "when": "",
            "by_attacker": False,
            "attribution": "present now, not recorded in the audit log window",
            "grants": grants, "action": fix, "not_fixed_by": nofix,
            "detail": ("keywords: " + ", ".join(rule["keywords"])
                       if rule.get("keywords") else ""),
            "survives_password_reset": "survives",
            "survives_token_revocation": "survives",
        })
    for t in (drift or {}).get("unexplained_transport_rules", []):
        out.append({
            "kind": "transport_rule", "target": t["name"], "when": "",
            "by_attacker": False,
            "attribution": "tenant-wide rule, not recorded in the audit window",
            "grants": "Copies or redirects mail to " + ", ".join(t["redirects_to"]),
            "action": ("Review and remove: Remove-TransportRule -Identity "
                       "'%s'" % t["name"]),
            "not_fixed_by": ("A transport rule is tenant-wide and is untouched "
                             "by anything done to the user's account."),
            "detail": "", "survives_password_reset": "survives",
            "survives_token_revocation": "survives",
        })
    for d in (drift or {}).get("delegations", []):
        if not d["external"]:
            continue
        out.append({
            "kind": "delegation", "target": "%s -> %s" % (d["trustee"], d["mailbox"]),
            "when": "", "by_attacker": False,
            "attribution": "delegated access held by an address outside the tenant",
            "grants": "Holds %s on the mailbox." % d["rights"],
            "action": ("Remove the permission: Remove-MailboxPermission "
                       "-Identity %s -User %s -AccessRights FullAccess"
                       % (d["mailbox"], d["trustee"])),
            "not_fixed_by": ("Delegated access is a property of the mailbox, "
                             "not of the user's credentials."),
            "detail": "", "survives_password_reset": "survives",
            "survives_token_revocation": "survives",
        })
    return out


# --------------------------------------------------------------------------
# Mailbox audit status: answering E4's UNKNOWN
# --------------------------------------------------------------------------

def audit_coverage_for(audit_status, victim_address=None):
    """Whether mailbox auditing could have recorded a read, and for whom.

    Without this the tool has to say "MailItemsAccessed is absent, so the
    exposure scope is UNKNOWN", which is honest but leaves the client's
    central question -- what did they see -- permanently open. The status
    export distinguishes the two cases hiding inside that UNKNOWN: auditing
    was off, so nothing could have been recorded; or auditing was on, and the
    silence means something.
    """
    if not audit_status:
        return {}
    target = _norm_addr(victim_address)
    entry = audit_status.get(target) if target else None
    if entry is None and len(audit_status) == 1:
        entry = next(iter(audit_status.values()))
    if entry is None:
        enabled = sum(1 for v in audit_status.values() if v["audit_enabled"])
        return {
            "known": True, "mailbox_matched": False,
            "mailboxes": len(audit_status), "enabled": enabled,
            "note": ("Audit status was collected for %d mailbox(es) but none "
                     "matches the mailbox this corpus came from, so it cannot "
                     "speak to this export." % len(audit_status)),
        }
    return {
        "known": True, "mailbox_matched": True,
        "audit_enabled": entry["audit_enabled"],
        "records_mail_access": entry["records_mail_access"],
        "retention_days": entry.get("retention_days", ""),
        "note": (
            "Mailbox auditing was ENABLED and MailItemsAccessed is in the "
            "audited action set, so the absence of read events is "
            "meaningful rather than a licensing gap."
            if entry["audit_enabled"] and entry["records_mail_access"] else
            "Mailbox auditing was ENABLED but MailItemsAccessed is not in the "
            "audited action set, so reads were never going to be recorded."
            if entry["audit_enabled"] else
            "Mailbox auditing was DISABLED for this mailbox. No read activity "
            "could have been recorded, whatever the licensing. The exposure "
            "scope cannot be established from the audit log at all."),
    }


def summarize(sources, directory, drift, audit_status):
    """One dict for the report and the manifest."""
    return {
        "available": bool(sources),
        "schema": SCHEMA,
        "sources": {k: (len(v) if isinstance(v, (list, dict)) else 0)
                    for k, v in (sources or {}).items()},
        "directory": directory.stats() if directory else {},
        "drift": drift or {},
        "audit_status_mailboxes": len(audit_status or {}),
        "titles": Counter(
            u["title"] for u in (directory.users if directory else [])
            if u.get("title")).most_common(10),
    }
