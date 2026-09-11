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

Output
------
Two things, because they answer different questions. The terminal says whether
there is anything here: counts, the worst few groups, and where the report is.
It stays about the same length whatever the finding count. The report is where
you investigate -- a self-contained HTML file written beside the logs, with a
sortable and filterable table of correlation groups, the legs of each, a
sign-in timeline per affected account, a copy-ready indicator list and an
export-coverage panel saying what window the answer covers.

The report contains client data. It is a local file, it loads no CDN, webfont
or script of any kind, and nothing in it is uploaded anywhere.

Usage
-----
    python find_device_code_flow.py <folder-with-json-files>
    python find_device_code_flow.py <folder> --all        # print every group
    python find_device_code_flow.py <folder> --verbose    # per-leg app/CA detail
    python find_device_code_flow.py <folder> --report out.html --csv out.csv
    python find_device_code_flow.py <folder> --all-signins-for user@corp.com
    python find_device_code_flow.py <folder> --no-report --no-color

Note it is a script, not a module: run it WITHOUT ``-m``.

Reads only. Nothing leaves the machine. No third-party packages.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import datetime
import html
from collections import Counter, OrderedDict

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



# ------------------------------------------------------------------------
# HTML report
# ------------------------------------------------------------------------

TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{
  --bg:#f6f7f9; --panel:#fff; --line:#dfe3e8; --ink:#14181d; --muted:#667085;
  --red:#c0261f; --redbg:#fdf0ef; --amber:#a35b00; --amberbg:#fdf6ec;
  --green:#1a7f4b; --greenbg:#eff8f3; --accent:#2d5bd7;
}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
  --bg:#12151a; --panel:#191d24; --line:#2c333d; --ink:#e6e9ee; --muted:#95a0b0;
  --red:#ff6b5e; --redbg:#2a1715; --amber:#e0a24a; --amberbg:#261d10;
  --green:#54c98c; --greenbg:#122219; --accent:#7aa0ff;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1400px;margin:0 auto;padding:20px 16px 64px}
h1{font-size:19px;margin:0 0 2px}
h2{font-size:14px;text-transform:uppercase;letter-spacing:.07em;
  color:var(--muted);margin:26px 0 8px;font-weight:600}
.sub{color:var(--muted);font-size:12px;margin:0 0 18px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:9px;
  padding:14px 16px;margin-bottom:14px}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
/* banner */
.banner{border-radius:9px;padding:14px 16px;margin-bottom:16px;
  border:1px solid var(--line);background:var(--panel)}
.banner.hit{border-color:var(--red);background:var(--redbg)}
.banner.clear{border-color:var(--green);background:var(--greenbg)}
.banner .big{font-size:17px;font-weight:650}
.banner.hit .big{color:var(--red)}
.banner.clear .big{color:var(--green)}
.counts{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}
.pill{border:1px solid var(--line);border-radius:999px;padding:3px 11px;
  font-size:12px;background:var(--panel);white-space:nowrap}
.pill.r{color:var(--red);border-color:var(--red)}
.pill.a{color:var(--amber);border-color:var(--amber)}
.pill.g{color:var(--green);border-color:var(--green)}
/* coverage grid */
.grid{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(190px,1fr))}
.stat{border:1px solid var(--line);border-radius:8px;padding:9px 11px;background:var(--panel)}
.stat .k{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.stat .v{font-size:15px;font-weight:600;margin-top:2px;word-break:break-word}
.warn{color:var(--red);font-weight:600}
/* controls */
.controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
input[type=search],select{background:var(--panel);color:var(--ink);
  border:1px solid var(--line);border-radius:7px;padding:7px 10px;font:inherit;font-size:13px}
input[type=search]{min-width:230px;flex:1}
.chip{border:1px solid var(--line);background:var(--panel);color:var(--muted);
  border-radius:999px;padding:5px 12px;font-size:12px;cursor:pointer;user-select:none}
.chip[aria-pressed=true]{color:var(--ink);border-color:var(--accent);
  box-shadow:inset 0 0 0 1px var(--accent)}
.chip.r[aria-pressed=true]{border-color:var(--red);box-shadow:inset 0 0 0 1px var(--red);color:var(--red)}
.chip.a[aria-pressed=true]{border-color:var(--amber);box-shadow:inset 0 0 0 1px var(--amber);color:var(--amber)}
.chip.g[aria-pressed=true]{border-color:var(--green);box-shadow:inset 0 0 0 1px var(--green);color:var(--green)}
button{font:inherit}
.btn{border:1px solid var(--line);background:var(--panel);color:var(--ink);
  border-radius:7px;padding:6px 12px;font-size:12px;cursor:pointer}
.btn:hover{border-color:var(--accent)}
/* table */
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:9px;background:var(--panel)}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:8px 11px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
  white-space:nowrap;position:sticky;top:0;background:var(--panel);z-index:1}
th.s{cursor:pointer}
th.s:hover{color:var(--accent)}
tr.grp{cursor:pointer}
tr.grp:hover td{background:var(--bg)}
tr.grp.attack td:first-child{box-shadow:inset 3px 0 0 var(--red)}
tr.grp.single td:first-child{box-shadow:inset 3px 0 0 var(--amber)}
tr.grp.consistent td:first-child{box-shadow:inset 3px 0 0 var(--green)}
.v-attack{color:var(--red);font-weight:650}
.v-single{color:var(--amber);font-weight:600}
.v-consistent{color:var(--green)}
.diff{color:var(--red);font-weight:600}
.legs{background:var(--bg)}
.legs td{padding:0}
.legtable{width:100%;font-size:12px;border-collapse:collapse}
.legtable th{background:transparent;position:static;font-size:10px}
.legtable td,.legtable th{padding:6px 11px;border-bottom:1px solid var(--line)}
.legtable tr:last-child td{border-bottom:none}
.role{font-weight:600;white-space:nowrap}
.role.poll{color:var(--red)}
.role.browser{color:var(--muted)}
.tag{display:inline-block;border-radius:5px;padding:1px 7px;font-size:11px;
  border:1px solid var(--line);color:var(--muted);white-space:nowrap}
.tag.bad{color:var(--red);border-color:var(--red);background:var(--redbg)}
.tag.ok{color:var(--green);border-color:var(--green);background:var(--greenbg)}
.muted{color:var(--muted)}
.small{font-size:12px}
.nowrap{white-space:nowrap}
.empty{padding:22px;text-align:center;color:var(--muted)}
/* timeline */
.tl{border-left:2px solid var(--line);margin-left:8px;padding-left:14px}
.tl .ev{position:relative;padding:5px 0;font-size:12.5px;
  display:grid;grid-template-columns:132px 1fr;gap:10px}
.tl .ev::before{content:"";position:absolute;left:-19px;top:12px;width:7px;height:7px;
  border-radius:50%;background:var(--line)}
.tl .ev.dcf::before{background:var(--red);box-shadow:0 0 0 3px var(--redbg)}
.tl .ev.dcf{color:var(--red);font-weight:550}
.acct{margin-bottom:18px}
.acct h3{font-size:13px;margin:0 0 7px;font-family:ui-monospace,monospace}
/* ioc */
pre.ioc{margin:0;padding:11px 13px;background:var(--bg);border:1px solid var(--line);
  border-radius:8px;font-size:12px;overflow-x:auto;white-space:pre;max-height:320px}
details>summary{cursor:pointer;color:var(--accent);font-size:13px;padding:4px 0}
.remedy li{margin:5px 0}
.remedy{border-left:3px solid var(--red);padding-left:14px}
footer{color:var(--muted);font-size:11px;margin-top:34px;
  border-top:1px solid var(--line);padding-top:12px}
@media print{.controls,.btn{display:none}.tablewrap{overflow:visible}
  tr.legs{display:table-row !important}}
</style></head><body>
<div class="wrap">
<h1>Device code flow &mdash; Entra sign-in log review</h1>
<p class="sub" id="sub"></p>
<div id="banner"></div>

<h2>Export coverage</h2>
<div class="panel"><div class="grid" id="coverage"></div>
<p class="small muted" id="coverageNote" style="margin:11px 0 0"></p></div>

<h2>Correlation groups</h2>
<div class="controls">
  <input type="search" id="q" placeholder="filter by user, IP, country, agent, correlation id&hellip;">
  <button class="chip r" id="fAttack" aria-pressed="true">likely attack</button>
  <button class="chip a" id="fSingle" aria-pressed="true">single leg</button>
  <button class="chip g" id="fConsistent" aria-pressed="false">consistent</button>
  <button class="btn" id="expandAll">expand all</button>
  <button class="btn" id="collapseAll">collapse all</button>
</div>
<div class="tablewrap"><table id="groups"><thead><tr>
  <th class="s" data-k="verdict">Verdict</th>
  <th class="s" data-k="time">First seen</th>
  <th class="s" data-k="user">Account</th>
  <th class="s" data-k="legs">Legs</th>
  <th>Origins</th>
  <th>Differs on</th>
  <th class="s" data-k="outcome">Outcome</th>
  <th>Correlation id</th>
</tr></thead><tbody id="gbody"></tbody></table></div>
<p class="small muted" id="shown"></p>

<div id="iocSection"></div>
<div id="timelineSection"></div>
<div id="remedySection"></div>

<footer id="foot"></footer>
</div>
<script>
const DATA = __DATA__;
const esc = s => String(s == null ? "" : s).replace(/[&<>"]/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c]));

const VLABEL = {attack:"likely attack", single:"single leg", consistent:"consistent"};
const VCLASS = {attack:"v-attack", single:"v-single", consistent:"v-consistent"};
const VRANK  = {attack:0, single:1, consistent:2};

/* ---------- header + banner ---------- */
(function(){
  const c = DATA.counts;
  document.getElementById("sub").textContent =
    DATA.records + " sign-in records from " + DATA.files + " file(s) · "
    + DATA.hits + " device code record(s) in " + DATA.groups.length
    + " correlation group(s) · generated " + DATA.generated;

  const b = document.getElementById("banner");
  if (!DATA.fieldsPresent) {
    b.className = "banner hit";
    b.innerHTML = '<div class="big">This export cannot answer the question</div>'
      + '<p class="small">Neither <code>originalTransferMethod</code> nor '
      + '<code>authenticationProtocol</code> appears in any record, so a clean '
      + 'result here would mean the column is missing &mdash; not that the attack '
      + 'did not happen. Re-export including <code>originalTransferMethod</code>: '
      + 'the Graph API <code>/auditLogs/signIns</code> and the portal\'s '
      + '<b>Download JSON</b> both carry it; the portal\'s CSV download does not.</p>';
    return;
  }
  if (c.attack) {
    b.className = "banner hit";
    b.innerHTML = '<div class="big">' + c.attack + ' correlation group(s) show a '
      + 'device code flow whose two legs came from different places</div>'
      + '<p class="small">One leg is the account holder completing MFA in their '
      + 'browser; the other is whoever was polling for the token.</p>'
      + counts(c);
  } else if (DATA.hits) {
    b.className = "banner";
    b.innerHTML = '<div class="big">Device code flow in use, no split-origin group</div>'
      + '<p class="small">Every paired group came from one origin, which is what a '
      + 'genuine device enrolment looks like. Single-leg groups cannot be compared '
      + 'and are worth a look.</p>' + counts(c);
  } else {
    b.className = "banner clear";
    b.innerHTML = '<div class="big">No device code flow sign-ins in this export</div>'
      + '<p class="small">The field is present, so this is a real negative for the '
      + 'window and accounts covered below &mdash; confirm that window spans the '
      + 'suspected compromise date before concluding.</p>';
  }
  function counts(c){
    return '<div class="counts">'
      + '<span class="pill r">' + c.attack + ' likely attack</span>'
      + '<span class="pill a">' + c.single + ' single leg</span>'
      + '<span class="pill g">' + c.consistent + ' consistent</span></div>';
  }
})();

/* ---------- coverage ---------- */
(function(){
  const g = document.getElementById("coverage");
  DATA.coverage.forEach(s => {
    const d = document.createElement("div");
    d.className = "stat";
    d.innerHTML = '<div class="k">' + esc(s[0]) + '</div><div class="v'
      + (s[2] ? " warn" : "") + '">' + esc(s[1]) + '</div>';
    g.appendChild(d);
  });
  document.getElementById("coverageNote").innerHTML = DATA.coverageNote;
})();

/* ---------- groups table ---------- */
let sortKey = "verdict", sortDir = 1;
const filters = {attack:true, single:true, consistent:false};

function rowsFor(){
  const q = document.getElementById("q").value.toLowerCase().trim();
  return DATA.groups.filter(g => filters[g.verdict])
    .filter(g => !q || g.blob.includes(q))
    .sort((a,b) => {
      let x, y;
      if (sortKey === "verdict"){ x = VRANK[a.verdict]; y = VRANK[b.verdict]; }
      else if (sortKey === "legs"){ x = a.legs.length; y = b.legs.length; }
      else { x = a[sortKey] || ""; y = b[sortKey] || ""; }
      if (x < y) return -1*sortDir;
      if (x > y) return  1*sortDir;
      return String(a.time).localeCompare(String(b.time));
    });
}

function render(){
  const rows = rowsFor(), tb = document.getElementById("gbody");
  if (!rows.length){
    tb.innerHTML = '<tr><td colspan="8"><div class="empty">'
      + (DATA.hits ? "No group matches the current filter."
                   : "No device code flow sign-ins in this export.")
      + '</div></td></tr>';
  } else {
    tb.innerHTML = rows.map((g,i) => groupRow(g,i)).join("");
  }
  const hidden = DATA.groups.length - rows.length;
  document.getElementById("shown").textContent =
    rows.length + " of " + DATA.groups.length + " group(s) shown"
    + (hidden ? " · " + hidden + " hidden by the filters above" : "");
  tb.querySelectorAll("tr.grp").forEach(tr => {
    tr.addEventListener("click", () => {
      const legs = document.getElementById("legs-" + tr.dataset.i);
      if (legs) legs.hidden = !legs.hidden;
    });
  });
}

function groupRow(g, i){
  const d = new Set(g.differs);
  const origins = g.legs.map(l =>
      '<div class="nowrap' + (d.size && g.verdict === "attack" ? ' diff' : '') + '">'
      + esc(l.ip) + ' <span class="muted">' + esc(l.loc) + '</span></div>').join("");
  const differs = g.differs.length
    ? '<span class="diff">' + g.differs.map(esc).join(" · ") + '</span>'
    : '<span class="muted">&mdash;</span>';
  const outcome = g.tokensIssued
    ? '<span class="tag bad">tokens issued</span>'
    : (g.anySuccess ? '<span class="tag">succeeded</span>'
                    : '<span class="tag ok">all failed</span>');

  return '<tr class="grp ' + g.verdict + '" data-i="' + i + '">'
    + '<td class="' + VCLASS[g.verdict] + ' nowrap">' + VLABEL[g.verdict] + '</td>'
    + '<td class="nowrap mono small">' + esc(g.time) + '</td>'
    + '<td class="mono small">' + esc(g.user) + '</td>'
    + '<td class="small">' + g.legs.length + '</td>'
    + '<td class="mono small">' + origins + '</td>'
    + '<td class="small">' + differs + '</td>'
    + '<td class="small">' + outcome + '</td>'
    + '<td class="mono small muted">' + esc(g.cid) + '</td></tr>'
    + '<tr class="legs" id="legs-' + i + '" hidden><td colspan="8">'
    + legTable(g) + '</td></tr>';
}

function legTable(g){
  const d = new Set(g.differs);
  const cell = (v, field) =>
    (d.has(field) && g.verdict === "attack")
      ? '<span class="diff">' + esc(v) + '</span>' : esc(v);
  return '<table class="legtable"><thead><tr>'
    + '<th>Role</th><th>Time</th><th>IP</th><th>Location</th><th>ASN</th>'
    + '<th>User agent</th><th>App &rarr; resource</th><th>Auth</th><th>Result</th>'
    + '</tr></thead><tbody>'
    + g.legs.map(l =>
        '<tr><td class="role ' + (l.interactive ? "browser" : "poll") + '">'
        + (l.interactive ? "browser" : "polling") + '</td>'
        + '<td class="mono">' + esc(l.time) + '</td>'
        + '<td class="mono">' + cell(l.ip, "IP") + '</td>'
        + '<td>' + cell(l.loc, "country") + '</td>'
        + '<td class="mono">' + cell(l.asn, "ASN") + '</td>'
        + '<td class="mono">' + cell(l.agent, "user agent") + '</td>'
        + '<td>' + esc(l.app) + (l.resource ? ' &rarr; ' + esc(l.resource) : '') + '</td>'
        + '<td>' + esc(l.auth) + (l.ca ? ' / CA ' + esc(l.ca) : '') + '</td>'
        + '<td>' + (l.ok ? '<span class="tag">success</span>'
                         : '<span class="tag ok">' + esc(l.status) + '</span>') + '</td>'
        + '</tr>').join("")
    + '</tbody></table>';
}

document.getElementById("q").addEventListener("input", render);
[["fAttack","attack"],["fSingle","single"],["fConsistent","consistent"]]
  .forEach(([id,key]) => {
    const el = document.getElementById(id);
    el.addEventListener("click", () => {
      filters[key] = !filters[key];
      el.setAttribute("aria-pressed", String(filters[key]));
      render();
    });
  });
document.querySelectorAll("th.s").forEach(th => {
  th.addEventListener("click", () => {
    const k = th.dataset.k;
    sortDir = (k === sortKey) ? -sortDir : 1;
    sortKey = k;
    render();
  });
});
document.getElementById("expandAll").addEventListener("click", () =>
  document.querySelectorAll("tr.legs").forEach(t => t.hidden = false));
document.getElementById("collapseAll").addEventListener("click", () =>
  document.querySelectorAll("tr.legs").forEach(t => t.hidden = true));

/* ---------- IOCs ---------- */
(function(){
  if (!DATA.iocText) return;
  document.getElementById("iocSection").innerHTML =
    '<h2>Indicators from the polling legs</h2><div class="panel">'
    + '<p class="small muted" style="margin:0 0 9px">Taken from the '
    + 'non-interactive leg of every split-origin group &mdash; the side that '
    + 'collected the token. Paste into a block list, a hunt query or the case file.</p>'
    + '<pre class="ioc" id="iocPre">' + esc(DATA.iocText) + '</pre>'
    + '<p style="margin:9px 0 0"><button class="btn" id="copyIoc">copy</button> '
    + '<span class="small muted" id="copyMsg"></span></p></div>';
  const btn = document.getElementById("copyIoc");
  if (!btn) return;
  btn.addEventListener("click", () => {
    const text = document.getElementById("iocPre").textContent;
    const done = ok => document.getElementById("copyMsg").textContent =
      ok ? "copied" : "press Ctrl+C — the text is selected";
    // navigator.clipboard is unavailable on file:// in most browsers, so the
    // selection fallback is the path that actually runs here.
    try {
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => done(true), () => select());
      } else { select(); }
    } catch (e) { select(); }
    function select(){
      const r = document.createRange();
      r.selectNodeContents(document.getElementById("iocPre"));
      const s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
      let ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      done(ok);
    }
  });
})();

/* ---------- timelines ---------- */
(function(){
  if (!DATA.timelines.length) return;
  document.getElementById("timelineSection").innerHTML =
    '<h2>Sign-in timeline per affected account</h2><div class="panel">'
    + '<p class="small muted" style="margin:0 0 12px">Every sign-in in this export '
    + 'for an account with a device code record, so you can see what it did before '
    + 'and after, and from where. Device code events are marked.</p>'
    + DATA.timelines.map(t =>
        '<details class="acct"' + (t.open ? " open" : "") + '>'
        + '<summary><b class="mono">' + esc(t.user) + '</b> <span class="muted small">'
        + t.events.length + ' sign-in(s), ' + t.dcf + ' device code</span></summary>'
        + '<div class="tl">' + t.events.map(e =>
            '<div class="ev' + (e.dcf ? " dcf" : "") + '">'
            + '<span class="mono">' + esc(e.time) + '</span>'
            + '<span>' + esc(e.app) + ' <span class="muted">from</span> '
            + '<span class="mono">' + esc(e.ip) + '</span> '
            + '<span class="muted">' + esc(e.loc) + '</span>'
            + (e.ok ? '' : ' <span class="tag ok">' + esc(e.status) + '</span>')
            + (e.dcf ? ' <span class="tag bad">device code</span>' : '')
            + '</span></div>').join("")
        + '</div></details>').join("")
    + '</div>';
})();

/* ---------- remediation ---------- */
(function(){
  if (!DATA.counts.attack) return;
  document.getElementById("remedySection").innerHTML =
    '<h2>If any of these succeeded</h2><div class="panel remedy">'
    + '<p style="margin-top:0"><b>A password reset does not evict the holder of '
    + 'these tokens.</b> No password was ever learned in this flow and the tokens '
    + 'are already issued, so a reset changes a secret the attacker never had.</p>'
    + '<ol class="small remedy" style="border:none;padding-left:20px">'
    + '<li><b>Revoke refresh tokens</b> &mdash; <code>Revoke-MgUserSignInSession '
    + '-UserId &lt;upn&gt;</code>, or &ldquo;Revoke sessions&rdquo; on the user in Entra. '
    + 'Do this first; everything else is undone by a live token.</li>'
    + '<li><b>Reset the password</b> and re-register MFA methods.</li>'
    + '<li><b>Review the mailbox</b> for inbox rules and forwarding created after '
    + 'the timestamps above &mdash; that is usually the first thing done with the '
    + 'access.</li>'
    + '<li><b>Check enterprise app consents</b> granted by the account in the same '
    + 'window; a consented app survives a token revoke.</li>'
    + '<li><b>Consider blocking device code flow</b> in Conditional Access '
    + '(authentication flows) for users who have no need of it.</li></ol></div>';
})();

document.getElementById("foot").innerHTML =
  "find_device_code_flow.py · read-only · generated on this machine from "
  + esc(DATA.source) + " · " + esc(DATA.generated)
  + " · this file contains client data: it is local and was not uploaded anywhere.";
render();
</script></body></html>
"""



def build_report_data(records, groups, files, folder, generated, fields_present,
          coverage_rows, coverage_note, timelines, ioc_text, hits):
    return {
        "records": len(records),
        "files": len(files),
        "hits": hits,
        "generated": generated,
        "source": os.path.abspath(folder),
        "fieldsPresent": fields_present,
        "counts": {
            "attack": sum(1 for g in groups if g["verdict"] == "attack"),
            "single": sum(1 for g in groups if g["verdict"] == "single"),
            "consistent": sum(1 for g in groups if g["verdict"] == "consistent"),
        },
        "groups": groups,
        "coverage": coverage_rows,
        "coverageNote": coverage_note,
        "timelines": timelines,
        "iocText": ioc_text,
    }


def write_report(data, path, title="Device code flow review"):
    payload = json.dumps(data, ensure_ascii=False, default=str)
    # A literal </script> inside the embedded JSON would close the block early.
    payload = payload.replace("</", "<\\/")
    doc = (TEMPLATE
           .replace("__TITLE__", html.escape(title))
           .replace("__DATA__", payload))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return os.path.abspath(path)


# How many groups the terminal will print before deferring to the
# report. Six fits on one screen alongside the summary and the
# remediation note.
TERMINAL_GROUP_CAP = 6


def assess(legs):
    """Verdict and concrete mismatches for one correlation group."""
    ips = {str(get(f, "ip", "")) for _, f in legs if get(f, "ip", "")}
    countries = {country_of(f) for _, f in legs if country_of(f)}
    asns = {str(get(f, "asn", "")) for _, f in legs if get(f, "asn", "")}
    agents = {short_agent(f) for _, f in legs if get(f, "user_agent", "")}

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


def build_groups(hits):
    """One record per correlation group, shaped for both outputs."""
    buckets = OrderedDict()
    for src, f in sorted(hits, key=lambda x: str(get(x[1], "time", ""))):
        buckets.setdefault(
            str(get(f, "correlation", "(no correlation id)")), []).append((src, f))

    groups = []
    for cid, legs in buckets.items():
        verdict, differs = assess(legs)
        leg_rows = []
        for _src, f in sorted(legs, key=lambda x: str(get(x[1], "time", ""))):
            leg_rows.append({
                "interactive": truthy(get(f, "interactive", "")),
                "time": str(get(f, "time", ""))[:19].replace("T", " "),
                "ip": str(get(f, "ip", "?")),
                "loc": short_location(f),
                "asn": "AS" + str(get(f, "asn", "?")),
                "agent": short_agent(f, 60),
                "app": str(get(f, "app", "?")),
                "resource": str(get(f, "resource", "")),
                "auth": str(get(f, "auth_req", "?")),
                "ca": str(get(f, "ca_status", "")),
                "ok": succeeded(f),
                "status": status_of(f),
            })
        user = str(get(legs[0][1], "user", "(unknown)"))
        blob = " ".join([cid, user, " ".join(differs)]
                        + [" ".join(str(v) for v in l.values()) for l in leg_rows]
                        ).lower()
        groups.append({
            "cid": cid,
            "verdict": verdict,
            "differs": differs,
            "user": user,
            "time": leg_rows[0]["time"] if leg_rows else "",
            "legs": leg_rows,
            "anySuccess": any(l["ok"] for l in leg_rows),
            "tokensIssued": verdict == "attack" and any(l["ok"] for l in leg_rows),
            "blob": blob,
            "_raw": legs,
        })
    return groups


def build_coverage(records, files, have_transfer, have_protocol, hits):
    blind = have_transfer == 0 and have_protocol == 0
    times = sorted(str(get(f, "time", "")) for _, f in records if get(f, "time", ""))
    accounts = {str(get(f, "user", "")) for _, f in records if get(f, "user", "")}
    rows = [
        ["Records", "%d from %d file(s)" % (len(records), len(files)), False],
        ["First event", (times[0][:19].replace("T", " ") if times else "unknown"),
         not times],
        ["Last event", (times[-1][:19].replace("T", " ") if times else "unknown"),
         not times],
        ["Accounts in export", str(len(accounts)), False],
        # Either field alone answers the question, so neither is flagged on its
        # own -- only their joint absence is a problem, and that is what the
        # banner says. Marking authenticationProtocol red beside a fully
        # populated originalTransferMethod reads as a defect that is not there.
        ["originalTransferMethod",
         "%d of %d records" % (have_transfer, len(records)), blind],
        ["authenticationProtocol",
         "%d of %d records" % (have_protocol, len(records)), blind],
        ["Device code records", str(hits), False],
    ]
    if have_transfer == 0 and have_protocol == 0:
        note = ("<span class='warn'>Neither field is present. This export cannot "
                "answer the device code question at all &mdash; see above.</span>")
    else:
        note = ("A finding here speaks only for the window and the accounts this "
                "export covers. Confirm that window spans the suspected compromise "
                "date before reading a clean result as a negative.")
    return rows, note


def build_timelines(records, groups, limit=400):
    """Every sign-in for each account that has a device code record."""
    affected = OrderedDict()
    for g in groups:
        affected.setdefault(g["user"], 0)
        affected[g["user"]] += sum(1 for _ in g["legs"])

    out = []
    for user, dcf_count in affected.items():
        rows = [f for _s, f in records
                if str(get(f, "user", "")).lower() == user.lower()]
        rows.sort(key=lambda f: str(get(f, "time", "")))
        events = [{
            "time": str(get(f, "time", ""))[:19].replace("T", " "),
            "app": str(get(f, "app", "?")),
            "ip": str(get(f, "ip", "?")),
            "loc": short_location(f),
            "ok": succeeded(f),
            "status": status_of(f)[:28],
            "dcf": is_device_code(f)[0],
        } for f in rows[:limit]]
        out.append({
            "user": user,
            "events": events,
            "dcf": dcf_count,
            # Only the accounts that actually matter start expanded.
            "open": any(g["user"] == user and g["verdict"] == "attack"
                        for g in groups),
        })
    return out


def build_iocs(groups):
    """Indicators from the polling leg of every split-origin group."""
    ips, asns, agents, users = OrderedDict(), OrderedDict(), OrderedDict(), OrderedDict()
    for g in groups:
        if g["verdict"] != "attack":
            continue
        users[g["user"]] = True
        # The browser leg is the account holder. Only the other side is an IOC,
        # and publishing the victim's own address as one would be a real error.
        browser_ips = {l["ip"] for l in g["legs"] if l["interactive"]}
        for l in g["legs"]:
            if l["interactive"] or l["ip"] in browser_ips:
                continue
            ips[l["ip"]] = l["loc"]
            if l["asn"] not in ("AS?", "AS"):
                asns[l["asn"]] = True
            if l["agent"] and l["agent"] != "?":
                agents[l["agent"]] = True
    if not ips:
        return ""
    lines = ["# device code flow - polling-leg indicators",
             "# the account-holder's own IP is deliberately excluded", ""]
    lines.append("[ip]")
    lines += ["%-16s  # %s" % (ip, loc or "?") for ip, loc in ips.items()]
    if asns:
        lines += ["", "[asn]"] + list(asns)
    if agents:
        lines += ["", "[user-agent]"] + list(agents)
    lines += ["", "[affected-account]"] + list(users)
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Terminal output -- a verdict, not a report
#
# The report is the place to investigate; the terminal's job is to say whether
# there is anything to investigate and where to look. Anything longer gets
# scrolled past.
# --------------------------------------------------------------------------

def print_group(g, verbose):
    marker, colour = {
        "attack": ("[!!]", lambda: C.BRED),
        "single": ("[! ]", lambda: C.YEL),
        "consistent": ("[ok]", lambda: C.GRN),
    }[g["verdict"]]
    col = colour()
    print("%s%s %-42s%s %s%s%s"
          % (col, marker, g["user"][:42], C.OFF, C.DIM, g["time"][:16], C.OFF))

    diffs = set(g["differs"])
    for l in g["legs"]:
        lead = col if (not l["interactive"] and g["verdict"] == "attack") else C.DIM

        def mark(value, field, width):
            # Pad before colouring: escape sequences count toward a %-Ns width,
            # so colouring first knocks every later column out of line.
            cell = str(value)[:width].ljust(width)
            if field in diffs and g["verdict"] == "attack":
                return "%s%s%s" % (col, cell, C.OFF)
            return cell

        st = (("%ssuccess%s" % (C.RED, C.OFF)
               if not l["interactive"] and g["verdict"] == "attack"
               else "%ssuccess%s" % (C.DIM, C.OFF)) if l["ok"]
              else "%s%s%s" % (C.YEL, l["status"][:20], C.OFF))
        print("     %s%s%s %s %s %s %s %s"
              % (lead, "browser " if l["interactive"] else "polling ", C.OFF,
                 mark(l["ip"], "IP", 15), mark(l["loc"], "country", 18),
                 mark(l["asn"], "ASN", 9), mark(l["agent"], "user agent", 24), st))
        if verbose:
            print("       %sapp %s -> %s | auth %s | CA %s%s"
                  % (C.DIM, l["app"], l["resource"] or "-", l["auth"],
                     l["ca"] or "-", C.OFF))

    bits = []
    if g["differs"]:
        bits.append("%sdiffers: %s%s" % (col, " ".join(g["differs"]), C.OFF))
    if g["verdict"] == "single":
        bits.append("%sonly one leg in this export%s" % (C.DIM, C.OFF))
    if g["tokensIssued"]:
        bits.append("%sTOKENS ISSUED%s" % (C.BRED, C.OFF))
    print("     %scid %s%s%s" % (C.DIM, g["cid"][:22], C.OFF,
                                 ("  " + " | ".join(bits)) if bits else ""))
    print()


def main():
    ap = argparse.ArgumentParser(
        description="Find device code flow sign-ins in an Entra sign-in log export.")
    ap.add_argument("folder", help="folder containing the exported JSON files")
    ap.add_argument("--report", default="",
                    help="HTML report path (default: device_code_flow_report.html "
                         "beside the logs)")
    ap.add_argument("--csv", default="",
                    help="CSV path (default: device_code_flow_findings.csv "
                         "beside the logs)")
    ap.add_argument("--all", action="store_true",
                    help="print every group, not just the likely attacks")
    ap.add_argument("--verbose", action="store_true",
                    help="per-file counts and per-leg app/CA detail")
    ap.add_argument("--all-signins-for", default="",
                    help="print every sign-in for this UPN (also in the report)")
    ap.add_argument("--no-report", action="store_true", help="skip the HTML report")
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
    fields_present = bool(have_transfer or have_protocol)

    hits = [(src, f) for src, f in records if is_device_code(f)[0]]
    groups = build_groups(hits)
    counts = Counter(g["verdict"] for g in groups)

    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    coverage_rows, coverage_note = build_coverage(
        records, files, have_transfer, have_protocol, len(hits))
    timelines = build_timelines(records, groups)
    ioc_text = build_iocs(groups)

    report_path = ""
    if not args.no_report:
        target = args.report or os.path.join(
            args.folder, "device_code_flow_report.html")
        report_path = write_report(build_report_data(
            records, groups, files, args.folder, generated, fields_present,
            coverage_rows, coverage_note, timelines, ioc_text, len(hits)), target)

    csv_path = ""
    if hits:
        target = args.csv or os.path.join(
            args.folder, "device_code_flow_findings.csv")
        csv_path = write_csv(groups, target)

    # ---------------- terminal ----------------
    print("%s%d records from %d file(s)%s"
          % (C.DIM, len(records), len(files), C.OFF))

    if not fields_present:
        print()
        print("%s[!!] THIS EXPORT CANNOT ANSWER THE QUESTION%s" % (C.BRED, C.OFF))
        print("     Neither originalTransferMethod nor authenticationProtocol is")
        print("     present, so a clean result would mean the column is missing --")
        print("     not that the attack did not happen. Re-export including")
        print("     originalTransferMethod (Graph /auditLogs/signIns, or the")
        print("     portal's Download JSON; the CSV download omits it).")
        if report_path:
            print()
            print("%sReport: %s%s" % (C.DIM, report_path, C.OFF))
        return 1

    if not hits:
        print("%s[ok] No device code flow sign-ins in %d records.%s"
              % (C.GRN, len(records), C.OFF))
        print("     %sReal negative for the window and accounts this export "
              "covers.%s" % (C.DIM, C.OFF))
        if report_path:
            print("%sReport: %s%s" % (C.DIM, report_path, C.OFF))
        return 0

    print("%s%d device code record(s) in %d group(s):%s  %s%d likely attack%s  "
          "%s%d single leg%s  %s%d consistent%s"
          % (C.BOLD, len(hits), len(groups), C.OFF,
             C.BRED, counts.get("attack", 0), C.OFF,
             C.YEL, counts.get("single", 0), C.OFF,
             C.GRN, counts.get("consistent", 0), C.OFF))
    print()

    order = {"attack": 0, "single": 1, "consistent": 2}
    shown = [g for g in groups
             if args.all or g["verdict"] in ("attack", "single")]
    shown.sort(key=lambda g: (order[g["verdict"]], g["time"]))

    # The terminal answers "is there anything here". Past a handful of groups
    # it stops answering that and becomes something to scroll past, so it is
    # capped whatever the finding count -- the report is where a long list
    # belongs, because there it can be sorted and filtered.
    cap = len(shown) if args.all else TERMINAL_GROUP_CAP
    for g in shown[:cap]:
        print_group(g, args.verbose)

    over = len(shown) - cap
    if over > 0:
        print("%s... and %d more flagged group(s). The report lists them all, "
              "sortable and filterable; --all prints them here.%s"
              % (C.DIM, over, C.OFF))
        print()

    hidden = len(groups) - len(shown)
    if hidden:
        print("%s%d consistent group(s) not shown -- one origin each, which is "
              "what a real enrolment looks like. --all to list them.%s"
              % (C.DIM, hidden, C.OFF))
        print()

    if counts.get("attack"):
        print("%sA password reset does NOT evict them%s -- no password was learned "
              "and the" % (C.BRED, C.OFF))
        print("tokens are already issued. Revoke refresh tokens first")
        print("(Revoke-MgUserSignInSession), then reset, then check mailbox rules.")
        print()

    if report_path:
        print("%sReport:%s %s" % (C.BOLD, C.OFF, report_path))
        print("%s        sortable, filterable, with per-account timelines and "
              "the IOC list%s" % (C.DIM, C.OFF))
    if csv_path:
        print("%sCSV:%s    %s" % (C.BOLD, C.OFF, csv_path))

    if args.all_signins_for:
        target = args.all_signins_for.strip().lower()
        same = [(s, f) for s, f in records
                if str(get(f, "user", "")).lower() == target]
        print()
        print("%sALL SIGN-INS FOR %s (%d)%s"
              % (C.BOLD, args.all_signins_for, len(same), C.OFF))
        for _s, f in sorted(same, key=lambda x: str(get(x[1], "time", ""))):
            dcf = is_device_code(f)[0]
            line = "  %s  %-9s %-26s %-15s %s" % (
                str(get(f, "time", ""))[:16].replace("T", " "),
                status_of(f)[:9], str(get(f, "app", ""))[:26],
                str(get(f, "ip", ""))[:15], short_location(f)[:22])
            print("%s%s%s%s" % (C.RED if dcf else C.DIM, line,
                                "   <== DEVICE CODE" if dcf else "", C.OFF))

    return 0


def write_csv(groups, path):
    rows = []
    for g in groups:
        for l in g["legs"]:
            rows.append(OrderedDict([
                ("correlationId", g["cid"]),
                ("verdict", g["verdict"]),
                ("differsOn", "; ".join(g["differs"])),
                ("tokensIssued", g["tokensIssued"]),
                ("time", l["time"]),
                ("user", g["user"]),
                ("role", "browser" if l["interactive"] else "polling"),
                ("isInteractive", l["interactive"]),
                ("status", l["status"]),
                ("app", l["app"]),
                ("resource", l["resource"]),
                ("ip", l["ip"]),
                ("location", l["loc"]),
                ("asn", l["asn"]),
                ("userAgent", l["agent"]),
                ("authRequirement", l["auth"]),
                ("conditionalAccess", l["ca"]),
            ]))
    if not rows:
        return ""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return os.path.abspath(path)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # Piping to `more` or a pager that exits early is a normal way to read
        # this; a traceback on top of the output is not helpful.
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
