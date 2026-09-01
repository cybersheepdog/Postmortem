# postmortem

**A forensic analyzer for Business Email Compromise (BEC) and phishing incidents.**

Point it at an exported mailbox and it works out **which email started the compromise** — the credential-phishing message in an account-takeover, or the fraudulent request in a vendor/impersonation scam — and reconstructs what the attacker did next. It is built for the real problem an incident responder faces: a single mailbox with tens of thousands of messages and only a vague idea of where the badness begins.

Everything runs **offline**. It never executes an attachment, opens a URL, or sends a byte off the machine.

---

## Highlights

- **Finds the initial malicious email**, not just "suspicious mail." It scores every message on how likely it is to be *the entry point* under the detected scenario, and ranks suspects into review tiers.
- **Scenario-aware.** Distinguishes account-takeover (ATO) from external impersonation/vendor-email-compromise and hunts accordingly.
- **Robust to bad SPF/DKIM/DMARC.** Small orgs often fail authentication legitimately, so auth failure is scored as a **deviation from each sender's own norm**, not as an absolute red flag.
- **Catches concealment.** Messages the attacker deleted or hid (Deleted Items, RSS Feeds, Junk) are surfaced, and mailbox-rule keywords resurface the mail the rule was hiding.
- **Ingests real evidence formats:** a directory of `.eml`, **PST/OST/MBOX** containers, and the **Microsoft 365 Unified Audit Log**.
- **Chain of custody built in.** Every finding carries its provenance (which field, what matched, how much it scored), and every run emits a reproducibility manifest.
- **Built for scale.** Resumable SQLite cache, parallel parsing, two-pass screening, and top-N report trimming keep a 30,000-message mailbox practical.

---

## Installation

The core needs **only Python 3.10+** — no third-party packages.

```bash
python -m postmortem --help
```

Optional extras (see [`requirements.txt`](requirements.txt)) — each degrades gracefully when absent:

- **Parsing robustness** — `beautifulsoup4` (sturdier HTML body/link/form parsing) and `tldextract` (Public Suffix List–aware registrable domains).
- **PST/OST ingestion** — `pip install libpff-python`. Without it, `.pst`/`.ost` inputs are skipped with instructions to convert via `readpst`. MBOX and `.eml` need nothing.
- **Attachment/image analysis** — `yara-python` (`--yara-rules`), `pyzbar`+`Pillow` (`--scan-qr`), `py7zr`/`rarfile` (7z/rar peek).
- **Geolocation** — `maxminddb` + local GeoLite2 `.mmdb` files (`--geoip-db`).
- **Tests/lint** — `pip install pytest pyflakes`.

The console output is **color-coded** by severity/tier when writing to a terminal (disable with `--no-color`, or the `NO_COLOR` env var), and prints **timed progress** for the slower phases (clustering, indexing, HTML generation, and any online/opt-in enrichment).

---

## Quick start

```bash
# A folder of .eml files
python -m postmortem ./mailbox_export

# A Gmail/Unix MBOX or an Outlook PST, with an HTML + JSON report
python -m postmortem ./case.mbox -o report.html --json report.json

# The high-value run: mailbox + M365 audit log together
python -m postmortem ./mailbox.pst --audit-log ./UnifiedAuditLog.csv -o report.html
```

That last command runs the whole stack: container extraction → folder-aware concealment detection → scenario/anchor scoring → audit-log-confirmed attack narrative → per-finding provenance.

---

## Inputs

### Mailbox

The positional argument accepts any of:

| Input | Notes |
|---|---|
| A **directory of `.eml`** | Scanned recursively. |
| A **`.mbox`** file | Gmail Takeout / Unix mbox. Standard library — always works. `X-Gmail-Labels` `Trash`/`Spam` map to `Deleted Items`/`Junk Email`; `X-Folder` is honored. |
| A **`.pst` / `.ost`** file | Outlook containers. Needs `libpff-python`. |
| A **directory containing** any of the above | Loose `.eml` and containers are all analyzed. |

Containers are exploded into `.eml` under `<scan root>/.postmortem_extracted/…`, **preserving the source folder hierarchy in the path** so folder-based concealment detection works exactly as it does on a raw `.eml` tree. Extraction is idempotent (reuses prior output unless `--reingest`).

### Microsoft 365 Unified Audit Log (`--audit-log`)

Pass a UAL export and the tool derives the incident anchors **from the attacker's own recorded actions** — no manual entry, and no Entra sign-in log required. It accepts all three common shapes automatically:

- Purview portal **CSV**
- `Search-UnifiedAuditLog` **JSON / JSONL**
- Management Activity / **Graph JSON** (`{"value":[…]}`)

From it, `postmortem` derives the compromise time, attacker IP(s), forwarding address/domain, and rule keywords, and turns the malicious mailbox rule and attacker sign-ins into **confirmed** evidence in the attack narrative. (Attacker IPs come from the `ClientIP` that created the malicious rule; any `UserLoggedIn` from that IP is then treated as an attacker session.)

---

## Incident anchors

Anchors are ground-truth facts that focus the hunt. Supply any you know; the rest are inferred. `--audit-log` fills these in automatically where it can, and explicit flags win over derived values.

| Flag | Purpose |
|---|---|
| `--scenario {auto,ato,impersonation}` | Force or auto-detect the BEC scenario. |
| `--compromise-date` | Earliest known attacker action (e.g. when the malicious rule was created). In ATO mode the phish is sought *before* this; later mail is treated as post-compromise. |
| `--impersonated` | Impersonated exec/vendor (name or email). |
| `--fraud-account` | Known fraudulent bank account / IBAN. |
| `--attacker-domain` | Known attacker domain (e.g. a rule's forwarding target). |
| `--attacker-ip` | Attacker sending IP, matched against each message's originating IP. |
| `--attacker-address` | Known attacker email, matched against sender and Reply-To. |
| `--rule-keyword` | Keyword the malicious rule filtered on — resurfaces the mail it was hiding. |
| `--victim-domain` | The org's own domain(s), for self-spoofing detection (inferred if omitted). |

All list flags are repeatable and comma-separatable.

### Tuning & CI

| Flag | Purpose |
|---|---|
| `--allowlist DOMAIN` | Known-good sending domain(s) whose **weak header-hygiene noise** (chronic auth failure, thin/absent Received chain, missing Date) is suppressed — **only** when the message shows no active spoofing signal. Alignment, impersonation, and content checks are never suppressed, so spoofing an allowlisted From address cannot launder an attack. Repeatable/comma-separated. |
| `--fail-on-tier N` | CI gating: exit with **code 3** if any message lands in review tier ≤ N (1 = prime suspects, 2 = + secondary). Default `0` = always exit 0 on a successful scan. |

**Exit codes:** `0` success · `1`/`2` usage/IO errors · `3` findings met `--fail-on-tier`.

---

## What it looks for

Rather than trusting any single header, `postmortem` combines config-independent, attacker-controlled signals:

- **Authentication deviation** — auth failure weighted against the sender's baseline, so chronically-misconfigured legitimate senders aren't promoted while a normally-authenticating sender that suddenly fails is. SPF/DKIM/DMARC results are parsed with their **failure reasons** (and Microsoft 365's `compauth` composite verdict), which are shown inline with each finding.
- **Self-spoofing** — mail failing auth while claiming one of the victim's own domains.
- **Look-alike / homoglyph domains** and **display-name impersonation**.
- **Reply-To divergence** from the sending domain.
- **Sending-IP anomaly** — an established sender arriving from an unfamiliar origin.
- **Thread injection** — a reply grafted into an existing thread from a new domain.
- **Header hygiene / spoofing alignment** (weak corroborators, external senders): a forged **Received chain** (missing, single-hop, or out-of-order timestamps), **Message-ID**, **DKIM `d=`**, and **Return-Path** domains that don't align with the From domain, and an impossible **Date** (missing, unparseable, or later than delivery). Compared at the registrable-domain level, so legitimate subdomain signing doesn't trip them.
- **Concealment** — messages deleted or moved to low-visibility folders, and messages matching a malicious rule's keywords.
- **Attachment threats** — macro-enabled Office docs, HTML login forms, forwarded phish, deceptive double extensions, **content that doesn't match its extension** (magic-byte sniff — e.g. an executable named `invoice.pdf`), and **dangerous files inside archives** (a `.zip` peeked for `.exe`/`.js`/nested archives, no extraction). Offline inspection, no execution.
- **Obfuscated & random signals** — URLs hidden in **base64-encoded body text** (decoded and run through the URL pipeline; inline `data:` images excluded), and **machine-generated sender local-parts** (high-entropy, corroboration-gated).
- **Bulk-mail down-weighting** — legitimate marketing markers (`List-Unsubscribe`, `Precedence: bulk`) lower a message's priority, but never override a spoofing signal.
- **Anchor matches** — anything tied to a known attacker IP/address/domain/account or a supplied/derived compromise window.

### Optional enrichment (opt-in)

| Flag | What it adds |
|---|---|
| `--check-domain-age [DAYS]` | **Online (RDAP):** flags suspect sender domains registered within `DAYS` (default 90) — a strong attacker-infrastructure signal. Results cached on disk; fails closed offline. |
| `--yara-rules FILE` | Scans suspect attachments with YARA rules (needs `yara-python`; skipped with a warning if absent). |
| `--scan-qr` | Decodes QR codes in suspect image attachments ("quishing") and analyzes the linked URLs (needs `pyzbar` + `Pillow`). |
| `--geoip-db FILE` | **Offline:** geolocate originating/Received IPs with a local MaxMind GeoLite2 `.mmdb` (City/Country and/or ASN; repeatable). Surfaces each suspect's origin country, ASN, and hosting org, and flags **high-abuse hosting networks**. Needs the `maxminddb` reader. |
| `--expected-countries CC,CC` | With `--geoip-db`, flags a message routed through any country outside this set as **suspicious geography**. |

---

## Outputs

By default it prints a console report; add flags to write files.

| Flag | Output |
|---|---|
| `-o, --output` | **Interactive HTML** report — an **executive summary**, dashboard, attack narrative, timeline, an interactive **relationship graph** (shared senders/domains/hashes/campaigns/ASNs; click a node to pivot), and a searchable, **sortable** candidate table with **MITRE ATT&CK** tags per message and a **defanged, collapsible preview** of each body. Trimmed to the top `--html-limit` messages (default 1000). |
| `--json` | **Full JSON** — every message, every finding with provenance, the audit-log block, IOCs, an **ATT&CK technique summary**, timeline, and manifest. Never trimmed. |
| `--csv` | **Per-message CSV** with all timestamps converted to **UTC** (handy when the export is in local time). |
| `--ioc` | **Pivot-ready IOC CSV** — domains, URLs, IPs, and hashes from the Tier 1/2 suspects. |

### Review tiers

Suspects are ranked into **Tier 1** (prime suspects), **Tier 2** (secondary), and **Tier 3** (everything else) so an analyst reviews the shortlist first instead of 30,000 messages.

### Top flagged domains

Both the console and HTML report include a **Top Flagged Domains** summary — Tier 1/2 messages grouped by sender domain with message count, highest tier, total score, and senders — so a campaign shows up as one row instead of many. In the HTML report the table is sortable and each domain pivots the view.

### Evidence provenance

Every named finding carries a chain-of-custody record — `{signal, category, source, matched, weight, severity}` — so each conclusion is independently verifiable. In the console it appears inline, e.g.:

```
- External sender: supplier.com  [header:From +2 | low]
- Matches a keyword the malicious mailbox rule acted on  [investigator_anchor +3 | medium]
- Message was deleted/moved to a low-visibility folder (deleted items)  [mailbox_metadata +4 | medium]
```

The full record is in the JSON (`emails[].provenance`) and annotated in the HTML candidate table.

### Attack narrative

The report reconstructs the incident across phases — initial access → compromise → persistence/concealment → fraudulent objective — with a chronological UTC timeline. When an audit log is supplied, the relevant steps are marked **CONFIRMED (M365 audit log)**.

### Run manifest

Every run emits a reproducibility / chain-of-custody manifest: tool and parser version, UTC timestamp, corpus message count and SHA-256, the detected scenario, and the exact command line.

---

## Performance on large mailboxes

- **Resumable SQLite cache** — re-runs reuse prior parse/analysis; interrupted runs pick up where they left off. (`--cache`, `--no-cache`.)
- **Parallel parsing** — `--workers N` (default 8); falls back to serial automatically where process pools aren't available.
- **Two-pass screening** — a cheap fast pass narrows candidates before expensive deep analysis (`--candidate-threshold`).
- **`--screen-chars N`** — cap the body characters scanned in the fast pass (default 16000) for a large speed win on long-body mail.
- **`--content-hash`** — compute per-file SHA-256 so identical messages at different paths reuse analysis (off by default).
- **`--html-limit`** — cap messages embedded in the HTML (default 1000; JSON/CSV always keep everything), keeping the report small and openable.

---

## Configuration

`--config file.json` overrides scoring weights, thresholds, clustering caps, and baseline minimums (see `CONFIG` in [`postmortem/config.py`](postmortem/config.py) for the keys). The effective values are recorded in the run manifest.

---

## Safety

- Parses local files only; **never executes attachments, opens URLs, or downloads remote content**.
- Attachment inspection (macros, embedded forms) is static — archives are read, not run.
- No telemetry, no network calls.

---

## Development

```bash
pip install pytest pyflakes
python -m pytest -q          # test suite
python -m pyflakes postmortem/*.py   # lint
```

### Project layout

```
postmortem/
  __main__.py          CLI orchestrator (argument parsing, run wiring); `python -m postmortem`
  models.py            EmailRecord, Anchors, and other core dataclasses
  parsing.py           .eml parsing, body/URL/attachment extraction
  scoring.py           screening, scenario/anchor analysis, tiers, narrative, provenance
  clustering.py        campaign detection
  auditlog.py          M365 Unified Audit Log ingestion
  mailbox_ingest.py    PST/OST/MBOX -> .eml extraction (folders preserved)
  iocs.py              IOC extraction/export
  reporting.py         console + HTML + JSON + CSV output
  cache.py             resumable SQLite record cache
  urls.py, utils.py, config.py
test_postmortem.py     test suite
```

---

## Limitations

- PST/OST require `libpff-python`; otherwise convert with `readpst -e -o <outdir> file.pst` and analyze `<outdir>`.
- The tool assists an analyst — it ranks and explains suspects; it does not render a verdict on your behalf. Corroborate findings with mailbox audit and sign-in logs.
