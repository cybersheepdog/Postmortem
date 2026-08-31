"""Unit and integration tests for postmortem.

Run with:  python -m pytest test_postmortem.py -q
       or:  python test_postmortem.py        (falls back to a built-in runner)

These lock down the parsing, scoring, clustering, tiering, attachment
inspection, IOC extraction and config behaviour so the scoring logic can be
changed safely. They construct messages in memory; no network or real mailbox
is required.
"""

import copy
from email.message import EmailMessage

import postmortem.__main__ as b
from postmortem.config import CONFIG
from postmortem.models import Anchors, EmailRecord
from postmortem.scoring import (
    find_lookalike, v8_candidate_score, classify_attack_stage,
    run_scenario_analysis, calculate_score,
)
from postmortem.parsing import parse_eml
from postmortem.iocs import extract_iocs
from postmortem.utils import parse_date, to_utc_fields
from postmortem.reporting import corpus_fingerprint


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def make_record(**kw):
    """An EmailRecord with test-friendly defaults."""
    defaults = dict(
        path=kw.get("path", "/mail/" + kw.get("mid", "m") + ".eml"),
        filename="m.eml",
        sender_email=kw.get("sender_email", "sender@ext.example"),
        sender_domain=kw.get("sender_domain", "ext.example"),
        recipients=["victim@acme.com"],
        date=kw.get("date", "Mon, 12 Jan 2025 09:00:00 -0500"),
        subject=kw.get("subject", "Hello"),
        body=kw.get("body", "Regular message."),
    )
    defaults.update({k: v for k, v in kw.items() if k not in ("mid",)})
    return EmailRecord(**defaults)


def write_eml(path, from_addr, subject, body, attachments=None, auth=None):
    m = EmailMessage()
    m["From"] = from_addr
    m["To"] = "victim@acme.com"
    m["Subject"] = subject
    m["Date"] = "Mon, 12 Jan 2025 09:00:00 -0500"
    m["Message-ID"] = f"<{abs(hash((from_addr, subject)))}@x>"
    if auth:
        m["Authentication-Results"] = auth
    m.set_content(body)
    for name, data, ctype in (attachments or []):
        maintype, subtype = ctype.split("/", 1)
        m.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    path.write_bytes(bytes(m))
    return path


# --------------------------------------------------------------------------
# pure helpers
# --------------------------------------------------------------------------
def test_normalize_email_and_domain():
    from postmortem.utils import normalize_email, domain_of
    assert normalize_email("Jane Doe <Jane@Example.COM>") == "jane@example.com"
    assert domain_of("jane@example.com") == "example.com"
    assert domain_of("no-at-sign") == ""


def test_parse_date_and_utc_rollover():
    # 22:30 EST -> 03:30 next day UTC
    iso, day = to_utc_fields("Mon, 13 Jan 2025 22:30:00 -0500")
    assert iso == "2025-01-14T03:30:00Z"
    assert day == "2025-01-14"
    assert parse_date("") is None


def test_parse_date_is_memoized():
    parse_date.cache_clear()
    s = "Tue, 04 Feb 2025 11:00:00 +0000"
    parse_date(s)
    parse_date(s)
    info = parse_date.cache_info()
    assert info.hits >= 1


def test_find_lookalike():
    known = {"example-corp.com", "microsoft.com", "acme.com"}
    assert find_lookalike("examp1e-corp.com", known) == "example-corp.com"
    assert find_lookalike("rnicrosoft.com", known) == "microsoft.com"  # rn->m
    assert find_lookalike("acme.com", known) == ""       # identical, not a lookalike
    assert find_lookalike("totally-different.org", known) == ""


def test_registered_domain_approx():
    from postmortem.utils import registered_domain_approx
    assert registered_domain_approx("mail.example.co.uk") == "example.co.uk"
    assert registered_domain_approx("a.b.example.com") == "example.com"


def test_classify_attack_stage():
    r = make_record(subject="wire transfer", body="please send the wire")
    assert classify_attack_stage(r) == "payment_request"
    r2 = make_record(subject="hello", body="are you available", urls=[])
    assert classify_attack_stage(r2) in {"social_engineering", "initial_contact"}


# --------------------------------------------------------------------------
# candidate screening
# --------------------------------------------------------------------------
def test_v8_candidate_score_flags_bec():
    r = make_record(subject="URGENT wire transfer", body="please wire funds to new bank account")
    candidate, score, reasons = v8_candidate_score(r)
    assert candidate and score > 0

    benign = make_record(subject="lunch", body="want to grab lunch tomorrow")
    cand2, score2, _ = v8_candidate_score(benign)
    assert score2 == 0


def test_screen_chars_limits_scan():
    # a high-signal term only deep in the body
    body = ("neutral text " * 500) + " wire transfer bank account gift card"
    r = make_record(subject="notes", body=body)
    full = v8_candidate_score(r, 16000)[1]
    short = v8_candidate_score(r, 200)[1]
    assert full >= short  # scanning less can only lose signal, never gain


# --------------------------------------------------------------------------
# attachment inspection (B3)
# --------------------------------------------------------------------------
def test_attachment_macro_html_and_double_ext(tmp_path):
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/vbaProject.bin", b"\x00macro")
    macro = write_eml(tmp_path / "macro.eml", "x@ext.example", "doc",
                      "see attached", [("invoice.docx", buf.getvalue(),
                       "application/vnd.openxmlformats-officedocument.wordprocessingml.document")])
    rec = parse_eml(macro, deep=True)
    assert any(a.get("macro") for a in rec.attachment_details)

    html = b"<form><input type=password></form>"
    hrec = parse_eml(write_eml(tmp_path / "h.eml", "x@ext.example", "login",
                                 "open this", [("a.html", html, "text/html")]), deep=True)
    assert any(a.get("html_form") for a in hrec.attachment_details)

    drec = parse_eml(write_eml(tmp_path / "d.eml", "x@ext.example", "pay",
                                 "open", [("receipt.pdf.exe", b"MZ", "application/octet-stream")]), deep=True)
    assert any(a.get("suspicious_name") for a in drec.attachment_details)


# --------------------------------------------------------------------------
# scenario scoring / auth baselining / tiering (integration)
# --------------------------------------------------------------------------
def build_ato_corpus():
    recs = []
    # acme.com authenticates (enforce domain) via several internal passes
    for i in range(6):
        recs.append(make_record(mid=f"int{i}", sender_email=f"staff{i}@acme.com",
                                 sender_domain="acme.com", subject="team note",
                                 authentication_results={"spf_pass": True, "dmarc_pass": True}))
    # chronically misconfigured vendor: always fails
    for i in range(6):
        recs.append(make_record(mid=f"ven{i}", sender_email="billing@smallvendor.com",
                                 sender_domain="smallvendor.com", subject="statement",
                                 authentication_results={"spf_fail": True}))
    # self-spoof: claims acme.com but fails
    recs.append(make_record(mid="spoof", sender_email="ceo@acme.com", sender_domain="acme.com",
                            subject="urgent wire transfer confidential",
                            body="process an urgent wire transfer, keep confidential",
                            authentication_results={"spf_fail": True, "dmarc_fail": True}))
    return recs


def test_auth_baseline_deviation_not_absolute():
    recs = build_ato_corpus()
    run_scenario_analysis(recs, {"acme.com"}, Anchors(victim_domains=["acme.com"]))
    by = {r.path.split("/")[-1]: r for r in recs}
    spoof = by["spoof.eml"]
    vendor = by["ven0.eml"]
    # self-spoof of the authenticating victim domain is flagged and scored high
    assert spoof.self_spoofing and spoof.scenario_score >= vendor.scenario_score + 5
    # chronic failer is NOT an anomaly and stays low
    assert vendor.auth_anomaly is False and vendor.scenario_score <= 1


def test_outbound_is_not_initial_email():
    recs = build_ato_corpus()
    recs.append(make_record(mid="sent", sender_email="victim@acme.com", sender_domain="acme.com",
                            subject="re: wire", body="here are the wire details"))
    run_scenario_analysis(recs, {"acme.com"}, Anchors(victim_domains=["acme.com"]))
    sent = [r for r in recs if r.path.endswith("sent.eml")][0]
    assert sent.is_inbound is False
    assert sent.scenario_score == 0 and sent.tier == 3


def test_attack_narrative_reconstruction():
    recs = build_ato_corpus()
    # add a clearly post-compromise outbound fraud message
    recs.append(make_record(mid="wire", sender_email="victim@acme.com",
                            sender_domain="acme.com", subject="Re: wire",
                            body="please wire the funds to new bank account",
                            date="20 Jan 2025 09:00:00 -0500"))
    _, _, verdict = run_scenario_analysis(
        recs, {"acme.com"},
        Anchors(victim_domains=["acme.com"], compromise_date=parse_date("15 Jan 2025 00:00:00 -0500")))
    narrative = verdict["attack_narrative"]
    phases = {p["phase"] for p in narrative["phases"]}
    assert "initial_access" in phases          # the self-spoof entry
    assert "persistence" in phases             # the compromise date / rule
    assert "fraud" in phases                    # the post-compromise wire
    assert narrative["summary"] and narrative["timeline"]
    stamps = [e["timestamp_utc"] for e in narrative["timeline"] if e["timestamp_utc"]]
    assert stamps == sorted(stamps)            # chronologically ordered


def test_anchor_match_forces_tier1_and_high_confidence():
    recs = build_ato_corpus()
    anchors = Anchors(victim_domains=["acme.com"], attacker_addresses=["ceo@acme.com"])
    scenario, reason, verdict = run_scenario_analysis(recs, {"acme.com"}, anchors)
    spoof = [r for r in recs if r.path.endswith("spoof.eml")][0]
    assert any("attacker address" in m for m in spoof.anchor_matches)
    assert spoof.tier == 1


# --------------------------------------------------------------------------
# evidence provenance (B7)
# --------------------------------------------------------------------------
def test_evidence_provenance_per_finding():
    r = make_record(
        sender_email="it@contoso-secure.com", sender_domain="contoso-secure.com",
        subject="Action required: verify your password",
        body="Please login at http://contoso-secure.com/verify",
        urls=["http://contoso-secure.com/verify"],
        url_domains=["contoso-secure.com"],
    )
    calculate_score(r, {"acme.com"}, set())

    # Every named indicator has a provenance record with the required schema.
    prov_by_signal = {p["signal"]: p for p in r.provenance}
    required = {"signal", "category", "source", "matched", "weight", "severity"}
    for p in r.provenance:
        assert required <= set(p), f"provenance entry missing keys: {p}"
        assert p["severity"] in ("low", "medium", "high")
    for ind in r.indicators:
        assert ind in prov_by_signal, f"indicator without provenance: {ind}"

    # The external-sender finding is sourced to the From header and carries the
    # concrete matched value and its score weight.
    ext = prov_by_signal["External sender: contoso-secure.com"]
    assert ext["source"] == "header:From"
    assert ext["matched"] == "contoso-secure.com"
    assert ext["weight"] == 2

    # Anchor findings from the scenario pass are attributed to the investigator
    # anchor (which is where a UAL-derived anchor also lands).
    recs = build_ato_corpus()
    anchors = Anchors(victim_domains=["acme.com"], attacker_addresses=["ceo@acme.com"])
    run_scenario_analysis(recs, {"acme.com"}, anchors)
    spoof = [r for r in recs if r.path.endswith("spoof.eml")][0]
    anchor_prov = [p for p in spoof.provenance
                   if p["category"] == "anchor" and p["source"] == "investigator_anchor"]
    assert anchor_prov, "expected an anchor-sourced provenance entry"
    assert any("attacker address" in p["matched"] for p in anchor_prov)


# --------------------------------------------------------------------------
# container ingestion (B8)
# --------------------------------------------------------------------------
def test_mbox_ingestion_preserves_concealment_folder(tmp_path):
    import mailbox as _mailbox
    from postmortem.mailbox_ingest import ingest_all, find_containers

    mbox_path = tmp_path / "case.mbox"
    box = _mailbox.mbox(str(mbox_path))

    def add(frm, subj, body, labels):
        m = _mailbox.mboxMessage()
        m["From"] = frm
        m["To"] = "victim@contoso.com"
        m["Subject"] = subj
        m["Date"] = "Thu, 21 Aug 2026 10:00:00 -0400"
        m["Message-ID"] = f"<{abs(hash((frm, subj)))}@x>"
        m["X-Gmail-Labels"] = labels
        m.set_payload(body)
        box.add(m)

    add("ap@supplier.com", "Updated invoice", "wire to new bank account", "Trash")
    add("bob@contoso.com", "lunch?", "grab lunch", "Inbox")
    box.flush()
    box.close()

    assert find_containers(mbox_path) == [mbox_path]

    out = tmp_path / "extracted"
    summary = ingest_all(mbox_path, out)
    assert summary["messages_written"] == 2

    emls = sorted(p for p in out.rglob("*.eml"))
    rel = {str(p.relative_to(out)).replace("\\", "/") for p in emls}
    # Gmail "Trash" label maps onto the Outlook "Deleted Items" folder so the
    # path-based concealment signal fires; "Inbox" is preserved verbatim.
    assert any("case/Deleted Items/" in r for r in rel), rel
    assert any("case/Inbox/" in r for r in rel), rel

    # The extracted Deleted-Items message parses and the folder hint resolves.
    from postmortem.scoring import folder_hint
    deleted = [p for p in emls if "Deleted Items" in str(p)][0]
    rec = parse_eml(deleted)
    assert rec is not None and rec.sender_email == "ap@supplier.com"
    kind, marker = folder_hint(rec.path)
    assert kind == "deleted"

    # Re-ingest is idempotent (reuses the prior extraction, no duplication).
    summary2 = ingest_all(mbox_path, out)
    assert summary2["messages_written"] == 2
    assert len(list(out.rglob("*.eml"))) == 2


# --------------------------------------------------------------------------
# clustering
# --------------------------------------------------------------------------
def test_campaign_similarity_wrapper_equivalence():
    from postmortem.clustering import (
        campaign_similarity, campaign_similarity_features, campaign_features,
    )
    a = make_record(subject="Invoice 1", body="payment please", sender_email="x@corp.com",
                    sender_domain="corp.com", url_domains=["bad.com"])
    c = make_record(subject="Invoice 1", body="payment please", sender_email="x@corp.com",
                    sender_domain="corp.com", url_domains=["bad.com"])
    v1 = campaign_similarity(a, c)
    v2 = campaign_similarity_features(campaign_features(a), campaign_features(c))
    assert v1 == v2


# --------------------------------------------------------------------------
# IOC extraction (B1)
# --------------------------------------------------------------------------
def test_extract_iocs():
    r = make_record(sender_email="attacker@evil.example", sender_domain="evil.example",
                    urls=["http://evil.example/login"],
                    url_analysis=[{"registrable_domain": "evil.example"}],
                    attachment_details=[{"sha256": "a" * 64, "filename": "x"}])
    r.tier = 1
    iocs = extract_iocs([r])
    types = {e["type"] for e in iocs}
    assert {"sender_domain", "sender_email", "url", "attachment_sha256"} <= types
    # tier-3 records contribute nothing
    r.tier = 3
    assert extract_iocs([r]) == []


# --------------------------------------------------------------------------
# config (C2)
# --------------------------------------------------------------------------
def test_config_override_changes_scoring():
    saved = copy.deepcopy(CONFIG)
    try:
        base = build_ato_corpus()
        run_scenario_analysis(base, {"acme.com"}, Anchors(victim_domains=["acme.com"]))
        spoof_default = [r for r in base if r.path.endswith("spoof.eml")][0].scenario_score

        CONFIG["initial_weights"]["self_spoofing"] = 30
        boosted = build_ato_corpus()
        run_scenario_analysis(boosted, {"acme.com"}, Anchors(victim_domains=["acme.com"]))
        spoof_boosted = [r for r in boosted if r.path.endswith("spoof.eml")][0].scenario_score
        assert spoof_boosted > spoof_default
    finally:
        CONFIG.clear()
        CONFIG.update(saved)


def test_corpus_fingerprint_deterministic():
    recs = [make_record(mid="a"), make_record(mid="b")]
    d1, basis1 = corpus_fingerprint(recs)
    d2, basis2 = corpus_fingerprint(list(reversed(recs)))
    assert d1 == d2  # order-independent


def test_package_shared_singletons():
    # CONFIG is one shared, mutable object across every module that reads it, so a
    # runtime --config override is visible everywhere.
    import postmortem.config, postmortem.scoring, postmortem.clustering, postmortem.parsing
    assert postmortem.scoring.CONFIG is postmortem.config.CONFIG
    assert postmortem.clustering.CONFIG is postmortem.config.CONFIG
    # The EmailRecord class the parser produces is the same one scoring consumes
    # (so pickling across the process pool stays consistent).
    assert postmortem.parsing.EmailRecord is postmortem.scoring.EmailRecord
    # The postmortem CLI facade wires straight through to the package functions.
    assert b.run_scenario_analysis is postmortem.scoring.run_scenario_analysis
    assert b.parse_eml is postmortem.parsing.parse_eml


# --------------------------------------------------------------------------
# minimal fallback runner
# --------------------------------------------------------------------------
if __name__ == "__main__":
    import tempfile
    from pathlib import Path
    failures = 0
    for name, fn in sorted(globals().items()):
        if not (name.startswith("test_") and callable(fn)):
            continue
        try:
            if "tmp_path" in fn.__code__.co_varnames[: fn.__code__.co_argcount]:
                with tempfile.TemporaryDirectory() as td:
                    fn(Path(td))
            else:
                fn()
            print(f"ok   {name}")
        except Exception as exc:  # noqa
            failures += 1
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    print(f"\n{'PASSED' if not failures else str(failures) + ' FAILED'}")
    raise SystemExit(1 if failures else 0)
