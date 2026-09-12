"""Unit and integration tests for postmortem.

Run with:  python -m pytest test_postmortem.py -q
       or:  python test_postmortem.py        (falls back to a built-in runner)

These lock down the parsing, scoring, clustering, tiering, attachment
inspection, IOC extraction and config behaviour so the scoring logic can be
changed safely. They construct messages in memory; no network or real mailbox
is required.
"""

import copy
import json
import sys
from datetime import datetime, timezone
from email.message import EmailMessage

import postmortem.__main__ as b
from postmortem.config import CONFIG
from postmortem.models import Anchors, EmailRecord
from postmortem.scoring import (
    find_lookalike, candidate_score, classify_attack_stage,
    run_scenario_analysis, calculate_score,
    analyze_received_chain, message_id_domain, dkim_d_domains,
    analyze_date_header,
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
def test_candidate_score_flags_bec():
    r = make_record(subject="URGENT wire transfer", body="please wire funds to new bank account")
    candidate, score, reasons = candidate_score(r)
    assert candidate and score > 0

    benign = make_record(subject="lunch", body="want to grab lunch tomorrow")
    cand2, score2, _ = candidate_score(benign)
    assert score2 == 0


def test_screen_chars_limits_scan():
    # a high-signal term only deep in the body
    body = ("neutral text " * 500) + " wire transfer bank account gift card"
    r = make_record(subject="notes", body=body)
    full = candidate_score(r, 16000)[1]
    short = candidate_score(r, 200)[1]
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
    # concrete matched value. Its weight is 0 since B6: being external is the
    # median external email, not evidence. It is still reported as context,
    # with full provenance -- a zero-weight finding is a fact about the
    # message, not an absent one.
    ext = prov_by_signal["External sender: contoso-secure.com"]
    assert ext["source"] == "header:From"
    assert ext["matched"] == "contoso-secure.com"
    assert ext["weight"] == 0

    # Something that IS evidence still carries its weight through provenance.
    scored = [p for p in r.provenance if p["weight"] > 0]
    assert scored, "expected at least one weighted finding"
    assert sum(p["weight"] for p in scored) >= r.score

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
# header-hygiene / spoofing-alignment checks
# --------------------------------------------------------------------------
def test_received_chain_analysis():
    assert analyze_received_chain([], True)["missing"] is True
    assert analyze_received_chain([], False)["missing"] is False  # internal ok
    one = analyze_received_chain(
        ["from a by b; Mon, 1 Jan 2026 10:00:00 +0000"], True)
    assert one["too_short"] is True
    # Newer-position hop older than an older-position hop => forged ordering.
    ooo = analyze_received_chain([
        "from a by b; Mon, 1 Jan 2026 10:00:00 +0000",   # newest (delivery)
        "from c by d; Mon, 1 Jan 2026 12:00:00 +0000",   # older but LATER
    ], True)
    assert ooo["out_of_order"] is True
    # A well-ordered two-hop external chain is clean.
    ok = analyze_received_chain([
        "from a by b; Mon, 1 Jan 2026 12:00:00 +0000",
        "from c by d; Mon, 1 Jan 2026 10:00:00 +0000",
    ], True)
    assert not (ok["missing"] or ok["too_short"] or ok["out_of_order"])


def test_header_domain_alignment_helpers():
    assert message_id_domain("<abc@mail.evil.com>") == "evil.com"
    assert message_id_domain("") == ""
    assert dkim_d_domains(["v=1; a=rsa-sha256; d=evil.com; s=sel"]) == {"evil.com"}
    assert dkim_d_domains(["d=vendor.com"]) == {"vendor.com"}  # tag at start
    anom, note = analyze_date_header("", None)
    assert anom and "missing" in note
    assert analyze_date_header("not a date", None)[0] is True
    assert analyze_date_header("Mon, 12 Jan 2026 09:00:00 -0500", None)[0] is False


def test_header_hygiene_signals_end_to_end():
    # External sender whose Message-ID, DKIM d=, and Return-Path all point at a
    # different registrable domain than the From header — classic spoof shape.
    r = make_record(
        sender_email="ceo@vendor.com", sender_domain="vendor.com",
        subject="Payment", body="please review",
        message_id="<x123@evil.com>",
        authentication_results={
            "return_path": "<bounce@evil.com>",
            "dkim_signatures": ["v=1; a=rsa-sha256; d=evil.com; s=s1"],
            "received": [],
        },
    )
    run_scenario_analysis([r], {"acme.com"}, Anchors(victim_domains=["acme.com"]))
    assert r.message_id_mismatch and r.dkim_domain_mismatch and r.return_path_mismatch
    sources = {p["source"] for p in r.provenance}
    assert {"header:Message-ID", "header:DKIM-Signature",
            "header:Return-Path"} <= sources

    # Legitimate subdomain signing must NOT trip the alignment checks.
    clean = make_record(
        sender_email="ap@vendor.com", sender_domain="vendor.com",
        message_id="<y@mail.vendor.com>",
        authentication_results={
            "return_path": "<bounce@mx.vendor.com>",
            "dkim_signatures": ["d=mail.vendor.com"],
            "received": [],
        },
    )
    run_scenario_analysis([clean], {"acme.com"}, Anchors(victim_domains=["acme.com"]))
    assert not clean.message_id_mismatch
    assert not clean.dkim_domain_mismatch
    assert not clean.return_path_mismatch


# --------------------------------------------------------------------------
# detection-quality batch: entropy, bulk, archive peek, base64, RDAP, yara, qr
# --------------------------------------------------------------------------
def test_high_entropy_local_part():
    from postmortem.scoring import looks_random_local_part
    assert looks_random_local_part("xk4jf92mliq8h@evil.example") is True
    assert looks_random_local_part("john.smith@corp.com") is False
    assert looks_random_local_part("john.smith2020@corp.com") is False
    assert looks_random_local_part("jsmith@corp.com") is False           # short
    assert looks_random_local_part("newsletter@corp.com") is False       # no digits


def test_high_entropy_local_part_needs_corroboration():
    # A random local-part with NO other signal must NOT be scored/listed. Give
    # the record a clean header set so no hygiene signal provides corroboration.
    r = make_record(
        sender_email="xk4jf92mliq8h@ext.example", sender_domain="ext.example",
        subject="hi", body="hello", message_id="<x@ext.example>",
        date="Mon, 20 Jan 2026 12:00:00 +0000",
        authentication_results={"received": [
            "from a by b; Mon, 20 Jan 2026 12:00:05 +0000",
            "from c by d; Mon, 20 Jan 2026 12:00:00 +0000"]})
    run_scenario_analysis([r], {"acme.com"}, Anchors(victim_domains=["acme.com"]))
    assert r.random_local_part is True   # detected...
    assert not any("machine-generated" in i for i in r.indicators)  # ...not scored alone


def test_bulk_mail_negative_signal():
    from postmortem.parsing import parse_authentication_headers
    from email.message import EmailMessage
    m = EmailMessage()
    m["From"] = "news@vendor.com"
    m["List-Unsubscribe"] = "<mailto:unsub@vendor.com>"
    auth = parse_authentication_headers(m)
    assert auth["bulk_mail"] is True

    r = make_record(sender_email="news@vendor.com", sender_domain="vendor.com",
                    subject="invoice payment", body="payment details",
                    authentication_results={"bulk_mail": True, "received": []})
    run_scenario_analysis([r], {"acme.com"}, Anchors(victim_domains=["acme.com"]))
    assert r.bulk_mail is True
    assert any("Bulk/marketing" in i for i in r.indicators)
    assert r.score >= 0  # floored


def test_base64_body_url_decoding():
    import base64 as _b64
    from postmortem.parsing import decode_base64_urls
    blob = _b64.b64encode(b"click http://evil.example/login now").decode()
    urls = decode_base64_urls(f"harmless text {blob} more text")
    assert any("evil.example" in u for u in urls)
    # data: image blobs are ignored
    assert decode_base64_urls("data:image/png;base64," + "A" * 40) == []


def test_base64_promotes_to_candidate_but_not_data_uri():
    # A lure + a base64 blob is promoted to a deep-analysis candidate...
    blob = "Z28gdG8gaHR0cDovL2V2aWwtbG9naW4uZXhhbXBsZS92ZXJpZnkgbm93"
    r = make_record(subject="verify your account password",
                    body="Please review: " + blob)
    cand, score, reasons = candidate_score(r)
    assert cand and "base64-encoded content in body" in reasons
    # ...but an inline data: image alone must NOT promote a benign newsletter.
    r2 = make_record(subject="monthly newsletter",
                     body="<img src='data:image/png;base64," + "A" * 200 + "'>")
    assert not candidate_score(r2)[0]


def test_archive_zip_peek(tmp_path):
    import zipfile as _zip
    import io as _io
    buf = _io.BytesIO()
    with _zip.ZipFile(buf, "w") as z:
        z.writestr("invoice.exe", b"MZ payload")
        z.writestr("readme.txt", b"hello")
    p = write_eml(tmp_path / "m.eml", "a@ext.example", "docs", "see zip",
                  attachments=[("docs.zip", buf.getvalue(), "application/zip")])
    rec = parse_eml(p, deep=True)
    det = rec.attachment_details[0]
    assert det["archive_threat"] is True
    assert any(".exe" in f for f in det["attachment_flags"])


def test_rdap_domain_age_parsing():
    from postmortem.netcheck import _registration_date, age_days
    data = {"events": [{"eventAction": "registration",
                        "eventDate": "2026-08-01T00:00:00Z"}]}
    reg = _registration_date(data)
    assert reg is not None
    ref = datetime(2026, 8, 20, tzinfo=timezone.utc)
    assert age_days(reg, ref) == 19
    assert age_days(None, ref) == -1


def test_rdap_checker_offline_is_safe(tmp_path):
    # No network here: a lookup must fail closed to None, never raise.
    from postmortem.netcheck import DomainAgeChecker
    c = DomainAgeChecker(cache_path=tmp_path / "cache.json", timeout=0.01)
    assert c.registration_date("definitely-not-a-real-domain-xyz.invalid") is None


def test_yara_and_qr_graceful_without_deps(tmp_path):
    # These opt-in passes must no-op (return 0) when their libs are absent,
    # rather than crash. (yara-python / pyzbar are not installed here.)
    import importlib.util
    from postmortem import yara_scan, qr_scan
    r = make_record(sender_email="a@ext.example", sender_domain="ext.example")
    r.tier = 1
    r.path = str(tmp_path / "nonexistent.eml")
    if importlib.util.find_spec("yara") is None:
        # a directory of rules is accepted; missing lib -> available False, no crash
        (tmp_path / "rules").mkdir()
        (tmp_path / "rules" / "a.yar").write_text("rule x { condition: true }")
        res = yara_scan.scan_records([r], tmp_path / "rules")
        assert res["matches"] == 0 and res["available"] is False
    if importlib.util.find_spec("pyzbar") is None:
        assert qr_scan.scan_records([r]) == 0


# --------------------------------------------------------------------------
# investigation window: bounding "earliest" against the compromise date
# --------------------------------------------------------------------------
def test_investigation_window_bounds_the_entry_point_search():
    from datetime import datetime, timedelta, timezone
    from email.utils import format_datetime
    from postmortem.scoring import (
        investigation_window, in_lookback, after_compromise)

    compromise = datetime(2026, 8, 25, 15, 54, tzinfo=timezone.utc)
    anchors = Anchors(compromise_date=compromise, lookback_days=90)

    start, end = investigation_window(anchors)
    assert (end - start).days == 90

    def at(when):
        r = make_record()
        r.date = format_datetime(when)
        return r

    ancient = at(datetime(2012, 4, 13, tzinfo=timezone.utc))
    recent = at(compromise - timedelta(days=9))
    later = at(compromise + timedelta(hours=2))

    # The failure this guards: on a fourteen-year mailbox everything is
    # "before the compromise", so an unbounded search always returns the
    # oldest message rather than the entry point.
    assert in_lookback(ancient, anchors) is False
    assert in_lookback(recent, anchors) is True
    assert in_lookback(later, anchors) is False
    assert after_compromise(later, anchors) is True
    assert after_compromise(recent, anchors) is False

    # With no compromise date, nothing is excluded.
    open_anchors = Anchors()
    assert investigation_window(open_anchors) == (None, None)
    assert in_lookback(ancient, open_anchors) is True


def test_old_outbound_payment_mail_is_not_fraud_evidence():
    # Reproduces the reported symptom: a 2014 outbound email mentioning a
    # payment was surfaced as "fraudulent instruction" for a 2026 compromise,
    # because the outbound branch of the fraud test ignored the date.
    from datetime import datetime, timedelta, timezone
    from email.utils import format_datetime
    from postmortem.scoring import run_scenario_analysis

    compromise = datetime(2026, 8, 25, 15, 54, tzinfo=timezone.utc)
    anchors = Anchors(compromise_date=compromise, lookback_days=90)

    def outbound(mid, when):
        r = make_record(mid=mid, sender_email="staff@acme.com",
                        sender_domain="acme.com")
        r.recipients = ["ap@partner.example"]
        r.date = format_datetime(when)
        r.subject = "Invoice"
        r.body = "Please change bank details for the next wire transfer."
        r.is_inbound = False
        return r

    old = outbound("old", datetime(2014, 8, 20, tzinfo=timezone.utc))
    new = outbound("new", compromise + timedelta(hours=2))

    _scenario, _reason, _verdict = run_scenario_analysis(
        [old, new], {"acme.com"}, anchors, {})
    fraud_paths = {
        e["path"] for e in (_verdict.get("narrative", {}) or {}).get("timeline", [])
        if e.get("phase") == "fraud"
    }
    assert old.path not in fraud_paths, (
        "a 2014 message must not be fraud evidence for a 2026 compromise")


# --------------------------------------------------------------------------
# tiering and verdicts are bounded to the incident
# --------------------------------------------------------------------------
def _aged_corpus():
    """A long-lived mailbox: years of signal-bearing mail, one real phish."""
    from datetime import datetime, timedelta, timezone
    from email.utils import format_datetime
    compromise = datetime(2026, 8, 25, 15, 54, tzinfo=timezone.utc)
    records = []
    for i in range(60):
        r = make_record(mid="old%d" % i, sender_email="p%d@vendor.example" % (i % 10),
                        sender_domain="vendor.example")
        r.date = format_datetime(datetime(2012, 1, 1, tzinfo=timezone.utc)
                                 + timedelta(days=i * 60))
        r.subject = "Please verify your account"
        r.body = "Confirm the payment and sign in: http://vendor.example/login"
        r.is_inbound = True
        r.scenario_score = 6
        records.append(r)
    phish = make_record(mid="phish", sender_email="x@evil.example",
                        sender_domain="evil.example")
    phish.date = format_datetime(compromise - timedelta(days=11))
    phish.subject = "Action required: mailbox over quota"
    phish.body = "Verify your identity and reset your password: http://evil.example/verify"
    phish.is_inbound = True
    phish.scenario_score = 20
    records.append(phish)
    return records, phish, Anchors(compromise_date=compromise, lookback_days=90)


def test_tier_two_is_bounded_to_the_incident():
    # Regression: Tier 2 was "inbound with any signal", unbounded. On a
    # fourteen-year mailbox that was over half the corpus -- not a review
    # queue, and it dragged the attachment scan and IOC extraction with it.
    from postmortem.scoring import assign_tiers

    records, phish, anchors = _aged_corpus()
    counts = assign_tiers(records, "ato", anchors)
    assert phish.tier == 1
    assert counts[2] == 0, "years-old mail must not be a secondary suspect"
    assert counts[3] == 60

    # With no compromise date there is no window, so nothing is excluded.
    open_anchors = Anchors()
    counts = assign_tiers(records, "ato", open_anchors)
    assert counts[2] > 0

    # An investigator anchor always wins, however old the message.
    ancient = records[0]
    ancient.anchor_matches = ["attacker address bad@evil.example"]
    assign_tiers(records, "ato", anchors)
    assert ancient.tier == 1


def test_initial_email_is_chosen_from_the_window():
    from postmortem.scoring import anchored_initial_email_verdict
    records, phish, anchors = _aged_corpus()
    verdict = anchored_initial_email_verdict(records, "ato", anchors, "test")
    assert verdict["verdict"] == "LIKELY_INITIAL_EMAIL"
    assert verdict["initial_email"]["path"] == phish.path
    assert "searched" in verdict["reason"]


def test_nothing_in_window_is_reported_as_nothing():
    # A wrong answer stated confidently is worse than no answer: the old code
    # fell back to the whole corpus and returned a 2014 message at high
    # confidence.
    from postmortem.scoring import anchored_initial_email_verdict
    records, phish, anchors = _aged_corpus()
    records.remove(phish)
    verdict = anchored_initial_email_verdict(records, "ato", anchors, "test")
    assert verdict["verdict"] == "NO_INITIAL_EMAIL_IDENTIFIED"
    assert "searched" in verdict["reason"]
    assert verdict["initial_email"] is None


# --------------------------------------------------------------------------
# process pools: spawn-safety
# --------------------------------------------------------------------------
def test_pool_workers_are_importable_by_module_path():
    """Every function handed to a process pool must live outside __main__.

    Windows and macOS start workers with `spawn`: the child is a fresh
    interpreter that imports the function by its module path. A function
    defined in postmortem/__main__.py and reached via `python -m postmortem`
    has module path "__main__", which in the child is an empty frozen module::

        AttributeError: Can't get attribute '_parse_uncached_worker'
            on <module '__main__' (BuiltinImporter)>
        BrokenProcessPool: A process in the pool was terminated abruptly

    Every worker died on startup, so parallel parsing, deep enrichment and
    attachment scanning never ran on Windows at all. Linux's default `fork`
    inherits memory and hides it completely.
    """
    import importlib
    from postmortem import workers, attachment_scan, mailbox_ingest

    dispatched = [
        workers._parse_uncached_worker,
        workers._deep_analyze_worker,
        attachment_scan._scan_one,
        attachment_scan._init_worker,
        mailbox_ingest._extract_folder,
    ]
    for fn in dispatched:
        assert fn.__module__ != "__main__", (
            f"{fn.__qualname__} is defined in __main__ and cannot be sent to a "
            "spawn-based process pool")
        module = importlib.import_module(fn.__module__)
        assert getattr(module, fn.__name__, None) is fn, (
            f"{fn.__qualname__} is not reachable at {fn.__module__}."
            f"{fn.__name__}, so a spawned worker cannot import it")


def test_broken_pool_falls_back_without_losing_or_repeating_work():
    # A pool that dies mid-run used to abort the whole analysis. Degrading to
    # serial must produce exactly the same results: executor.map yields in
    # order, so the count of results already delivered is a safe resume point.
    import postmortem.__main__ as main_module

    class DyingPool:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def map(self, fn, items, chunksize=1):
            for i, item in enumerate(items):
                if i == 4:
                    raise OSError("pool died")
                yield fn(item)

    original = main_module.ProcessPoolExecutor
    main_module.ProcessPoolExecutor = DyingPool
    try:
        out = list(main_module.parallel_map(
            lambda x: x * 2, list(range(10)), workers=4, chunksize=1))
    finally:
        main_module.ProcessPoolExecutor = original

    assert out == [x * 2 for x in range(10)]


# --------------------------------------------------------------------------
# audit log: mailbox forwarding, merged timeline
# --------------------------------------------------------------------------
def _write_ual(tmp_path, events):
    import json
    p = tmp_path / "ual.json"
    p.write_text(json.dumps(events))
    return p


def test_set_mailbox_smtp_forwarding_is_detected(tmp_path):
    # Regression: Exchange records Set-Mailbox forwarding inside Parameters,
    # but the code only looked for it as a top-level field, so one of the most
    # common BEC persistence mechanisms was never detected -- and its exfil
    # address never became an anchor.
    from postmortem.auditlog import analyze_audit_log
    ual = _write_ual(tmp_path, [{
        "CreationTime": "2025-09-01T14:32:11", "Operation": "Set-Mailbox",
        "UserId": "jane@corp.example", "ClientIP": "203.0.113.9",
        "Parameters": [
            {"Name": "ForwardingSmtpAddress", "Value": "smtp:exfil@evil.example"},
            {"Name": "DeliverToMailboxAndForward", "Value": "True"}]}])
    summary = analyze_audit_log(str(ual))
    assert "exfil@evil.example" in summary["derived"]["attacker_addresses"]
    assert "evil.example" in summary["derived"]["attacker_domains"]
    entry = summary["forwarding_rules"][0]
    assert entry["mailbox_level"] is True
    # Forwarding that also delivers to the mailbox hides the exfiltration from
    # the user, and is worth stating separately.
    assert entry["keeps_copy"] is True


def test_audit_events_merge_into_the_timeline(tmp_path):
    from postmortem.auditlog import analyze_audit_log
    from postmortem.scoring import build_attack_timeline
    from postmortem.utils import parse_date

    ual = _write_ual(tmp_path, [
        {"CreationTime": "2025-01-15T09:14:00", "Operation": "UserLoggedIn",
         "UserId": "jane@corp.example", "ClientIP": "203.0.113.9"},
        {"CreationTime": "2025-01-15T09:26:00", "Operation": "New-InboxRule",
         "UserId": "jane@corp.example", "ClientIP": "203.0.113.9",
         "Parameters": [{"Name": "SubjectContainsWords", "Value": "invoice;wire"},
                        {"Name": "MoveToFolder", "Value": "RSS Feeds"}]}])
    summary = analyze_audit_log(str(ual))

    before = make_record(mid="before", date="Mon, 13 Jan 2025 09:00:00 +0000")
    after = make_record(mid="after", date="Fri, 17 Jan 2025 09:00:00 +0000")
    timeline = build_attack_timeline([before, after], summary)

    sources = [getattr(e, "source", "message") for e in timeline]
    assert sources.count("audit") == 2
    assert len(timeline) == 4

    # Fully chronological: audit timestamps are ISO 8601 rather than RFC 2822,
    # and used to fail to parse, which sorted every audit event to the end.
    stamps = [parse_date(e.timestamp) for e in timeline]
    assert all(stamps[i] >= stamps[i - 1] for i in range(1, len(stamps)))
    assert sources == ["message", "audit", "audit", "message"]

    audit_events = [e for e in timeline if e.source == "audit"]
    assert {e.stage for e in audit_events} == {"attacker_signin", "persistence_rule"}
    rule = next(e for e in audit_events if e.stage == "persistence_rule")
    assert rule.client_ip == "203.0.113.9"
    assert any("invoice" in d for d in rule.evidence)
    # An audit event is a recorded fact, not a scored inference.
    assert rule.score == 0


def test_timeline_without_an_audit_log_is_unchanged():
    from postmortem.scoring import build_attack_timeline
    records = [make_record(mid="a", date="Mon, 13 Jan 2025 09:00:00 +0000")]
    assert len(build_attack_timeline(records)) == 1
    assert len(build_attack_timeline(records, None)) == 1
    assert build_attack_timeline(records)[0].source == "message"


# --------------------------------------------------------------------------
# body regions: quoted history, signatures, boilerplate, mass-mail bursts
# --------------------------------------------------------------------------
def test_split_quoted_and_signature():
    from postmortem.bodytext import split_quoted, strip_signature
    body = ("Hi Tom,\n\nThe payment went out today.\n\n"
            "--\nJane Smith | Accounts Payable\nThis email is confidential.\n\n"
            "On Mon, 1 Sep 2025 at 09:12, Tom <tom@corp.example> wrote:\n"
            "> Did the wire transfer go out? Keep this confidential.\n")
    own, quoted = split_quoted(body)
    assert "wire transfer" not in own.lower()
    assert "wire transfer" in quoted.lower()
    body_only, signature = strip_signature(own)
    assert "payment went out" in body_only
    assert "Accounts Payable" in signature

    # Interleaved quoting is history wherever it sits.
    own, quoted = split_quoted("New text.\n> old quoted line\nMore new text.")
    assert "old quoted line" not in own
    assert "old quoted line" in quoted


def test_boilerplate_index_separates_footers_from_mass_mail():
    # The case that makes naive repetition-detection dangerous: an attacker who
    # mass-mails a lure from a compromised account produces a repeated block
    # too. Suppressing it would hide the attack.
    from datetime import datetime, timedelta, timezone
    from email.utils import format_datetime
    from postmortem.bodytext import BoilerplateIndex, block_hash

    footer = ("This email and any attachments are confidential and intended solely "
              "for the addressee. If received in error please notify the sender.")
    lure = ("I have shared a secure document with you through our finance portal. "
            "Please sign in with your work credentials to review the details.")
    base = datetime(2025, 6, 1, tzinfo=timezone.utc)

    index = BoilerplateIndex()
    # Institutional: many senders, wide span, trailing, pre-compromise.
    for i in range(40):
        r = make_record(sender_email="user%02d@corp.example" % (i % 10))
        r.date = format_datetime(base + timedelta(days=i * 1.5))
        r.is_pre_compromise = True
        index.observe(r, "Notes attached.\n\n" + footer)
    # The blast: one sender, four hours, post-compromise, carrying that footer.
    blast = base + timedelta(days=95)
    for i in range(25):
        r = make_record(sender_email="jane@corp.example")
        r.date = format_datetime(blast + timedelta(minutes=i * 10))
        r.is_pre_compromise = False
        index.observe(r, lure + "\n\n" + footer)

    index.finalize(compromise_known=True)
    assert index.is_boilerplate(block_hash(footer)) is True
    assert index.is_boilerplate(block_hash(lure)) is False, (
        "an attacker's mass-mailed lure must never be treated as boilerplate")

    burst = index.burst_for(block_hash(lure))
    assert burst and burst["count"] == 25 and burst["sender"] == "jane@corp.example"
    assert index.burst_for(block_hash(footer)) is None


def test_footer_no_longer_scores():
    # Measured before this change: the footer alone was worth +7, because
    # "confidential" scored and unlocked the payment+secrecy combination.
    from postmortem.bodytext import prepare_bodies
    from datetime import datetime, timedelta, timezone
    from email.utils import format_datetime

    footer = ("This email and any attachments are confidential and intended solely "
              "for the addressee. If received in error please notify the sender.")
    message = "Hi Tom, the payment went out today. Thanks."
    base = datetime(2025, 6, 1, tzinfo=timezone.utc)

    corpus = []
    for i in range(40):
        r = make_record(sender_email="user%02d@vendor.example" % (i % 10))
        r.date = format_datetime(base + timedelta(days=i * 1.5))
        r.body = "Notes attached.\n\n" + footer
        corpus.append(r)

    with_footer = make_record(sender_email="jane@vendor.example")
    with_footer.date = format_datetime(base + timedelta(days=61))
    with_footer.body = message + "\n\n" + footer
    without = make_record(sender_email="jane@vendor.example")
    without.date = format_datetime(base + timedelta(days=61))
    without.body = message
    corpus += [with_footer, without]

    prepare_bodies(corpus)
    for r in (with_footer, without):
        calculate_score(r, {"acme.com"}, set())
    assert with_footer.score == without.score, (
        "the confidentiality footer still contributes "
        f"{with_footer.score - without.score} point(s)")


def test_quoted_signals_are_reported_without_score():
    # Excluding quoted history from scoring must not become a blind spot.
    from postmortem.bodytext import prepare_bodies
    r = make_record(sender_email="bob@corp.example")
    r.body = ("Looping in finance.\n\n"
              "On Mon, 1 Sep 2025 at 09:12, a <a@evil.example> wrote:\n"
              "> Please change the bank details and keep this confidential.\n")
    plain = make_record(sender_email="bob@corp.example")
    plain.body = "Looping in finance."

    prepare_bodies([r, plain])
    assert "bank details" in r.quoted_signals
    calculate_score(r, {"acme.com"}, set())
    calculate_score(plain, {"acme.com"}, set())
    # Reported, but worth nothing: the original message carries the weight.
    assert r.score == plain.score
    assert any("Quoted history mentions" in i for i in r.indicators)
    for finding in r.provenance:
        if "Quoted history" in finding.get("signal", ""):
            assert finding.get("weight", 0) == 0


# --------------------------------------------------------------------------
# provenance: every point is accounted for
# --------------------------------------------------------------------------
def test_score_reconciles_with_provenance():
    # The tool's headline claim is that every finding carries its provenance.
    # A score that cannot be decomposed into named findings is not evidence.
    # Regression: url_domains used to add points by mutating the score
    # directly, bypassing add() and leaving no indicator or provenance entry.
    cases = [
        dict(subject="Newsletter",
             body="Links: http://a.example/1 http://b.example/2 http://c.example/3",
             urls=["http://a.example/1", "http://b.example/2", "http://c.example/3"],
             url_domains=["a.example", "b.example", "c.example"]),
        dict(subject="URGENT wire transfer",
             body="Change bank details immediately and keep this confidential.",
             attachments=["invoice.docm"]),
        dict(subject="Re: lunch", body="See you at one."),
        dict(subject="Account statement",
             body="Payment received today. http://203.0.113.9/pay",
             urls=["http://203.0.113.9/pay"], url_domains=["203.0.113.9"]),
    ]
    for kw in cases:
        r = make_record(sender_email="s@ext.example", sender_domain="ext.example")
        for key, value in kw.items():
            setattr(r, key, value)
        calculate_score(r, {"acme.com"}, set())
        accounted = sum(f.get("weight", 0) for f in r.provenance)
        assert accounted == r.score, (
            f"{r.score - accounted} unattributed point(s) for {kw['subject']!r}")
        # Anything that scored must also be visible to the analyst.
        for finding in r.provenance:
            if finding.get("weight", 0):
                assert finding.get("signal"), "scored finding with no signal name"


# --------------------------------------------------------------------------
# candidate screening: sender, URL traits, standalone signals
# --------------------------------------------------------------------------
def _screen_record(**kw):
    r = make_record(sender_email=kw.get("sender_email", "s@ext.example"),
                    sender_domain=kw.get("sender_domain", "ext.example"))
    r.subject = kw.get("subject", "Hello")
    r.body = kw.get("body", "Regular message.")
    r.sender_name = kw.get("sender_name", "")
    r.urls = kw.get("urls", [])
    r.attachments = kw.get("attachments", [])
    r.authentication_results = kw.get("auth", {})
    return r


def test_url_risk_patterns_do_not_match_body_prose():
    # Regression: URL-risk patterns were matched against the whole message, so
    # ordinary words like "update", "account" and "payment" registered as URL
    # risk with no URL involved.
    prose = _screen_record(subject="Your March product update",
                           body="Your payment was received. Please update your account records.")
    assert candidate_score(prose)[1] == 0

    # The same words inside a URL still count -- but the risky-path family
    # stays gated behind a content signal, because plenty of legitimate URLs
    # contain "account" or "update". Isolate its contribution by holding the
    # lure text constant and varying only the URL.
    lure = "Please confirm your account. "
    risky = _screen_record(subject="Password reset",
                           body=lure + "http://evil.example/secure/verify/account",
                           urls=["http://evil.example/secure/verify/account"])
    benign = _screen_record(subject="Password reset",
                            body=lure + "https://corp.example/offsite",
                            urls=["https://corp.example/offsite"])
    assert candidate_score(risky)[1] > candidate_score(benign)[1]

    # A benign link with no lure is not evidence on its own.
    plain = _screen_record(subject="Team offsite",
                           body="Agenda: https://corp.example/offsite",
                           urls=["https://corp.example/offsite"])
    assert candidate_score(plain)[1] == 0


def test_url_traits_promote_without_a_partner_signal():
    # These have essentially no legitimate use in business mail, so a message
    # whose only content is such a link must still be examined.
    for body, url, reason in (
        ("see http://u:p@evil.example/", "http://u:p@evil.example/", "credentials"),
        ("see http://203.0.113.9/x", "http://203.0.113.9/x", "bare IP"),
    ):
        r = _screen_record(subject="Doc", body=body, urls=[url])
        candidate, score, reasons = candidate_score(r)
        assert candidate is True, reason
        assert any(reason.split()[0].lower() in x.lower() for x in reasons)


def test_executive_display_name_from_free_mail_stands_alone():
    # The opening move of most BEC carries no lure text by design; gating it
    # behind content signals meant it scored zero.
    bec = _screen_record(sender_name="Dana Whitfield (CEO)",
                         sender_email="dana.w@gmail.com", sender_domain="gmail.com",
                         subject="Quick favour", body="Are you at your desk?")
    candidate, score, reasons = candidate_score(bec)
    assert candidate is True
    assert any("free-mail" in r for r in reasons)

    # The genuine executive on the corporate domain is not a candidate.
    real = _screen_record(sender_name="Dana Whitfield, CEO",
                          sender_email="dana@corp.example", sender_domain="corp.example",
                          subject="All-hands Friday", body="See you there.")
    assert candidate_score(real)[0] is False


def test_sender_address_does_not_feed_the_content_family():
    # An ordinary accounts-payable mailbox address must not score as though the
    # message used invoice language.
    ap = _screen_record(sender_email="invoice@supplier.example",
                        sender_domain="supplier.example",
                        subject="Statement", body="Attached.")
    assert candidate_score(ap)[1] == 0


# --------------------------------------------------------------------------
# candidate screening: authentication signal
# --------------------------------------------------------------------------
def _auth_record(**auth):
    r = make_record(sender_email="s@ext.example", sender_domain="ext.example")
    r.subject = "Quarterly figures"
    r.body = "Attached as discussed."
    r.attachments = []
    r.authentication_results = dict(auth)
    return r


def test_auth_failures_promote_a_candidate():
    # Regression: candidate_score used to read record.authentication (no
    # such field) and compare "spf"/"dkim"/"dmarc" strings (wrong shape), so a
    # message failing every mechanism counted zero failures and was skipped by
    # deep analysis entirely.
    clean = _auth_record(spf_pass=True, dkim_pass=True, dmarc_pass=True)
    assert candidate_score(clean)[0] is False

    failing = _auth_record(spf_fail=True, dkim_fail=True, dmarc_fail=True)
    candidate, score, reasons = candidate_score(failing)
    assert candidate is True
    assert score > 0
    assert any("authentication" in r for r in reasons)

    # A lone SPF failure is routine on forwarded mail and stays below the bar.
    assert candidate_score(_auth_record(spf_fail=True))[0] is False

    # M365's composite verdict is its own judgement, counted alongside the
    # three mechanisms.
    both = _auth_record(spf_fail=True, compauth_fail=True)
    assert both.authentication_results["compauth_fail"] is True
    assert candidate_score(both)[1] > candidate_score(_auth_record(spf_fail=True))[1]


def test_bulk_mail_is_not_promoted_by_auth_failure_alone():
    # Relaying breaks SPF and DKIM on legitimate list traffic, so an auth
    # failure on an otherwise unremarkable bulk message is weak evidence.
    bulk = _auth_record(spf_fail=True, dkim_fail=True, bulk_mail=True)
    bulk.subject = "Your March product update"
    bulk.body = "Here is what shipped this month."
    candidate, score, reasons = candidate_score(bulk)
    assert candidate is False
    assert score == 0
    assert any("not promoted" in r for r in reasons)

    # But any other signal restores it: bulk is a tie-breaker, not an exemption.
    phishy = _auth_record(spf_fail=True, dkim_fail=True, bulk_mail=True)
    phishy.subject = "Verify your account immediately"
    phishy.body = "Click here to confirm your identity and reset your password."
    assert candidate_score(phishy)[0] is True

    attached = _auth_record(spf_fail=True, dkim_fail=True, bulk_mail=True)
    attached.attachments = ["statement.hta"]
    assert candidate_score(attached)[0] is True

    # A non-bulk message with the same failures is unaffected.
    assert candidate_score(
        _auth_record(spf_fail=True, dkim_fail=True))[0] is True


# --------------------------------------------------------------------------
# scale: adaptive worker sizing, resumable extraction, shared attachment scan
# --------------------------------------------------------------------------
def _mk_eml(path, subject="Urgent wire transfer request", attachment=None):
    m = EmailMessage()
    m["From"] = "attacker@evil-example.com"
    m["To"] = "victim@corp-example.com"
    m["Subject"] = subject
    m["Date"] = "Mon, 1 Sep 2025 10:00:00 +0000"
    m["Message-ID"] = "<%s@evil-example.com>" % path.stem
    m.set_content("Update the bank details now: http://evil-example.com/login")
    if attachment:
        name, data, maintype, subtype = attachment
        m.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(m.as_bytes())
    return path


def test_worker_plan_respects_cpu_memory_and_overrides(monkeypatch):
    # Worker counts must come from the host at run time, never a fixed cap,
    # and every bound must stay overridable for odd machines.
    from postmortem import resources

    monkeypatch.setattr(resources, "cpu_count", lambda logical=None: 8)
    monkeypatch.setattr(resources, "available_memory", lambda: 32 * 1024**3)
    monkeypatch.setenv("POSTMORTEM_CPU_RESERVE", "0")
    n, why = resources.plan_workers("parse")
    assert n == 8 and "cpu-bound" in why

    # A reservation leaves cores free for the parent and the OS.
    monkeypatch.setenv("POSTMORTEM_CPU_RESERVE", "2")
    assert resources.plan_workers("parse")[0] == 6

    # Scarce memory must narrow the pool rather than let it OOM mid-run.
    monkeypatch.setattr(resources, "available_memory", lambda: 1024**3)
    n, why = resources.plan_workers("parse")
    assert n < 6 and "memory-bound" in why

    # An explicit request is a ceiling, not a floor.
    monkeypatch.setattr(resources, "available_memory", lambda: 32 * 1024**3)
    assert resources.plan_workers("parse", requested=3)[0] == 3
    monkeypatch.setenv("POSTMORTEM_WORKERS", "5")
    assert resources.plan_workers("parse", requested=3)[0] == 5


def test_interrupted_extraction_is_not_reused_as_complete(tmp_path):
    # The bug this guards: reuse used to be decided by "does the output
    # directory contain any .eml", so a crash part way through a container
    # left a truncated mailbox that every later run silently accepted.
    import mailbox
    from postmortem import mailbox_ingest as mi

    src = tmp_path / "corp.mbox"
    box = mailbox.mbox(str(src))
    for i in range(40):
        m = EmailMessage()
        m["From"] = "a%d@evil-example.com" % i
        m["To"] = "v@corp-example.com"
        m["Subject"] = "Invoice %d" % i
        m["Date"] = "Mon, 1 Sep 2025 10:00:00 +0000"
        m["Message-ID"] = "<m%d@evil-example.com>" % i
        m.set_content("body")
        box.add(m)
    box.flush()
    box.close()

    out = tmp_path / "extracted"
    real_write = mi._write_eml
    state = {"n": 0}

    class Boom(Exception):
        pass

    def flaky(out_dir, parts, seq, raw):
        state["n"] += 1
        if state["n"] > 15:
            raise Boom("simulated power loss")
        return real_write(out_dir, parts, seq, raw)

    mi._write_eml = flaky
    try:
        try:
            mi.ingest_container(src, out)
        except Boom:
            pass
    finally:
        mi._write_eml = real_write

    target = out / "corp"
    assert list(target.rglob("*.eml")), "expected a partial extraction"
    manifest = mi.read_manifest(target)
    # Partial output must never pass for a finished extraction.
    assert not mi._manifest_usable(manifest, src)

    result = mi.ingest_container(src, out)
    assert not result.get("reused")
    assert len(list(target.rglob("*.eml"))) == 40
    assert result["messages_written"] == 40

    # A finished extraction is reused, and only then.
    again = mi.ingest_container(src, out)
    assert again.get("reused") is True


def test_mbox_resume_skips_already_extracted(tmp_path):
    import mailbox
    from postmortem import mailbox_ingest as mi

    src = tmp_path / "corp.mbox"
    box = mailbox.mbox(str(src))
    for i in range(30):
        m = EmailMessage()
        m["From"] = "a@evil-example.com"
        m["To"] = "v@corp-example.com"
        m["Subject"] = "Invoice %d" % i
        m["Date"] = "Mon, 1 Sep 2025 10:00:00 +0000"
        m["Message-ID"] = "<m%d@evil-example.com>" % i
        m.set_content("body")
        box.add(m)
    box.flush()
    box.close()

    target = tmp_path / "out"
    partial = mi.extract_mbox(src, target, manifest={"mbox_position": 20,
                                                     "messages_written": 20})
    # Only the tail is written when the manifest says the head is already done.
    assert partial["resumed_from"] == 20
    assert len(list(target.rglob("*.eml"))) == 10
    # Sequence numbers follow the message's position in the file, so a resumed
    # run lands on the same filenames an uninterrupted one would.
    names = sorted(p.name for p in target.rglob("*.eml"))
    assert names[0] == "000021.eml" and names[-1] == "000030.eml"


def test_attachment_scan_decodes_once_for_both_passes(tmp_path):
    # YARA and QR each used to re-open and re-parse every suspect message.
    from postmortem import attachment_scan

    records = []
    for i in range(4):
        p = _mk_eml(tmp_path / ("m%d.eml" % i),
                    attachment=("a.png", b"MARKER", "image", "png"))
        r = parse_eml(p)
        r.tier = 1
        records.append(r)

    real = attachment_scan.iter_attachment_payloads
    calls = {"n": 0}

    def counting(path):
        calls["n"] += 1
        return real(path)

    attachment_scan.iter_attachment_payloads = counting
    attachment_scan._build_decoder = lambda: (
        lambda payload: ["http://evil-qr-example.com/pay"])
    try:
        _, hits = attachment_scan.run_passes(records, want_qr=True)
    finally:
        attachment_scan.iter_attachment_payloads = real

    assert hits == 4
    assert calls["n"] == 4, "each message must be decoded exactly once"


def test_enrichment_replay_does_not_double_count(tmp_path):
    # Findings are additive, and scoring is recomputed from scratch each run.
    # A record already scanned must have its stored hits replayed exactly once
    # -- not rescanned, and not applied on top of themselves.
    from postmortem import attachment_scan

    p = _mk_eml(tmp_path / "m.eml",
                attachment=("a.png", b"MARKER", "image", "png"))
    record = parse_eml(p)
    record.tier = 1
    attachment_scan._build_decoder = lambda: (
        lambda payload: ["http://evil-qr-example.com/pay"])

    _, first = attachment_scan.run_passes([record], want_qr=True)
    score_after_first = record.score
    stamp = record.enrichment_fingerprint
    assert first == 1 and stamp and record.enrichment_hits

    # Second run: scoring has rebuilt the record, as the real pipeline does.
    record.score = 0
    record.indicators = []
    record.provenance = []
    real = attachment_scan.iter_attachment_payloads
    calls = {"n": 0}

    def counting(path):
        calls["n"] += 1
        return real(path)

    attachment_scan.iter_attachment_payloads = counting
    try:
        _, second = attachment_scan.run_passes([record], want_qr=True)
    finally:
        attachment_scan.iter_attachment_payloads = real

    assert calls["n"] == 0, "an already-scanned record must not be re-read"
    assert second == 1
    assert record.score == score_after_first
    assert len([i for i in record.indicators if "QR" in i]) == 1

    # Changing the configuration must invalidate the stored result.
    rules = tmp_path / "r.yar"
    rules.write_text('rule R { condition: false }')
    assert attachment_scan.fingerprint(rules, True) != stamp


def test_prune_keeps_flagged_and_never_leaves_the_extract_dir(tmp_path):
    from postmortem import mailbox_ingest as mi

    extract_dir = tmp_path / "extracted"
    outside = tmp_path / "analyst_own_eml"
    keep = _mk_eml(extract_dir / "corp" / "Inbox" / "000001.eml")
    drop = _mk_eml(extract_dir / "corp" / "Inbox" / "000002.eml")
    untouched = _mk_eml(outside / "mine.eml")

    r_keep = parse_eml(keep)
    r_keep.tier = 1
    r_drop = parse_eml(drop)
    r_drop.tier = 3
    r_outside = parse_eml(untouched)
    r_outside.tier = 3

    report = mi.prune_to_hits(extract_dir, [r_keep, r_drop, r_outside],
                              dry_run=True)
    assert report["removed"] == 1 and keep.exists() and drop.exists()

    report = mi.prune_to_hits(extract_dir, [r_keep, r_drop, r_outside])
    assert report["removed"] == 1 and report["kept"] == 1
    assert keep.exists() and not drop.exists()
    # A file the investigator supplied is outside the staging directory and
    # must be untouchable, whatever its tier.
    assert untouched.exists()


# --------------------------------------------------------------------------
# parsing correctness (HTML + PSL), top-domains summary, terminal color
# --------------------------------------------------------------------------
def test_html_to_text_and_links():
    from postmortem.parsing import html_to_text, html_links, html_has_login_form
    html = ("<html><head><style>x{}</style></head><body>Hello "
            "<a href='http://evil.example/login'>click here</a>"
            "<script>bad()</script><form><input type='password'></form></body></html>")
    text = html_to_text(html)
    assert "Hello" in text and "click here" in text
    assert "bad()" not in text and "x{}" not in text  # script/style stripped
    links = html_links(html)
    assert any(h == "http://evil.example/login" for h, _ in links)
    assert html_has_login_form(html) is True
    assert html_has_login_form("<p>no form here</p>") is False


def test_registered_domain_still_correct():
    from postmortem.utils import registered_domain_approx
    # Works whether or not tldextract is installed (PSL or built-in fallback).
    assert registered_domain_approx("mail.example.co.uk") == "example.co.uk"
    assert registered_domain_approx("a.b.example.com") == "example.com"


def test_top_flagged_domains():
    from postmortem.reporting import top_flagged_domains
    r1 = make_record(sender_email="a@bad.example", sender_domain="bad.example")
    r1.tier = 1
    r1.score = 30
    r2 = make_record(sender_email="b@bad.example", sender_domain="bad.example")
    r2.tier = 2
    r2.score = 8
    r3 = make_record(sender_email="c@ok.example", sender_domain="ok.example")
    r3.tier = 3  # not flagged -> excluded
    rows = top_flagged_domains([r1, r2, r3])
    assert len(rows) == 1
    row = rows[0]
    assert row["domain"] == "bad.example"
    assert row["messages"] == 2 and row["highest_tier"] == 1
    assert row["total_score"] == 38 and row["sender_count"] == 2


def test_terminal_color_passthrough():
    from postmortem import term
    term.set_enabled(False)
    assert term.c("hello", "red") == "hello"          # disabled -> plain
    term.set_enabled(True)
    colored = term.c("hello", "red")
    assert colored.startswith("\x1b[") and "hello" in colored and colored.endswith("\x1b[0m")
    term.set_enabled(False)  # restore default for other tests


# --------------------------------------------------------------------------
# geolocation / ASN / suspicious geography + entity graph
# --------------------------------------------------------------------------
def test_geoip_public_ip_extraction():
    from postmortem.geoip import _public_ips
    hops = [
        "from mx by acme; 1.2.3.4 Mon, 1 Jan 2026 10:00:00 +0000",  # public
        "from internal by mx; 10.0.0.5",                            # private
        "from x by y; 8.8.8.8",                                     # public
    ]
    ips = list(_public_ips(hops))
    assert "1.2.3.4" in ips and "8.8.8.8" in ips
    assert "10.0.0.5" not in ips


def test_geoip_annotation_with_fake_resolver():
    from postmortem.geoip import annotate_records

    class FakeResolver:
        def lookup(self, ip):
            if ip == "45.61.12.34":
                return {"country": "RU", "asn": "AS99",
                        "org": "FlokiNET Bulletproof"}
            return {"country": "US", "asn": "AS15169", "org": "Google LLC"}

    r = make_record(sender_email="a@ext.example", sender_domain="ext.example",
                    authentication_results={"received": [
                        "from x by y; 45.61.12.34 Mon, 1 Jan 2026 10:00:00 +0000"]})
    r.tier = 1
    from postmortem.config import CONFIG
    geo, host = annotate_records([r], FakeResolver(), ["US", "GB"],
                                 CONFIG["high_abuse_asn_keywords"])
    assert r.origin_country == "RU"
    assert r.suspicious_geo is True and geo == 1
    assert r.high_abuse_host is True and host == 1
    assert any("high-abuse" in i for i in r.indicators)


def test_geoip_extract_mmdb_from_tar():
    import io
    import tarfile
    from postmortem.geoip import _extract_mmdb
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        payload = b"\x00fake-mmdb-bytes"
        info = tarfile.TarInfo("GeoLite2-ASN_20260101/GeoLite2-ASN.mmdb")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    assert _extract_mmdb(buf.getvalue(), "GeoLite2-ASN") == b"\x00fake-mmdb-bytes"


def test_geoip_ensure_reuses_fresh_cache_no_network(tmp_path):
    # A fresh cached copy must be reused WITHOUT any download attempt, so this
    # runs fine offline even with a dummy key.
    from postmortem.geoip import ensure_databases
    (tmp_path / "GeoLite2-City.mmdb").write_bytes(b"city")
    (tmp_path / "GeoLite2-ASN.mmdb").write_bytes(b"asn")
    paths = ensure_databases("DUMMYKEY", tmp_path, max_age_days=999, verbose=False)
    assert {p.name for p in paths} == {"GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb"}


def test_entity_graph_builder():
    from postmortem.reporting import build_entity_graph
    a = make_record(sender_email="x@evil.example", sender_domain="evil.example",
                    url_domains=["bad.example"], campaign_id="CAMP-1")
    b = make_record(sender_email="y@evil.example", sender_domain="evil.example",
                    url_domains=["bad.example"], campaign_id="CAMP-1")
    g = build_entity_graph([a, b])
    ids = {n["id"] for n in g["nodes"]}
    assert "domain:evil.example" in ids and "camp:CAMP-1" in ids
    # the shared domain node connects both senders
    dom_links = [e for e in g["links"] if "domain:evil.example" in (e["source"], e["target"])]
    assert len(dom_links) >= 2


# --------------------------------------------------------------------------
# reporting polish: MITRE ATT&CK mapping + defanged preview
# --------------------------------------------------------------------------
def test_mitre_mapping_and_defang():
    from postmortem.reporting import mitre_for_record, mitre_summary, _defang
    r = make_record(subject="verify your password",
                    body="login at http://x.example/login",
                    urls=["http://x.example/login"], url_domains=["x.example"])
    calculate_score(r, {"acme.com"}, set())
    ids = {t["id"] for t in mitre_for_record(r)}
    assert "T1566" in ids          # phishing language
    assert "T1566.002" in ids      # spearphishing link (url category)
    summ = mitre_summary([r])
    assert any(t["id"] == "T1566" and t["messages"] == 1 for t in summ)

    d = _defang("mail bob@evil.com or visit http://evil.com/login")
    assert "http://" not in d and "hxxp" in d
    assert "@" not in d and "[at]" in d
    assert "evil[.]com" in d


# --------------------------------------------------------------------------
# allowlist (FP suppression) + anti-laundering
# --------------------------------------------------------------------------
def test_allowlist_suppresses_hygiene_but_not_spoofing():
    def partner(**kw):
        base = dict(sender_email="ap@partner.com", sender_domain="partner.com",
                    subject="invoice", body="see attached", date="",
                    authentication_results={"received": []})
        base.update(kw)
        return make_record(**base)

    # Without an allowlist a poorly-configured trusted partner is flagged.
    r = partner(message_id="<a@partner.com>")
    run_scenario_analysis([r], {"acme.com"}, Anchors(victim_domains=["acme.com"]))
    assert r.date_anomaly is True

    # Allowlisted + no spoofing signal => hygiene noise suppressed.
    r2 = partner(message_id="<a@partner.com>")
    run_scenario_analysis([r2], {"acme.com"}, Anchors(victim_domains=["acme.com"]),
                          allowlist=["partner.com"])
    assert r2.date_anomaly is False
    assert not any("Date header" in i for i in r2.indicators)

    # Anti-laundering: allowlisted BUT a spoofing signal is present (Message-ID
    # misaligned) => suppression is disabled; alignment always survives.
    r3 = partner(message_id="<x@evil.com>")
    run_scenario_analysis([r3], {"acme.com"}, Anchors(victim_domains=["acme.com"]),
                          allowlist=["partner.com"])
    assert r3.message_id_mismatch is True
    assert r3.date_anomaly is True


# --------------------------------------------------------------------------
# attachment magic-byte sniff (extension mismatch)
# --------------------------------------------------------------------------
def test_sniff_file_type():
    from postmortem.parsing import sniff_file_type
    assert sniff_file_type(b"MZ\x90\x00") == "pe_executable"
    assert sniff_file_type(b"\x7fELF\x02") == "elf_executable"
    assert sniff_file_type(b"%PDF-1.7") == "pdf"
    assert sniff_file_type(b"PK\x03\x04") == "zip"
    assert sniff_file_type(b"\x89PNG\r\n\x1a\n") == "png"
    assert sniff_file_type(b"#!/bin/sh\n") == "script"
    assert sniff_file_type(b"just some text") == ""


def test_attachment_extension_mismatch(tmp_path):
    p = write_eml(tmp_path / "m.eml", "a@ext.example", "invoice", "see attached",
                  attachments=[("invoice.pdf", b"MZ\x90\x00\x03fakeexe",
                                "application/pdf")])
    rec = parse_eml(p, deep=True)
    det = rec.attachment_details[0]
    assert det["ext_mismatch"] is True
    assert det["sniffed_type"] == "pe_executable"


# --------------------------------------------------------------------------
# detailed auth-results parsing (+ compauth)
# --------------------------------------------------------------------------
def test_detailed_auth_results_parsing():
    from postmortem.parsing import parse_authentication_results
    ar = ["mx.acme.com; spf=fail (acme.com: domain of x) smtp.mailfrom=evil.com; "
          "dkim=fail header.d=evil.com; dmarc=fail (p=REJECT) header.from=vendor.com; "
          "compauth=fail reason=001"]
    d = parse_authentication_results(ar)
    assert d["spf"]["result"] == "fail" and "smtp.mailfrom" in d["spf"]["reason"]
    assert d["dmarc"]["result"] == "fail" and "p=REJECT" in d["dmarc"]["reason"]
    assert d["compauth"]["result"] == "fail"


def test_compauth_fail_detected(tmp_path):
    p = write_eml(tmp_path / "c.eml", "a@ext.example", "hi", "body",
                  auth="mx.acme.com; compauth=fail reason=001")
    rec = parse_eml(p)
    assert rec.authentication_results["compauth_fail"] is True


# --------------------------------------------------------------------------
# CI gating: --fail-on-tier exit code
# --------------------------------------------------------------------------
def test_fail_on_tier_exit_code(tmp_path):
    import subprocess
    import os
    mb = tmp_path / "mb"
    mb.mkdir()
    write_eml(mb / "m.eml", "a@ext.example", "hello", "regular message")
    project_root = os.path.dirname(os.path.abspath(__file__))
    proc = subprocess.run(
        [sys.executable, "-m", "postmortem", str(mb), "--no-cache",
         "--fail-on-tier", "3"],
        capture_output=True, text=True, cwd=project_root,
    )
    assert proc.returncode == 3, proc.stderr
    # Without the flag, a clean scan still exits 0.
    proc0 = subprocess.run(
        [sys.executable, "-m", "postmortem", str(mb), "--no-cache"],
        capture_output=True, text=True, cwd=project_root,
    )
    assert proc0.returncode == 0, proc0.stderr


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
# device code flow phishing
# --------------------------------------------------------------------------
def _dcf_record(body, subject="Device setup", urls=None,
                sender_email="helpdesk@acme.com", sender_domain="acme.com"):
    r = make_record(sender_email=sender_email, sender_domain=sender_domain)
    r.subject = subject
    r.body = body
    r.urls = urls if urls is not None else []
    r.attachments = []
    r.authentication_results = {}
    return r


def _dcf_findings(record, internal=("acme.com",), contacts=()):
    calculate_score(record, set(internal), set(contacts))
    return [i for i in record.indicators
            if "device-login" in i.lower() or "device code flow" in i.lower()]


def test_device_code_lure_with_labelled_code_is_named_and_weighted():
    # The defining shape: Microsoft's own device-login URL plus a user code.
    # Every other defence passes by construction -- the link is genuinely
    # Microsoft's, there is no attachment, and the sender is often an already
    # compromised internal account -- so this pairing has to carry the weight
    # on its own.
    r = _dcf_record(
        "As part of our rollout you need to enrol this device.\n"
        "1. Go to https://microsoft.com/devicelogin\n"
        "2. Enter code G7QF-9K2M\n"
        "3. Sign in with your work account\n",
        subject="IT: enrol your device for the new security policy")
    found = _dcf_findings(r)
    assert found, "device-code lure was not detected"
    assert "G7QF-9K2M" in found[0]
    assert "deviceCodeFlow" in found[0], "finding must point at the Entra confirmation"

    # A message with the URL and a code must outrank the same message without
    # one; the pairing is the signal, not the URL.
    plain = _dcf_record("Please visit https://microsoft.com/devicelogin when you can.")
    calculate_score(plain, {"acme.com"}, set())
    assert r.score > plain.score


def test_device_code_lure_recognises_the_oauth_deviceauth_url():
    # The other common spelling: the tenant-scoped OAuth endpoint rather than
    # the short microsoft.com/devicelogin form.
    r = _dcf_record(
        "Please open\n"
        "https://login.microsoftonline.com/common/oauth2/deviceauth\n"
        "and enter the code HJ8KD2N4 to finish setup.\n",
        subject="Complete your Teams device setup")
    found = _dcf_findings(r)
    assert found, "oauth2/deviceauth URL was not recognised"
    assert "HJ8KD2N4" in found[0]

    # aka.ms is the third form attackers use.
    r2 = _dcf_record("Open https://aka.ms/devicelogin and enter BQ7X-T4RM.")
    assert _dcf_findings(r2)


def test_device_login_url_without_a_code_is_flagged_but_lower():
    # Attackers sometimes read the code out over the phone. The URL alone in
    # inbound mail is still worth an analyst's eye, but it is not the same
    # finding and must not carry the same weight.
    r = _dcf_record(
        "Open https://aka.ms/devicelogin and follow the instructions "
        "I gave you on the phone.\n")
    found = _dcf_findings(r)
    assert found
    assert "no user code" in found[0]

    coded = _dcf_record(
        "Open https://aka.ms/devicelogin and enter code G7QF-9K2M.\n")
    calculate_score(coded, {"acme.com"}, set())
    assert coded.score > r.score


def test_ordinary_mail_with_a_code_is_not_a_device_code_lure():
    # The code pattern is only ever consulted once a device-login URL is
    # present, so everyday messages that happen to contain a short uppercase
    # code must stay silent.
    notice = _dcf_record(
        "The all hands is Thursday at 10am.\n"
        "Building access code 4471 at the main door.\n",
        subject="Reminder: quarterly all hands")
    assert not _dcf_findings(notice)

    booking = _dcf_record(
        "Your booking is confirmed. Reference code XR42QM8B.\n"
        "Manage it at https://travel.example/bookings\n",
        subject="Booking confirmed",
        urls=["https://travel.example/bookings"])
    assert not _dcf_findings(booking)

    # A genuine Microsoft notification that names no device-login URL is not
    # a lure either.
    intune = _dcf_record(
        "Your device has been enrolled in Intune. No further action is needed.\n"
        "Manage your devices at https://portal.office.com/devices\n",
        subject="Your device enrollment is complete",
        sender_email="noreply@microsoft.com", sender_domain="microsoft.com",
        urls=["https://portal.office.com/devices"])
    assert not _dcf_findings(intune)


def test_device_code_lure_is_found_in_the_url_list_not_only_the_body():
    # HTML mail hides the href behind anchor text, so the extracted URL list
    # has to be searched as well as the visible text.
    r = _dcf_record(
        "Click here to enrol. Your code is G7QF-9K2M.\n",
        subject="Device enrolment",
        urls=["https://microsoft.com/devicelogin"])
    assert _dcf_findings(r)


# --------------------------------------------------------------------------
# report quality: evidence, noise and volume
#
# Every test here came from reading a real 117,300-message run and asking why
# a line in the report could not be checked or was not worth reading.
# --------------------------------------------------------------------------
def test_namespace_uris_are_not_counted_as_links():
    # Word and Outlook emit xmlns declarations and DTD references into almost
    # every HTML mail. They are identifiers, not destinations; counting them
    # inflated URL totals, the IOC export and the "contains N URL(s)" signal.
    from postmortem.urls import extract_urls, is_navigable

    markup = (
        '<html xmlns="http://www.w3.org/TR/REC-html40" '
        'xmlns:m="http://schemas.microsoft.com/office/2004/12/omml" '
        'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        'Please sign in at https://evil.example/login</html>'
    )
    assert extract_urls(markup) == ["https://evil.example/login"]

    # The opt-out still reports everything, for a caller that wants to know
    # what a document declared.
    assert len(extract_urls(markup, navigable_only=False)) == 4

    # Matching is on the hostname, not the registrable domain: the
    # registrable domain of schemas.microsoft.com is microsoft.com, and
    # filtering that would discard every genuine Microsoft link -- including
    # the device-login endpoints this tool exists to flag.
    assert not is_navigable("http://schemas.microsoft.com/office/2004/12/omml")
    assert is_navigable("https://microsoft.com/devicelogin")
    assert is_navigable("https://login.microsoftonline.com/common/oauth2/deviceauth")
    assert is_navigable("https://outlook.office.com/mail")


def test_base64_body_urls_ignore_encoded_attachments():
    # An Office attachment decodes to OOXML whose every namespace looked like
    # a URL the sender had hidden in the body -- worth +4 risk each, and the
    # largest single source of candidate promotions on a real corpus.
    import base64
    from postmortem.parsing import decode_base64_urls

    ooxml = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        b'xmlns:m="http://schemas.microsoft.com/office/2004/12/omml">'
        b'<w:body><w:p><w:t>Quarterly figures</w:t></w:p></w:body></w:document>'
    )
    blob = base64.b64encode(ooxml).decode()
    wrapped = "\n".join(blob[i:i + 76] for i in range(0, len(blob), 76))
    assert decode_base64_urls("Please see attached.\n\n" + wrapped) == []

    # A genuinely obfuscated link in body text is still recovered, and
    # recovered whole -- the old per-line match decoded from an arbitrary byte
    # offset and returned truncated hosts like "http://schemas.microsoft".
    hidden = base64.b64encode(
        b"Click through to https://credential-harvest.example/owa/signin to continue"
    ).decode()
    found = decode_base64_urls("Details below.\n" + hidden + "\nThanks")
    assert found == ["https://credential-harvest.example/owa/signin"]


def test_evidence_graph_keeps_only_meaningful_edges():
    # A chain linking every message to the next in date order restates the
    # sort N-1 times; a chain linking every message from one sender domain
    # links most of the corpus. Neither can distinguish anything.
    from postmortem.scoring import build_evidence_graph

    recs = []
    for i in range(4):
        r = make_record(sender_email="a@same.example", sender_domain="same.example",
                        date="Mon, 1%d Jan 2025 09:00:00 -0500" % i,
                        path="/m/%d.eml" % i)
        r.url_analysis = []
        r.attachment_details = []
        recs.append(r)

    graph = build_evidence_graph(recs)
    assert len(graph["nodes"]) == 4
    relations = {e["relation"] for e in graph["edges"]}
    assert "temporal_sequence" not in relations
    assert "sender_domain" not in relations
    assert graph["edges"] == []

    # A shared attachment hash still links them, because that means something.
    for r in recs[:2]:
        r.attachment_details = [{"sha256": "deadbeef", "filename": "inv.docx"}]
    graph = build_evidence_graph(recs)
    assert {e["relation"] for e in graph["edges"]} == {"attachment_sha256"}
    assert len(graph["edges"]) == 1


def test_initial_email_findings_carry_their_evidence():
    # The report said "Display-name impersonation of a known contact" without
    # naming either address, and "Link to a credential/login page" without the
    # link. Both are unverifiable as written.
    from postmortem.scoring import score_initial_email
    from postmortem.models import Anchors

    r = make_record(sender_email="dana.w@acrne-corp.example",
                    sender_domain="acrne-corp.example")
    r.sender_name = "Dana Whitfield"
    r.subject = "Action required: verify your account"
    r.body = ("Your password expires today. Verify your account at "
              "https://acrne-corp.example/owa/login/verify?id=77")
    r.urls = ["https://acrne-corp.example/owa/login/verify?id=77"]
    r.url_analysis = [{"url": "https://acrne-corp.example/owa/login/verify?id=77",
                       "path": "/owa/login/verify", "suspicious_score": 12,
                       "registrable_domain": "acrne-corp.example"}]
    r.attachments = []
    r.attachment_details = []
    r.authentication_results = {}
    r.display_name_spoof = True
    r.display_name_spoof_of = ["dana.whitfield@acme.com"]

    score_initial_email(r, "ato", Anchors())
    assert r.scenario_score > 0
    by_signal = {f["signal"]: f for f in r.scenario_findings}

    # Every reason must have a finding; none may be evidence-free filler.
    assert set(r.scenario_reasons) <= set(by_signal)

    spoof = by_signal["Display-name impersonation of a known contact"]
    assert "dana.whitfield@acme.com" in spoof["matched"], "legitimate address missing"
    assert "dana.w@acrne-corp.example" in spoof["matched"], "spoofing address missing"

    link = by_signal["Link to a credential/login page"]
    assert link["matched"] == "https://acrne-corp.example/owa/login/verify?id=77"

    lure = by_signal["Credential-harvest lure language"]
    assert "verify your account" in lure["matched"]


def test_display_name_spoof_records_who_was_impersonated():
    # The detection knew the legitimate address and threw it away for a bool,
    # so the report could say a name was impersonated but never show the
    # substitution. Driven through the real pipeline entry point.
    from postmortem.scoring import run_scenario_analysis
    from postmortem.models import Anchors

    def msg(addr, name, path, day):
        r = make_record(sender_email=addr, sender_domain=addr.split("@")[1],
                        path=path,
                        date="Mon, 1%d Aug 2026 09:00:00 +0000" % day)
        r.sender_name = name
        r.subject = "Weekly numbers"
        r.body = "Figures attached as usual."
        r.urls = []
        r.url_analysis = []
        r.attachments = []
        r.attachment_details = []
        r.authentication_results = {}
        return r

    recs = [msg("dana.whitfield@acme.com", "Dana Whitfield", "/m/%d.eml" % i, i)
            for i in range(3)]
    imposter = msg("dana.w@acrne-corp.example", "Dana Whitfield", "/m/x.eml", 5)
    imposter.subject = "Action required: verify your account"
    imposter.body = "Verify your account to avoid interruption."
    recs.append(imposter)

    run_scenario_analysis(recs, {"acme.com"}, Anchors())

    assert imposter.display_name_spoof is True
    assert "dana.whitfield@acme.com" in imposter.display_name_spoof_of

    # And the evidence reaches the finding, in both-addresses form.
    spoof = [f for f in imposter.scenario_findings
             if "Display-name impersonation" in f["signal"]]
    assert spoof, "no display-name finding produced"
    assert "dana.whitfield@acme.com" in spoof[0]["matched"]
    assert "dana.w@acrne-corp.example" in spoof[0]["matched"]

    # The genuine sender is not accused of impersonating themselves.
    assert all(not r.display_name_spoof for r in recs[:3])


def test_low_confidence_clusters_are_not_reported_but_are_kept():
    # 3,506 "campaigns" on a real corpus, because any two messages over the
    # similarity threshold became one. Gating what is *reported* must not
    # change what is *computed* -- the per-message campaign columns and the
    # JSON stay complete.
    from postmortem.clustering import build_campaign_clusters

    recs = []
    for i in range(6):
        r = make_record(sender_email="s%d@ext.example" % i,
                        sender_domain="ext.example",
                        subject="Invoice %d attached" % i,
                        path="/m/%d.eml" % i)
        r.body = "Please find the invoice attached and remit payment."
        r.urls = []
        r.url_domains = []
        r.url_analysis = []
        r.attachments = []
        r.attachment_details = []
        r.authentication_results = {}
        recs.append(r)

    campaigns = build_campaign_clusters(recs)
    # Nothing here shares a URL domain or an attachment hash, so nothing is
    # worth putting in front of an analyst.
    assert all(c.reportable is False for c in campaigns), \
        [c.campaign_id for c in campaigns if c.reportable]
    # But the clusters still exist and members are still stamped.
    assert build_campaign_clusters.last_suppressed == len(campaigns)
    if campaigns:
        assert any(r.campaign_id for r in recs)


# --------------------------------------------------------------------------
# E8: the audit export's own coverage
#
# A conclusion drawn from an audit log is bounded by that log. These lock down
# that the run says where that boundary is, rather than reporting the earliest
# attacker action it happens to see as though it were the start of the attack.
# --------------------------------------------------------------------------
def _ual(tmp_path, events, name="ual.json"):
    import json
    p = tmp_path / name
    p.write_text(json.dumps(events), encoding="utf-8")
    return str(p)


def _ev(op, when, ip="203.0.113.9", user="victim@acme.com", **extra):
    d = {"Operation": op, "UserId": user, "ClientIP": ip}
    if when:
        d["CreationTime"] = when
    d.update(extra)
    return d


_RULE_PARAMS = [{"Name": "SubjectContainsWords", "Value": "invoice"},
                {"Name": "DeleteMessage", "Value": "True"}]


def test_audit_coverage_reports_range_and_operations(tmp_path):
    from postmortem.auditlog import analyze_audit_log

    events = [_ev("UserLoggedIn", "2026-08-01T09:00:00"),
              _ev("HardDelete", "2026-08-05T10:00:00"),
              _ev("HardDelete", "2026-08-09T10:00:00"),
              _ev("MailItemsAccessed", "2026-08-11T10:00:00"),
              _ev("Set-Mailbox", None)]  # no timestamp at all
    summary = analyze_audit_log(_ual(tmp_path, events))
    cov = summary["coverage"]

    assert cov["first_event"].startswith("2026-08-01")
    assert cov["last_event"].startswith("2026-08-11")
    assert cov["span_days"] == 10
    assert cov["events_parsed"] == 5
    assert cov["events_without_timestamp"] == 1
    # The histogram is what tells an analyst the export was scoped to the wrong
    # operations -- a log with no HardDelete cannot speak to deletions.
    assert dict(cov["operations"])["HardDelete"] == 2
    assert cov["distinct_operations"] == 4
    assert cov["mailboxes"] == 1


def test_corpus_older_than_the_log_is_a_high_severity_gap(tmp_path):
    # The failure mode that silently invalidates an entry-point finding: the
    # export starts after the corpus does, so "nothing before X" is a property
    # of the export rather than of the intrusion.
    from datetime import datetime, timezone
    from postmortem.auditlog import analyze_audit_log, coverage_warnings

    summary = analyze_audit_log(_ual(tmp_path, [
        _ev("UserLoggedIn", "2026-08-25T09:00:00"),
        _ev("HardDelete", "2026-08-27T09:00:00"),
    ]))
    warns = coverage_warnings(
        summary,
        corpus_first=datetime(2026, 5, 20, tzinfo=timezone.utc),
        corpus_last=datetime(2026, 9, 8, tzinfo=timezone.utc),
    )
    gap = [w for w in warns
           if w["severity"] == "high" and "before the audit log" in w["text"]]
    assert gap, [w["text"] for w in warns]
    assert "97 day(s)" in gap[0]["text"]
    assert "not evidence of absence" in gap[0]["text"]

    tail = [w for w in warns if "ends" in w["text"] and "before the corpus" in w["text"]]
    assert tail and tail[0]["severity"] == "medium"

    # A log that comfortably brackets the corpus raises neither.
    clean = coverage_warnings(
        summary,
        corpus_first=datetime(2026, 8, 26, tzinfo=timezone.utc),
        corpus_last=datetime(2026, 8, 26, tzinfo=timezone.utc),
    )
    assert not [w for w in clean if "before the audit log" in w["text"]]
    assert not [w for w in clean if "before the corpus" in w["text"]]


def test_compromise_on_the_first_day_of_the_export_is_flagged(tmp_path):
    # The most misleading output the tool can produce: a compromise date that
    # is really just where the export begins. It looks identical to a finding.
    from postmortem.auditlog import analyze_audit_log, coverage_warnings

    summary = analyze_audit_log(_ual(tmp_path, [
        _ev("New-InboxRule", "2026-08-25T15:54:33", Parameters=_RULE_PARAMS),
        _ev("HardDelete", "2026-09-10T09:00:00"),
    ]))
    assert summary["derived"]["compromise_date"].startswith("2026-08-25")

    warns = coverage_warnings(summary)
    lower = [w for w in warns if "lower bound set by the export" in w["text"]]
    assert lower and lower[0]["severity"] == "high"

    # Push the same rule well inside the export and the warning goes away --
    # the date is then a finding, not an artifact.
    later = analyze_audit_log(_ual(tmp_path, [
        _ev("UserLoggedIn", "2026-07-01T09:00:00", ip="198.51.100.1"),
        _ev("New-InboxRule", "2026-08-25T15:54:33", Parameters=_RULE_PARAMS),
    ], name="later.json"))
    assert not [w for w in coverage_warnings(later)
                if "lower bound set by the export" in w["text"]]


def test_lookback_longer_than_the_log_is_reported(tmp_path):
    from postmortem.auditlog import analyze_audit_log, coverage_warnings

    summary = analyze_audit_log(_ual(tmp_path, [
        _ev("UserLoggedIn", "2026-08-25T09:00:00"),
        _ev("HardDelete", "2026-08-30T09:00:00"),
    ]))
    warns = coverage_warnings(summary, lookback_days=90)
    hit = [w for w in warns if "reaches back 90 days" in w["text"]]
    assert hit, [w["text"] for w in warns]
    assert "spans only 5" in hit[0]["text"]

    # A log longer than the window is not worth a warning.
    assert not [w for w in coverage_warnings(summary, lookback_days=3)
                if "reaches back" in w["text"]]


def test_empty_and_undated_exports_say_so(tmp_path):
    from postmortem.auditlog import analyze_audit_log, coverage_warnings

    empty = analyze_audit_log(_ual(tmp_path, [], name="empty.json"))
    assert [w for w in coverage_warnings(empty) if w["severity"] == "high"]

    undated = analyze_audit_log(_ual(tmp_path, [
        _ev("UserLoggedIn", None), _ev("HardDelete", None),
    ], name="undated.json"))
    warns = coverage_warnings(undated)
    assert warns and warns[0]["severity"] == "high"
    assert "no compromise date can be derived" in warns[0]["text"]


def test_manifest_carries_audit_provenance_and_stays_serialisable(tmp_path):
    # The review's point: for a tool that emits a chain-of-custody manifest,
    # the provenance of the audit evidence belongs in it. And the manifest is
    # written to JSON, so the private datetimes must not leak into it.
    import json
    from types import SimpleNamespace
    from postmortem.auditlog import analyze_audit_log, coverage_warnings
    from postmortem.reporting import build_run_manifest
    from postmortem.models import Anchors

    summary = analyze_audit_log(_ual(tmp_path, [
        _ev("New-InboxRule", "2026-08-25T15:54:33", Parameters=_RULE_PARAMS),
        _ev("HardDelete", "2026-08-27T09:00:00"),
    ]))
    summary["coverage_warnings"] = coverage_warnings(summary)
    summary.pop("_compromise_dt", None)
    for k in ("_first_dt", "_last_dt"):
        summary["coverage"].pop(k, None)

    args = SimpleNamespace(directory=str(tmp_path), audit_log="ual.json",
                           lookback_days=90)
    recs = [make_record(path="/m/1.eml")]
    m = build_run_manifest(args, recs, "ato", Anchors(), {}, [], [],
                           generated_utc="2026-09-11T00:00:00Z",
                           elapsed_seconds=1.0, audit_summary=summary)

    a = m["audit_log"]
    assert a["supplied"] is True
    assert a["coverage"]["events_parsed"] == 2
    assert a["coverage"]["first_event"].startswith("2026-08-25")
    assert isinstance(a["warnings"], list)
    json.dumps(m["audit_log"])  # must not raise on a datetime

    # And a run with no audit log says so rather than staying silent, because
    # "no confirmed attacker action" means something different without a log.
    bare = build_run_manifest(
        SimpleNamespace(directory=str(tmp_path), audit_log="", lookback_days=None),
        recs, "ato", Anchors(), {}, [], [],
        generated_utc="2026-09-11T00:00:00Z", elapsed_seconds=1.0,
        audit_summary=None)
    assert bare["audit_log"]["supplied"] is False


# --------------------------------------------------------------------------
# E2: joining audit events to the messages they touched
#
# Every other signal in this tool infers from what a message says. These are
# the only ones that record what was done to it.
# --------------------------------------------------------------------------
ATTACKER_IP = "37.19.210.182"
OWNER_IP = "203.0.113.10"


def _rule_event(when="2026-08-25T15:54:33"):
    return {"CreationTime": when, "Operation": "New-InboxRule",
            "UserId": "victim@acme.com", "ClientIP": ATTACKER_IP,
            "Parameters": [{"Name": "SubjectContainsWords", "Value": "remittance"},
                           {"Name": "DeleteMessage", "Value": "True"}]}


def _audit(tmp_path, events, name="ual.json"):
    import json
    p = tmp_path / name
    p.write_text(json.dumps([_rule_event()] + events), encoding="utf-8")
    from postmortem.auditlog import analyze_audit_log
    return analyze_audit_log(str(p))


def test_message_ids_are_found_in_every_audit_shape(tmp_path):
    # The id sits somewhere different for each operation family, and Microsoft
    # has added shapes over time, so the walk must not depend on the layout.
    summary = _audit(tmp_path, [
        # AffectedItems[] -- deletes and moves
        {"CreationTime": "2026-08-25T16:00:00", "Operation": "HardDelete",
         "UserId": "victim@acme.com", "ClientIP": ATTACKER_IP,
         "AffectedItems": [{"InternetMessageId": "<a@x.example>",
                            "Subject": "Remittance",
                            "ParentFolder": {"Path": "\\Inbox"}}]},
        # Folders[].FolderItems[] -- MailItemsAccessed
        {"CreationTime": "2026-08-25T16:01:00", "Operation": "MailItemsAccessed",
         "UserId": "victim@acme.com", "ClientIP": ATTACKER_IP,
         "Folders": [{"Path": "\\Inbox",
                      "FolderItems": [{"InternetMessageId": "<b@x.example>"}]}]},
        # Item{} -- sends and binds
        {"CreationTime": "2026-08-25T16:02:00", "Operation": "Send",
         "UserId": "victim@acme.com", "ClientIP": ATTACKER_IP,
         "Item": {"InternetMessageId": "<c@x.example>", "Subject": "Invoice"}},
    ])
    idx = summary["message_index"]
    assert idx["messages_referenced"] == 3
    assert idx["events_with_message_id"] == 3
    by_id = idx["by_message_id"]
    assert set(by_id) == {"<a@x.example>", "<b@x.example>", "<c@x.example>"}

    # Context is carried through, and the deliberate/read split is recorded.
    deleted = by_id["<a@x.example>"][0]
    assert deleted["verb"] == "hard-deleted"
    assert deleted["by_attacker"] is True
    assert deleted["deliberate"] is True
    assert deleted["folder"] == "\\Inbox"
    assert by_id["<b@x.example>"][0]["deliberate"] is False   # a read
    assert by_id["<c@x.example>"][0]["deliberate"] is True    # a send


def test_a_bland_message_the_attacker_deleted_becomes_tier_one(tmp_path):
    # The case E2 exists for. This message has no lure language, no bad URL and
    # no attachment -- it scores almost nothing and would previously have sat
    # in Tier 3 forever. The audit log records the attacker hard-deleting it,
    # which is worth more than anything its wording could have said.
    from postmortem.scoring import run_scenario_analysis
    from postmortem.models import Anchors

    bland = make_record(sender_email="ap@supplier.example",
                        sender_domain="supplier.example",
                        subject="Remittance advice 88214",
                        path="/m/bland.eml",
                        date="Wed, 12 Aug 2026 09:00:00 +0000")
    bland.body = "Please see the remittance advice for last month."
    bland.message_id = "<bland-002@supplier.example>"
    for r in (bland,):
        r.urls = []; r.url_analysis = []; r.attachments = []
        r.attachment_details = []; r.authentication_results = {}

    summary = _audit(tmp_path, [
        {"CreationTime": "2026-08-25T16:32:44", "Operation": "HardDelete",
         "UserId": "victim@acme.com", "ClientIP": ATTACKER_IP,
         "AffectedItems": [{"InternetMessageId": "<bland-002@supplier.example>",
                            "ParentFolder": {"Path": "\\Inbox"}}]},
    ])
    anchors = Anchors()
    anchors.compromise_date = summary["_compromise_dt"]

    _s, _r, verdict = run_scenario_analysis(
        [bland], {"acme.com"}, anchors, summary)

    assert bland.audit_confirmed is True
    assert bland.tier == 1, "a recorded attacker deletion must reach Tier 1"

    # And it says what it knows, with the operation, time and address.
    finding = [f for f in bland.provenance if f["category"] == "audit"]
    assert finding, [i for i in bland.indicators]
    assert "hard-deleted by the attacker" in finding[0]["signal"]
    assert ATTACKER_IP in finding[0]["signal"]
    # An audit event is evidence, not a heuristic: it must not move the score.
    assert finding[0]["weight"] == 0

    join = verdict["audit_join"]
    assert join["matched"] == 1 and join["confirmed"] == 1


def test_being_seen_in_a_sync_does_not_reach_tier_one(tmp_path):
    # One MailItemsAccessed sync record can name every item in a folder, so
    # treating a read as targeting would promote whole mailboxes to Tier 1.
    from postmortem.scoring import run_scenario_analysis
    from postmortem.models import Anchors

    recs = []
    for i in range(3):
        r = make_record(sender_email="s%d@ext.example" % i,
                        sender_domain="ext.example",
                        subject="Monthly statement %d" % i,
                        path="/m/%d.eml" % i,
                        date="Wed, 12 Aug 2026 09:00:00 +0000")
        r.body = "Statement attached."
        r.message_id = "<seen-%d@ext.example>" % i
        r.urls = []; r.url_analysis = []; r.attachments = []
        r.attachment_details = []; r.authentication_results = {}
        recs.append(r)

    summary = _audit(tmp_path, [
        {"CreationTime": "2026-08-25T16:01:00", "Operation": "MailItemsAccessed",
         "UserId": "victim@acme.com", "ClientIP": ATTACKER_IP,
         "Folders": [{"Path": "\\Inbox", "FolderItems": [
             {"InternetMessageId": "<seen-%d@ext.example>" % i}
             for i in range(3)]}]},
    ])
    anchors = Anchors()
    anchors.compromise_date = summary["_compromise_dt"]
    _s, _r, verdict = run_scenario_analysis(recs, {"acme.com"}, anchors, summary)

    assert all(r.audit_confirmed is False for r in recs)
    assert all(r.audit_attacker_read is True for r in recs)
    assert all(r.tier == 2 for r in recs), [r.tier for r in recs]
    assert verdict["audit_join"]["confirmed"] == 0
    assert verdict["audit_join"]["read_only"] == 3


def test_the_owners_own_actions_do_not_promote(tmp_path):
    # A user reading and deleting their own mail is the most ordinary thing in
    # a mailbox. It is attached as context and nothing more.
    from postmortem.scoring import run_scenario_analysis
    from postmortem.models import Anchors

    r = make_record(sender_email="news@list.example", sender_domain="list.example",
                    subject="Weekly digest", path="/m/own.eml",
                    date="Wed, 12 Aug 2026 09:00:00 +0000")
    r.body = "This week's digest."
    r.message_id = "<own-1@list.example>"
    r.urls = []; r.url_analysis = []; r.attachments = []
    r.attachment_details = []; r.authentication_results = {}

    summary = _audit(tmp_path, [
        {"CreationTime": "2026-08-21T08:15:00", "Operation": "HardDelete",
         "UserId": "victim@acme.com", "ClientIP": OWNER_IP,
         "AffectedItems": [{"InternetMessageId": "<own-1@list.example>"}]},
    ])
    anchors = Anchors()
    anchors.compromise_date = summary["_compromise_dt"]
    run_scenario_analysis([r], {"acme.com"}, anchors, summary)

    assert r.audit_confirmed is False
    assert r.audit_attacker_read is False
    assert r.tier == 3
    # The event is still recorded -- it is evidence of what happened, just not
    # evidence against anyone.
    audit = [f for f in r.provenance if f["category"] == "audit"]
    assert audit and "victim@acme.com" in audit[0]["signal"]
    assert audit[0]["severity"] == "low"


def test_a_high_scoring_message_is_never_demoted_by_being_read(tmp_path):
    # The Tier 2 floor must only lift; a message that earned Tier 1 on its own
    # signals keeps it.
    from postmortem.scoring import run_scenario_analysis
    from postmortem.models import Anchors

    phish = make_record(sender_email="it@acrne-secure.example",
                        sender_domain="acrne-secure.example",
                        subject="Verify your account now",
                        path="/m/phish.eml",
                        date="Wed, 20 Aug 2026 09:00:00 +0000")
    phish.body = ("Your password expires today. Verify your account at "
                  "https://acrne-secure.example/owa/login and sign in.")
    phish.message_id = "<phish-3@acrne-secure.example>"
    phish.urls = ["https://acrne-secure.example/owa/login"]
    phish.url_analysis = [{"url": "https://acrne-secure.example/owa/login",
                           "path": "/owa/login", "suspicious_score": 12,
                           "registrable_domain": "acrne-secure.example"}]
    phish.attachments = []; phish.attachment_details = []
    phish.authentication_results = {}

    summary = _audit(tmp_path, [
        {"CreationTime": "2026-08-25T16:01:00", "Operation": "MailItemsAccessed",
         "UserId": "victim@acme.com", "ClientIP": ATTACKER_IP,
         "Folders": [{"Path": "\\Inbox", "FolderItems": [
             {"InternetMessageId": "<phish-3@acrne-secure.example>"}]}]},
    ])
    anchors = Anchors()
    anchors.compromise_date = summary["_compromise_dt"]
    run_scenario_analysis([phish], {"acme.com"}, anchors, summary)

    assert phish.audit_attacker_read is True
    assert phish.tier == 1, "the read floor must not demote an earned Tier 1"


def test_no_audit_log_changes_nothing(tmp_path):
    # The join must be inert when there is no log, so every existing run keeps
    # behaving exactly as before.
    from postmortem.scoring import run_scenario_analysis, attach_audit_events
    from postmortem.models import Anchors

    r = make_record(sender_email="a@ext.example", sender_domain="ext.example",
                    path="/m/1.eml")
    r.body = "Hello."
    r.message_id = "<x@ext.example>"
    r.urls = []; r.url_analysis = []; r.attachments = []
    r.attachment_details = []; r.authentication_results = {}

    assert attach_audit_events([r], None) == {
        "matched": 0, "confirmed": 0, "events": 0}
    assert attach_audit_events([r], {}) == {
        "matched": 0, "confirmed": 0, "events": 0}

    _s, _rsn, verdict = run_scenario_analysis([r], {"acme.com"}, Anchors(), None)
    assert r.audit_confirmed is False
    assert not r.audit_events
    assert verdict["audit_join"]["matched"] == 0


# --------------------------------------------------------------------------
# E5: what is missing from the corpus
#
# Every other section of the report describes messages that are present. These
# describe messages that are not, which the message-only pipeline has no way
# to notice: a hard-deleted item is simply absent from the PST.
# --------------------------------------------------------------------------
def _del_event(mid, subject, when, ip, op="HardDelete"):
    return {"CreationTime": when, "Operation": op, "UserId": "victim@acme.com",
            "ClientIP": ip,
            "AffectedItems": [{"InternetMessageId": mid, "Subject": subject,
                               "ParentFolder": {"Path": "\\Inbox"}}]}


def _corpus_record(mid, subject="Kept", path=None):
    r = make_record(sender_email="ap@supplier.example",
                    sender_domain="supplier.example",
                    subject=subject,
                    path=path or ("/m/%s.eml" % abs(hash(mid))),
                    date="Wed, 12 Aug 2026 09:00:00 +0000")
    r.body = "Body text."
    r.message_id = mid
    r.urls = []; r.url_analysis = []; r.attachments = []
    r.attachment_details = []; r.authentication_results = {}
    return r


def test_deleted_messages_absent_from_the_corpus_are_named(tmp_path):
    # The finding E5 exists for: the attacker destroyed three messages, they
    # are not in the export, and the only surviving record of them is what the
    # audit log retained -- which includes the subjects, and the subjects are
    # usually the whole point.
    from postmortem.scoring import deletion_completeness

    summary = _audit(tmp_path, [
        _del_event("<gone-1@bank.example>", "Updated bank details",
                   "2026-08-25T16:10:00", ATTACKER_IP),
        _del_event("<gone-2@bank.example>", "RE: Updated bank details",
                   "2026-08-25T16:11:00", ATTACKER_IP),
        _del_event("<gone-3@partner.example>", "Wire confirmation 44812",
                   "2026-08-25T16:12:00", ATTACKER_IP),
        # deleted by the owner, also absent -- ordinary housekeeping
        _del_event("<gone-4@news.example>", "Weekly digest",
                   "2026-08-01T08:00:00", OWNER_IP, op="SoftDelete"),
        # deleted, but the export was taken first so it is still here
        _del_event("<keep-2@supplier.example>", "Remittance advice",
                   "2026-08-26T09:00:00", ATTACKER_IP),
    ])
    records = [_corpus_record("<keep-1@supplier.example>"),
               _corpus_record("<keep-2@supplier.example>")]

    c = deletion_completeness(records, summary)
    assert c["reliable"] is True
    assert c["deleted_total"] == 5
    assert c["deleted_still_present"] == 1
    assert c["deleted_absent"] == 4
    assert c["deleted_absent_by_attacker"] == 3

    # Attacker deletions sort first: they are the ones worth reading.
    assert c["absent"][0]["by_attacker"] is True
    subjects = [e["subject"] for e in c["absent"]]
    assert "Updated bank details" in subjects
    assert "Wire confirmation 44812" in subjects

    # The surviving one is not reported as missing.
    assert all(e["message_id"] != "<keep-2@supplier.example>"
               for e in c["absent"])
    assert c["recovered"][0]["message_id"] == "<keep-2@supplier.example>"


def test_a_log_for_another_mailbox_makes_no_completeness_claim(tmp_path):
    # Without this guard the tool would report every message the log names as
    # missing -- a large, alarming and entirely meaningless number whenever
    # the log and the export do not correspond.
    from postmortem.scoring import deletion_completeness

    # The realistic form of the mistake: the log was exported for a different
    # user than the mailbox that was collected.
    other = []
    for mid, subj in (("<x-1@other.example>", "Something"),
                      ("<x-2@other.example>", "Something else")):
        e = _del_event(mid, subj, "2026-08-25T16:10:00", ATTACKER_IP)
        e["UserId"] = "someone.else@acme.com"
        other.append(e)
    summary = _audit(tmp_path, other)
    records = [_corpus_record("<unrelated@supplier.example>")]

    c = deletion_completeness(records, summary)
    assert c["reliable"] is False
    assert c["same_mailbox"] is False
    assert c["named_and_present"] == 0
    assert c["messages_named_by_log"] == 2

    # And the manifest refuses to assert completeness on that basis.
    from postmortem.reporting import _completeness_block
    block = _completeness_block(c)
    assert block["assessed"] is False
    assert "do not correspond" in block["note"]


def test_zero_overlap_is_still_reliable_when_the_mailbox_matches(tmp_path):
    # The case E5 exists for: the attacker destroyed every message the log
    # names, so NOTHING the log references survives in the corpus. Judging
    # correspondence by overlap would suppress the finding precisely here.
    from postmortem.scoring import deletion_completeness

    summary = _audit(tmp_path, [
        _del_event("<gone-1@bank.example>", "Updated bank details",
                   "2026-08-25T16:10:00", ATTACKER_IP),
        _del_event("<gone-2@bank.example>", "Wire confirmation",
                   "2026-08-25T16:11:00", ATTACKER_IP),
    ])
    # The log's UserId is victim@acme.com, which is this corpus's recipient.
    records = [_corpus_record("<survivor@supplier.example>")]

    c = deletion_completeness(records, summary)
    assert c["named_and_present"] == 0
    assert c["same_mailbox"] is True
    assert c["reliable"] is True, "same mailbox, so absence is a real finding"
    assert c["deleted_absent"] == 2
    assert c["deleted_absent_by_attacker"] == 2


def test_moves_within_the_mailbox_are_not_deletions(tmp_path):
    # A message moved to another folder is still in the export. Counting it as
    # missing would overstate the gap.
    from postmortem.scoring import deletion_completeness

    summary = _audit(tmp_path, [
        {"CreationTime": "2026-08-25T16:00:00", "Operation": "MoveToFolder",
         "UserId": "victim@acme.com", "ClientIP": ATTACKER_IP,
         "AffectedItems": [{"InternetMessageId": "<moved@supplier.example>",
                            "Subject": "Invoice"}]},
        _del_event("<gone@supplier.example>", "Invoice 2",
                   "2026-08-25T16:05:00", ATTACKER_IP),
    ])
    c = deletion_completeness([_corpus_record("<keep@supplier.example>")], summary)
    assert c["deleted_total"] == 1
    assert [e["message_id"] for e in c["absent"]] == ["<gone@supplier.example>"]


def test_complete_corpus_says_so(tmp_path):
    # Stating that nothing is missing is as much a completeness claim as
    # stating that something is, and the manifest should carry it either way.
    from postmortem.scoring import deletion_completeness
    from postmortem.reporting import _completeness_block

    summary = _audit(tmp_path, [
        _del_event("<here@supplier.example>", "Statement",
                   "2026-08-26T09:00:00", ATTACKER_IP),
    ])
    c = deletion_completeness([_corpus_record("<here@supplier.example>")], summary)
    assert c["reliable"] is True
    assert c["deleted_absent"] == 0
    assert c["deleted_still_present"] == 1

    block = _completeness_block(c)
    assert block["assessed"] is True
    assert block["deleted_absent"] == 0


def test_no_audit_log_means_completeness_is_unassessed(tmp_path):
    # The honest answer without a log is "cannot be assessed", not "complete".
    from postmortem.scoring import deletion_completeness
    from postmortem.reporting import _completeness_block

    assert deletion_completeness([_corpus_record("<a@b.example>")], None) == {}
    assert deletion_completeness([_corpus_record("<a@b.example>")], {}) == {}

    block = _completeness_block(None)
    assert block["assessed"] is False
    assert "cannot be assessed" in block["note"]


def test_completeness_reaches_the_manifest(tmp_path):
    import json
    from types import SimpleNamespace
    from postmortem.scoring import deletion_completeness
    from postmortem.reporting import build_run_manifest
    from postmortem.models import Anchors

    summary = _audit(tmp_path, [
        _del_event("<gone@bank.example>", "Updated bank details",
                   "2026-08-25T16:10:00", ATTACKER_IP),
    ])
    records = [_corpus_record("<keep@supplier.example>")]
    c = deletion_completeness(records, summary)

    args = SimpleNamespace(directory=str(tmp_path), audit_log="ual.json",
                           lookback_days=90)
    m = build_run_manifest(args, records, "ato", Anchors(), {}, [], [],
                           generated_utc="2026-09-11T00:00:00Z",
                           elapsed_seconds=1.0, audit_summary=summary,
                           completeness=c)
    cc = m["corpus_completeness"]
    assert cc["assessed"] is True
    assert cc["deleted_absent"] == 1
    assert cc["deleted_absent_by_attacker"] == 1
    # The ids are recorded so a later reader knows exactly what was never seen.
    assert cc["absent_items"][0]["message_id"] == "<gone@bank.example>"
    json.dumps(m["corpus_completeness"])


# --------------------------------------------------------------------------
# E3 / E4 / E6 / E9: the rest of what the audit log knows
# --------------------------------------------------------------------------
def _rule_with(words, field="SubjectContainsWords", when="2026-08-25T15:54:33"):
    return {"CreationTime": when, "Operation": "New-InboxRule",
            "UserId": "victim@acme.com", "ClientIP": ATTACKER_IP,
            "Parameters": [{"Name": field, "Value": words},
                           {"Name": "DeleteMessage", "Value": "True"}]}


def _mail(mid, subject, day, sender="ap@supplier.example", body="Body."):
    r = make_record(sender_email=sender, sender_domain=sender.split("@")[1],
                    subject=subject, path="/m/%s.eml" % abs(hash(mid)),
                    date="Wed, %02d Aug 2026 09:00:00 +0000" % day)
    r.body = body
    r.message_id = mid
    r.urls = []; r.url_analysis = []; r.attachments = []
    r.attachment_details = []; r.authentication_results = {}
    return r


# ---- E3 -------------------------------------------------------------------
def test_sends_from_an_attacker_address_are_confirmed_authorship(tmp_path):
    # B1 infers a mass-mail burst from repeated body text. This is the case the
    # heuristic cannot see: an attacker who varied the wording leaves no
    # repetition, but every message they sent is named in the log.
    from postmortem.auditlog import analyze_audit_log
    from postmortem.scoring import attacker_authorship
    from postmortem.models import Anchors

    p = tmp_path / "ual.json"
    p.write_text(json.dumps([
        _rule_with("invoice"),
        {"CreationTime": "2026-08-26T09:10:00", "Operation": "Send",
         "UserId": "victim@acme.com", "ClientIP": ATTACKER_IP,
         "Item": {"InternetMessageId": "<out-1@acme.com>",
                  "Subject": "Updated remittance instructions"}},
        # the owner sending their own mail is not attacker authorship
        {"CreationTime": "2026-08-20T09:00:00", "Operation": "Send",
         "UserId": "victim@acme.com", "ClientIP": OWNER_IP,
         "Item": {"InternetMessageId": "<own-1@acme.com>", "Subject": "Lunch"}},
    ]), encoding="utf-8")
    summary = analyze_audit_log(str(p))

    sent = _mail("<out-1@acme.com>", "Updated remittance instructions", 26,
                 sender="victim@acme.com")
    own = _mail("<own-1@acme.com>", "Lunch", 20, sender="victim@acme.com")

    anchors = Anchors()
    anchors.compromise_date = summary["_compromise_dt"]
    a = attacker_authorship([sent, own], summary, anchors)

    assert a["attributed_count"] == 1
    assert a["attributed"][0]["message_id"] == "<out-1@acme.com>"
    assert a["attributed"][0]["subject"] == "Updated remittance instructions"
    assert sent.attacker_authored is True
    assert own.attacker_authored is False

    # The owner's send, which is after the compromise but from their own
    # address, is not silently upgraded to attacker authorship.
    assert all(e["message_id"] != "<own-1@acme.com>" for e in a["attributed"])


# ---- E4 -------------------------------------------------------------------
def test_exposure_scope_lists_what_the_attacker_read(tmp_path):
    from postmortem.auditlog import analyze_audit_log
    from postmortem.scoring import exposure_scope

    p = tmp_path / "ual.json"
    p.write_text(json.dumps([
        _rule_with("invoice"),
        {"CreationTime": "2026-08-25T16:02:00", "Operation": "MailItemsAccessed",
         "UserId": "victim@acme.com", "ClientIP": ATTACKER_IP,
         "Folders": [{"Path": "\\Inbox", "FolderItems": [
             {"InternetMessageId": "<read-1@supplier.example>"},
             {"InternetMessageId": "<read-2@supplier.example>"}]}]},
        # the owner reading their own mail is not exposure
        {"CreationTime": "2026-08-11T08:00:00", "Operation": "MailItemsAccessed",
         "UserId": "victim@acme.com", "ClientIP": OWNER_IP,
         "Folders": [{"Path": "\\Inbox", "FolderItems": [
             {"InternetMessageId": "<own-read@list.example>"}]}]},
    ]), encoding="utf-8")
    summary = analyze_audit_log(str(p))

    records = [_mail("<read-1@supplier.example>", "Invoice 7781", 10),
               _mail("<own-read@list.example>", "Weekly digest", 11)]
    x = exposure_scope(records, summary)

    assert x["available"] is True
    assert x["messages_read"] == 2          # both attacker-read ids
    assert x["read_and_in_corpus"] == 1     # only one survives in the corpus
    ids = [e["message_id"] for e in x["read"]]
    assert "<read-2@supplier.example>" in ids
    assert "<own-read@list.example>" not in ids, "owner's own reads are not exposure"


def test_absent_mailitemsaccessed_is_unknown_not_none(tmp_path):
    # The dangerous false negative: a log that simply lacks the operation must
    # never read as "nothing was accessed". Keying off whether the message
    # index found anything got this wrong -- a log with HardDelete but no
    # MailItemsAccessed has a populated index.
    from postmortem.auditlog import analyze_audit_log
    from postmortem.scoring import exposure_scope

    p = tmp_path / "ual.json"
    p.write_text(json.dumps([
        _rule_with("invoice"),
        {"CreationTime": "2026-08-25T16:00:00", "Operation": "HardDelete",
         "UserId": "victim@acme.com", "ClientIP": ATTACKER_IP,
         "AffectedItems": [{"InternetMessageId": "<gone@x.example>"}]},
    ]), encoding="utf-8")
    x = exposure_scope([], analyze_audit_log(str(p)))

    assert x["available"] is False
    assert "UNKNOWN" in x["reason"]
    assert "E5/G5" in x["reason"]


# ---- E6 -------------------------------------------------------------------
def test_the_rule_is_replayed_over_the_corpus(tmp_path):
    # A rule's conditions are a specification of what the attacker wanted
    # hidden. Running it names the messages that were filed away unseen.
    from postmortem.auditlog import analyze_audit_log
    from postmortem.scoring import replay_rules

    p = tmp_path / "ual.json"
    p.write_text(json.dumps([_rule_with("invoice, wire")]), encoding="utf-8")
    summary = analyze_audit_log(str(p))

    records = [
        _mail("<pre@s.example>", "Invoice 7781 attached", 10),     # before
        _mail("<post1@s.example>", "Invoice 7782 overdue", 27),    # after
        _mail("<post2@s.example>", "Wire transfer confirmation", 28),
        _mail("<none@s.example>", "Weekly digest", 11),            # no match
    ]
    r = replay_rules(records, summary)
    assert r["rules_replayed"] == 1
    rule = r["rules"][0]

    assert rule["matched_total"] == 3
    assert rule["matched_before_rule"] == 1
    assert rule["matched_after_rule"] == 2
    assert r["matched_after_any_rule"] == 2

    after_subjects = [e["subject"] for e in rule["after"]]
    assert "Invoice 7782 overdue" in after_subjects
    assert "Wire transfer confirmation" in after_subjects
    assert all("digest" not in s.lower() for s in after_subjects)
    assert rule["conditions"]["subject"] == ["invoice", "wire"]


def test_rule_conditions_are_kept_apart_by_field(tmp_path):
    # A word that must appear in the subject is a different rule from the same
    # word anywhere in the body; replaying them as one would over-match.
    from postmortem.auditlog import analyze_audit_log
    from postmortem.scoring import replay_rules

    p = tmp_path / "ual.json"
    p.write_text(json.dumps([
        _rule_with("confidential", field="BodyContainsWords"),
    ]), encoding="utf-8")
    summary = analyze_audit_log(str(p))

    subject_only = _mail("<a@s.example>", "Confidential matters", 27,
                         body="Nothing notable here.")
    body_only = _mail("<b@s.example>", "Monthly update", 27,
                      body="Please treat as confidential.")
    r = replay_rules([subject_only, body_only], summary)
    rule = r["rules"][0]
    assert rule["conditions"].get("body") == ["confidential"]
    assert "subject" not in rule["conditions"]
    matched = [e["subject"] for e in rule["after"]]
    assert matched == ["Monthly update"], matched


# ---- E9 -------------------------------------------------------------------
def test_every_operation_from_an_attacker_ip_is_attributed(tmp_path):
    # Attribution used to stop at UserLoggedIn, so an attacker could create a
    # rule, read mail and delete it from one address and only the sign-in was
    # ever attributed to them.
    from postmortem.auditlog import analyze_audit_log

    p = tmp_path / "ual.json"
    p.write_text(json.dumps([
        _rule_with("invoice"),
        {"CreationTime": "2026-08-25T15:50:00", "Operation": "UserLoggedIn",
         "UserId": "victim@acme.com", "ClientIP": ATTACKER_IP},
        {"CreationTime": "2026-08-25T16:02:00", "Operation": "MailItemsAccessed",
         "UserId": "victim@acme.com", "ClientIP": ATTACKER_IP},
        {"CreationTime": "2026-08-25T16:30:00", "Operation": "HardDelete",
         "UserId": "victim@acme.com", "ClientIP": ATTACKER_IP},
        {"CreationTime": "2026-08-11T08:00:00", "Operation": "MailItemsAccessed",
         "UserId": "victim@acme.com", "ClientIP": OWNER_IP},
    ]), encoding="utf-8")
    summary = analyze_audit_log(str(p))

    ops = {x["operation"] for x in summary["attacker_operations"]}
    assert ops == {"New-InboxRule", "UserLoggedIn", "MailItemsAccessed",
                   "HardDelete"}
    assert len(summary["attacker_logins"]) == 1, "sign-ins remain identifiable"

    profile = {x["ip"]: x for x in summary["ip_activity"]}
    assert profile[ATTACKER_IP]["is_attacker"] is True
    assert profile[ATTACKER_IP]["events"] == 4
    assert profile[OWNER_IP]["is_attacker"] is False
    # The attacker's IP sorts first, so it is the first thing an analyst reads.
    assert summary["ip_activity"][0]["ip"] == ATTACKER_IP


def test_audit_ips_are_geolocated_and_flagged(tmp_path):
    # --geoip-db was wired for message headers and never applied to the audit
    # log, even though a ClientIP is recorded by the service rather than
    # asserted by a sender, and so is the stronger of the two.
    from postmortem.auditlog import analyze_audit_log, annotate_audit_geoip

    class FakeResolver:
        def available(self):
            return True

        def lookup(self, ip):
            if ip == ATTACKER_IP:
                return {"country": "IR", "asn": "AS197207", "org": "Example Host"}
            return {"country": "US", "asn": "AS15169", "org": "Corp ISP"}

    p = tmp_path / "ual.json"
    p.write_text(json.dumps([
        _rule_with("invoice"),
        {"CreationTime": "2026-08-11T08:00:00", "Operation": "MailItemsAccessed",
         "UserId": "victim@acme.com", "ClientIP": OWNER_IP},
    ]), encoding="utf-8")
    summary = analyze_audit_log(str(p))

    result = annotate_audit_geoip(summary, FakeResolver(), ["US"])
    assert result["resolved"] == 2
    assert result["unexpected"] == 1

    profile = {x["ip"]: x for x in summary["ip_activity"]}
    assert profile[ATTACKER_IP]["country"] == "IR"
    assert profile[ATTACKER_IP]["unexpected_country"] is True
    assert profile[OWNER_IP]["country"] == "US"
    assert profile[OWNER_IP]["unexpected_country"] is False

    # No resolver, no claims.
    class NoResolver:
        def available(self):
            return False

    assert annotate_audit_geoip(summary, NoResolver(), ["US"]) == {
        "resolved": 0, "unexpected": 0}


# --------------------------------------------------------------------------
# B2/B4/B5/B6/B7 and C1/C3: what stops scoring, and what starts
# --------------------------------------------------------------------------
def _msg(**kw):
    r = make_record(sender_email=kw.get("sender_email", "a@ext.example"),
                    sender_domain=kw.get("sender_domain", "ext.example"),
                    subject=kw.get("subject", "Hello"),
                    path=kw.get("path", "/m/x.eml"),
                    date=kw.get("date", "Mon, 12 Jan 2026 09:00:00 -0500"))
    r.body = kw.get("body", "Regular message.")
    r.urls = kw.get("urls", [])
    r.url_domains = kw.get("url_domains", [])
    r.url_analysis = kw.get("url_analysis", [])
    r.attachments = kw.get("attachments", [])
    r.attachment_details = kw.get("attachment_details", [])
    r.authentication_results = kw.get("auth", {})
    return r


def _score(record, baseline=None):
    calculate_score(record, {"acme.com"}, set(), baseline)
    return record.score


def test_today_alone_is_not_urgency(tmp_path):
    # "the payment went out today" is the most ordinary sentence in an
    # accounts mailbox, and used to be worth the payment+urgency combination.
    from postmortem.scoring import _DEADLINE_TODAY_RE

    ordinary = _msg(subject="Re: invoice",
                    body="Just confirming the payment went out today.")
    assert not any("urgency" in i.lower() for i in
                   (_score(ordinary), ordinary)[1].indicators)

    # A deadline construction still counts -- that is real pressure.
    for phrase in ("this must be paid by close of business today",
                   "wire the funds today or the account closes",
                   "no later than today please"):
        assert _DEADLINE_TODAY_RE.search(phrase), phrase
    for phrase in ("the payment went out today", "I saw him today"):
        assert not _DEADLINE_TODAY_RE.search(phrase), phrase


def test_links_are_counted_once(tmp_path):
    # A newsletter with eight tracking domains used to be charged for URL
    # presence, for each distinct domain, and again for URL analysis.
    news = _msg(subject="Weekly roundup", body="Read more on our site.",
                urls=["https://t%d.example/x" % i for i in range(8)],
                url_domains=["t%d.example" % i for i in range(8)],
                url_analysis=[{"url": "https://t%d.example/x" % i,
                               "risk_score": 0} for i in range(8)])
    assert _score(news) == 0

    # Presence and domain count are still reported, at zero weight: they are
    # facts about the message, just not evidence.
    prov = {p["signal"]: p for p in news.provenance}
    assert any("URL(s)" in s for s in prov)
    assert all(p["weight"] == 0 for s, p in prov.items() if "URL" in s)

    # A genuinely risky URL still scores, through the analysis path alone.
    risky = _msg(subject="Password reset",
                 body="Confirm your account at https://evil.example/owa/login",
                 urls=["https://evil.example/owa/login"],
                 url_domains=["evil.example"],
                 url_analysis=[{"url": "https://evil.example/owa/login",
                                "risk_score": 12, "flags": []}])
    assert _score(risky) > _score(news)


def test_attachments_are_weighted_by_what_they_are(tmp_path):
    # A zipped quarterly report used to cost +6 before anyone looked at it.
    zipped = _msg(subject="Q3 report", body="Attached.",
                  attachments=["Q3-report.zip"],
                  attachment_details=[{"flags": []}])
    assert _score(zipped) == 0

    # An archive whose peek found something is a different matter.
    loaded = _msg(subject="Q3 report", body="Attached.",
                  attachments=["Q3-report.zip"],
                  attachment_details=[{"flags": ["archive contains executable"]}])
    assert _score(loaded) > 0

    # And a script attachment has no legitimate use in mail at all.
    script = _msg(subject="Invoice", body="See attached.",
                  attachments=["invoice.js"], attachment_details=[{"flags": []}])
    assert _score(script) >= 8
    assert _score(script) > _score(loaded)


def test_being_an_ordinary_correspondent_is_free(tmp_path):
    # External + unfamiliar described the median external email and cost +4.
    ordinary = _msg(subject="Meeting Thursday", body="Does 2pm work?")
    assert _score(ordinary) == 0
    prov = {p["signal"]: p for p in ordinary.provenance}
    ext = [p for s, p in prov.items() if s.startswith("External sender")]
    assert ext and ext[0]["weight"] == 0


def test_terms_match_on_word_boundaries(tmp_path):
    from postmortem.scoring import term_present

    assert term_present("login", "Please login here")
    assert not term_present("login", "see the weblogin handler")
    assert not term_present("payment", "prepayment terms apply")
    assert term_present("payment", "the payment is due")
    assert term_present("wire transfer", "a wire  transfer was sent")

    prose = _msg(subject="Integration notes",
                 body="The weblogin handler reads prepayment terms.")
    assert _score(prose) == 0


def test_a_bulletin_about_phishing_is_not_phishing(tmp_path):
    from postmortem.scoring import discussing_not_doing

    assert discussing_not_doing("This is a security awareness test")
    assert not discussing_not_doing("Please verify your account")

    bulletin = _msg(sender_domain="acme.com", sender_email="security@acme.com",
                    subject="How to spot a phish",
                    body="A phishing email may say 'reset your password' or "
                         "'verify your account'. This is a test. Report "
                         "suspicious mail to the service desk.")
    real = _msg(sender_domain="evil.example", sender_email="it@evil.example",
                subject="Account notice",
                body="Your account is locked. Reset your password and verify "
                     "your account to restore access.")
    assert _score(real) > _score(bulletin)

    # The suppressed terms are still reported, so the finding is visible even
    # though it does not score.
    suppressed = [p for p in bulletin.provenance
                  if "security-awareness context" in p["signal"]]
    assert suppressed and all(p["weight"] == 0 for p in suppressed)


def test_authentication_suppresses_and_aggravates(tmp_path):
    from postmortem.scoring import corpus_baseline

    # An established, authenticating sender.
    corpus = [_msg(sender_domain="partner.example",
                   sender_email="ap@partner.example",
                   path="/c/%d.eml" % i, auth={"dmarc_pass": True})
              for i in range(20)]
    base = corpus_baseline(corpus)

    lure = "Please verify your account and reset your password immediately."
    trusted = _msg(sender_domain="partner.example",
                   sender_email="ap@partner.example",
                   subject="Account notice", body=lure,
                   auth={"dmarc_pass": True})
    spoofed = _msg(sender_domain="partner.example",
                   sender_email="ap@partner.example",
                   subject="Account notice", body=lure,
                   auth={"dmarc_fail": True})

    t = _score(trusted, base)
    s = _score(spoofed, base)
    assert s > t, "a spoofed message must outscore an aligned one"
    assert any("Authentication aligned" in i for i in trusted.indicators)
    assert any("Authentication failed" in i for i in spoofed.indicators)

    # The suppressor cannot drive a real signal to nothing.
    assert t > 0


def test_rarity_amplifies_but_never_convicts(tmp_path):
    from postmortem.scoring import corpus_baseline

    corpus = [_msg(sender_domain="known.example", sender_email="a@known.example",
                   path="/c/%d.eml" % i) for i in range(20)]
    stranger = _msg(sender_domain="brand-new.example",
                    sender_email="x@brand-new.example",
                    subject="Invoice", body="Please verify your account.")
    innocuous = _msg(sender_domain="also-new.example",
                     sender_email="y@also-new.example",
                     subject="Hello", body="Are you free Thursday?")
    base = corpus_baseline(corpus + [stranger, innocuous])

    # Rarity multiplies an existing signal...
    assert _score(stranger, base) > _score(stranger)
    # ...but creates nothing on its own. A new sender with nothing against it
    # stays at zero, however unfamiliar.
    assert _score(innocuous, base) == 0


# --------------------------------------------------------------------------
# The sanitized diagnostic
# --------------------------------------------------------------------------
def test_diagnostic_discards_every_identifier(tmp_path):
    from postmortem import diagnostic

    planted = [
        "j.hollingsworth@globex-industries.com",
        "globex-industries.com",
        "203.0.113.77",
        "C:\\Cases\\Globex\\export.pst",
        "https://globex-secure-login.example/owa",
        "<8812.abc@globex-industries.com>",
        "MERCURY-DC01.globex.local",
    ]
    for value in planted:
        out = diagnostic.template("Finding about %s here" % value)
        assert value not in out, (value, out)
        assert not diagnostic.scan_for_identifiers(out), (value, out)

    # The tool's own vocabulary survives -- without it every phrase finding
    # collapses into one line and the report loses its whole point.
    kept = diagnostic.template("Contains phrase: 'wire transfer'")
    assert "wire transfer" in kept

    # A client value in the same position does not.
    dropped = diagnostic.template("Contains phrase: 'Project Nightingale'")
    assert "Nightingale" not in dropped


def test_diagnostic_refuses_to_write_a_leak(tmp_path):
    from postmortem import diagnostic

    doc = diagnostic.build([], verdict={}, manifest={})
    # Force a leak past the templating to prove the final gate is real.
    doc["note"] = "contact analyst@example.com for details"
    try:
        diagnostic.write(doc, str(tmp_path / "d.txt"))
    except ValueError as exc:
        assert "refusing to write" in str(exc)
    else:
        raise AssertionError("a leaked identifier was written to disk")
    assert not (tmp_path / "d.txt").exists()


def test_diagnostic_reports_useful_shape(tmp_path):
    from postmortem import diagnostic

    records = []
    for i in range(10):
        r = _msg(sender_domain="ext%d.example" % i,
                 sender_email="a@ext%d.example" % i,
                 path="/m/%d.eml" % i,
                 subject="Verify your account",
                 body="Please verify your account immediately.")
        _score(r)
        r.tier = 1 if i < 3 else 3
        records.append(r)

    doc = diagnostic.build(records, verdict={"verdict": "LIKELY_INITIAL_EMAIL"},
                           manifest={"tool_version": "8.2"},
                           timings={"scoring": 1.5})
    assert doc["corpus"]["messages"] == 10
    assert doc["tiers"]["1"] == 3

    # Share of corpus counts messages, not fires: a signal firing twice on one
    # message must not push its share past 100%.
    assert doc["signals"], "expected signal statistics"
    for s in doc["signals"]:
        assert 0 < s["share_of_corpus"] <= 1.0, s
        assert s["messages"] <= doc["corpus"]["messages"]
        assert s["fires"] >= s["messages"]

    # And it renders without leaking.
    text = diagnostic.render(doc)
    assert not diagnostic.scan_for_identifiers(text)
    assert "[signals]" in text and "[timings_seconds]" in text


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



# --------------------------------------------------------------------------
# Entra sign-in ingestion: device code flow, and the join to the mail corpus
#
# This is the only attack in the tool that the mail corpus cannot see. The
# lure has no attacker domain, no credential page and nothing for URL analysis
# to score, because the victim authenticates on the real Microsoft page and
# passes real MFA. Only the sign-in log records that it happened.
# --------------------------------------------------------------------------
VICTIM_IP = "203.0.113.10"
POLLER_IP = "45.147.230.88"


def _signin(**kw):
    """One Entra sign-in record, in the portal's nested shape."""
    rec = {
        "createdDateTime": kw.get("time", "2026-08-25T15:40:00Z"),
        "userPrincipalName": kw.get("user", "victim@acme.com"),
        "correlationId": kw.get("cid", "cid-1"),
        "appDisplayName": kw.get("app", "Microsoft Office"),
        "resourceDisplayName": kw.get("resource", "Microsoft Graph"),
        "ipAddress": kw.get("ip", VICTIM_IP),
        "isInteractive": kw.get("interactive", True),
        "userAgent": kw.get("agent", "Mozilla/5.0 Chrome/128"),
        "status": {"errorCode": kw.get("error", 0)},
        "location": {"city": kw.get("city", "Tampa"),
                     "countryOrRegion": kw.get("country", "US")},
        "autonomousSystemNumber": kw.get("asn", 7018),
    }
    if kw.get("device_code", True):
        rec["originalTransferMethod"] = "deviceCodeFlow"
    else:
        rec["originalTransferMethod"] = "none"
    return rec


def _write_signin(tmp_path, records, name="signins.json"):
    import json
    p = tmp_path / name
    p.write_text(json.dumps(records), encoding="utf-8")
    return str(p)


def _phished_pair(tmp_path, cid="cid-1", when="2026-08-25T15:40:00Z"):
    """The shape of the attack: the victim types the code in Tampa, the
    attacker's client polls the token endpoint from another country."""
    return _write_signin(tmp_path, [
        _signin(cid=cid, time=when, ip=VICTIM_IP, interactive=True),
        _signin(cid=cid, time=when, ip=POLLER_IP, interactive=False,
                city="Frankfurt", country="DE", asn=200000,
                agent="python-requests/2.31"),
    ])


def test_a_location_split_names_the_attacker_leg(tmp_path):
    from postmortem.signin import analyze_signin_logs

    s = analyze_signin_logs(_phished_pair(tmp_path))
    assert s["available"] is True
    assert s["device_code_records"] == 2
    assert s["attack_groups"] == 1

    g = s["groups"][0]
    assert g["verdict"] == "attack"
    assert "country" in g["differs"] and "IP" in g["differs"]
    assert g["attribution_basis"] == "isInteractive"

    # Only the polling leg is named. The victim's own address must never be
    # seeded as the attacker's -- it would mislabel every action the mailbox
    # owner took for the rest of the report.
    assert s["attacker_ips"] == [POLLER_IP]
    assert VICTIM_IP not in s["attacker_ips"]

    assert s["tokens_issued"] == 1
    assert s["earliest_token"].startswith("2026-08-25T15:40")


def test_the_victims_address_is_never_attributed(tmp_path):
    # The catastrophic failure mode. If isInteractive is absent the legs are
    # indistinguishable, and guessing wrong poisons the entire audit-log
    # attribution chain. The tool must decline instead.
    from postmortem.signin import analyze_signin_logs

    records = []
    for ip, city, country in ((VICTIM_IP, "Tampa", "US"),
                              (POLLER_IP, "Frankfurt", "DE")):
        r = _signin(ip=ip, city=city, country=country)
        del r["isInteractive"]
        records.append(r)
    s = analyze_signin_logs(_write_signin(tmp_path, records))

    assert s["attacker_ips"] == [], "no leg may be attributed without a basis"
    assert s["unattributed_groups"], "the group must still be reported"
    assert "isInteractive" in s["unattributed_groups"][0]["reason"]


def test_an_address_the_user_signs_in_from_is_vetoed(tmp_path):
    # A device code flow the user completed themselves across two of their own
    # machines looks like a split. The veto is that the account demonstrably
    # signs in interactively from the "attacker" address.
    from postmortem.signin import analyze_signin_logs

    other = "198.51.100.22"
    s = analyze_signin_logs(_write_signin(tmp_path, [
        _signin(cid="c1", ip=VICTIM_IP, interactive=True),
        _signin(cid="c1", ip=other, interactive=False, city="Orlando"),
        # ... and here the user is plainly signing in from it themselves.
        _signin(cid="c2", ip=other, interactive=True, city="Orlando",
                time="2026-08-01T09:00:00Z", device_code=False),
    ]))
    assert other not in s["attacker_ips"]
    assert other in s["vetoed_ips"]
    assert any("interactively" in w for w in s["warnings"])


def test_a_consistent_flow_is_not_an_attack(tmp_path):
    # Device code flow is a legitimate protocol. Using it is not a finding.
    from postmortem.signin import analyze_signin_logs

    s = analyze_signin_logs(_write_signin(tmp_path, [
        _signin(cid="c1", ip=VICTIM_IP, interactive=True),
        _signin(cid="c1", ip=VICTIM_IP, interactive=False,
                agent="python-requests/2.31"),
    ]))
    assert s["device_code_records"] == 2
    assert s["attack_groups"] == 0
    assert s["attacker_ips"] == []
    assert s["groups"][0]["verdict"] == "consistent"
    # The user-agent difference is reported but does not convict.
    assert s["groups"][0]["differs"] == ["user agent"]


def test_an_export_without_the_fields_says_it_is_blind(tmp_path):
    # The dangerous false negative: an export that cannot answer the question
    # must not read as "no device code flow found".
    from postmortem.signin import analyze_signin_logs

    r = _signin()
    del r["originalTransferMethod"]
    s = analyze_signin_logs(_write_signin(tmp_path, [r]))

    assert s["coverage"]["blind"] is True
    assert s["device_code_records"] == 0
    assert any("cannot answer" in w for w in s["warnings"])


def test_failed_token_requests_are_not_issuances(tmp_path):
    from postmortem.signin import analyze_signin_logs

    s = analyze_signin_logs(_write_signin(tmp_path, [
        _signin(cid="c1", ip=VICTIM_IP, interactive=True),
        _signin(cid="c1", ip=POLLER_IP, interactive=False, country="DE",
                error=50126),
    ]))
    assert s["attack_groups"] == 1
    assert s["attacker_ips"] == [POLLER_IP]   # still an attacker address
    assert s["tokens_issued"] == 0            # but no token was minted
    assert s["earliest_token"] == ""


# ---- the merge into the audit log ----------------------------------------
def test_signin_ips_make_attribution_work_without_a_rule(tmp_path):
    # The structural gap this closes. analyze_audit_log seeds its attacker set
    # ONLY from malicious inbox-rule events, so an intruder who read and
    # deleted but never made a rule leaves it empty -- and every attribution
    # downstream silently reports nothing.
    import json
    from postmortem.auditlog import analyze_audit_log

    p = tmp_path / "ual.json"
    p.write_text(json.dumps([
        {"CreationTime": "2026-08-25T16:30:00", "Operation": "HardDelete",
         "UserId": "victim@acme.com", "ClientIP": POLLER_IP,
         "AffectedItems": [{"InternetMessageId": "<gone@bank.example>",
                            "Subject": "Updated bank details"}]},
    ]), encoding="utf-8")

    # Without the sign-in log: nothing is attributable.
    bare = analyze_audit_log(str(p))
    assert bare["derived"]["attacker_ips"] == []
    assert bare["attacker_operations"] == []

    # With it: the same log now names who did it.
    merged = analyze_audit_log(str(p), extra_attacker_ips=[POLLER_IP])
    assert merged["derived"]["attacker_ips"] == [POLLER_IP]
    assert [x["operation"] for x in merged["attacker_operations"]] == ["HardDelete"]
    idx = merged["message_index"]["by_message_id"]
    assert idx["<gone@bank.example>"][0]["by_attacker"] is True


def test_the_token_time_only_moves_the_compromise_earlier(tmp_path):
    import json
    from datetime import datetime, timezone
    from postmortem.auditlog import analyze_audit_log

    p = tmp_path / "ual.json"
    p.write_text(json.dumps([
        {"CreationTime": "2026-08-25T15:54:33", "Operation": "New-InboxRule",
         "UserId": "victim@acme.com", "ClientIP": POLLER_IP,
         "Parameters": [{"Name": "SubjectContainsWords", "Value": "invoice"},
                        {"Name": "DeleteMessage", "Value": "True"}]},
    ]), encoding="utf-8")

    earlier = datetime(2026, 8, 25, 15, 40, tzinfo=timezone.utc)
    later = datetime(2026, 9, 1, 0, 0, tzinfo=timezone.utc)

    assert analyze_audit_log(str(p))["derived"]["compromise_date"] \
        == "2026-08-25T15:54:33Z"
    # Token issuance precedes the first action taken with the token.
    assert analyze_audit_log(str(p), anchor_dt=earlier)["derived"]["compromise_date"] \
        == "2026-08-25T15:40:00Z"
    # A later anchor must never shrink the investigated window.
    assert analyze_audit_log(str(p), anchor_dt=later)["derived"]["compromise_date"] \
        == "2026-08-25T15:54:33Z"


def test_audit_log_behaviour_is_unchanged_without_the_new_arguments(tmp_path):
    import json
    from postmortem.auditlog import analyze_audit_log

    p = tmp_path / "ual.json"
    p.write_text(json.dumps([
        {"CreationTime": "2026-08-25T15:54:33", "Operation": "New-InboxRule",
         "UserId": "victim@acme.com", "ClientIP": POLLER_IP,
         "Parameters": [{"Name": "SubjectContainsWords", "Value": "invoice"},
                        {"Name": "DeleteMessage", "Value": "True"}]},
    ]), encoding="utf-8")
    a = analyze_audit_log(str(p))
    b = analyze_audit_log(str(p), extra_attacker_ips=(), anchor_dt=None)
    assert a["derived"] == b["derived"]


def test_the_audit_log_resolves_an_unresolved_device_code_group(tmp_path):
    # The reverse direction. One recorded leg is not a clean result -- and the
    # audit log derives attacker addresses from unrelated evidence, so it can
    # answer what the sign-in log left open.
    from postmortem.signin import analyze_signin_logs, resolve_single_groups

    s = analyze_signin_logs(_write_signin(tmp_path, [
        _signin(cid="lonely", ip=POLLER_IP, interactive=False, country="DE"),
    ]))
    assert s["groups"][0]["verdict"] == "single"
    assert s["attacker_ips"] == []

    out = resolve_single_groups(s, [POLLER_IP])
    assert out["resolved"] == 1
    assert s["groups"][0]["verdict"] == "attack"
    assert s["groups"][0]["attribution_basis"] == "audit log attacker IP"
    assert s["single_groups"] == []


# ---- the lure window -----------------------------------------------------
def _lure_record(subject, body, when, path="/m/lure.eml"):
    r = make_record(sender_email="it-support@acme.com", sender_domain="acme.com",
                    subject=subject, path=path, date=when)
    r.body = body
    r.urls = []
    r.url_domains = []
    r.url_analysis = []
    r.attachments = []
    r.attachment_details = []
    r.authentication_results = {}
    return r


def test_the_lure_is_found_by_time_not_only_by_wording(tmp_path):
    from postmortem.signin import analyze_signin_logs
    from postmortem.scoring import signin_lure_window

    s = analyze_signin_logs(_phished_pair(tmp_path, when="2026-08-25T15:40:00Z"))

    lure = _lure_record(
        "Action required: enroll your device",
        "Open https://microsoft.com/devicelogin and enter code F7K2QX9B to "
        "finish enrolling.",
        "Tue, 25 Aug 2026 15:33:00 +0000")
    unrelated = _lure_record("Lunch?", "Are you free at 1?",
                             "Tue, 25 Aug 2026 15:35:00 +0000",
                             path="/m/lunch.eml")
    old = _lure_record(
        "Enroll your device",
        "Go to https://microsoft.com/devicelogin and enter the code.",
        "Mon, 10 Aug 2026 09:00:00 +0000", path="/m/old.eml")

    out = signin_lure_window([lure, unrelated, old], s, window_minutes=20)
    assert out["available"] is True
    assert out["tokens"] == 1
    assert [e["path"] for e in out["confirmed"]] == ["/m/lure.eml"]
    assert lure.signin_confirmed is True
    assert out["confirmed"][0]["code"] == "F7K2QX9B"
    assert out["confirmed"][0]["delta_seconds"] == 420

    # In the window but carrying no device login URL: listed, not promoted.
    assert unrelated.signin_confirmed is False
    assert unrelated.signin_lure_candidate is True
    assert [e["path"] for e in out["in_window_only"]] == ["/m/lunch.eml"]

    # The same wording two weeks earlier is not this lure.
    assert old.signin_confirmed is False
    assert old.signin_lure_candidate is False


def test_a_confirmed_lure_scores_nothing_and_still_reaches_tier_one(tmp_path):
    # The decision this was built on: recorded facts are evidence, not
    # heuristics. Were it weighted, the baseline modifiers would suppress it
    # for arriving from an aligned, familiar sender -- which is exactly what a
    # second-hop BEC lure does.
    from postmortem.signin import analyze_signin_logs
    from postmortem.scoring import run_scenario_analysis
    from postmortem.models import Anchors

    s = analyze_signin_logs(_phished_pair(tmp_path, when="2026-08-25T15:40:00Z"))
    lure = _lure_record(
        "Device enrollment",
        "Visit https://microsoft.com/devicelogin and enter code F7K2QX9B.",
        "Tue, 25 Aug 2026 15:33:00 +0000")
    before = lure.score

    run_scenario_analysis([lure], {"acme.com"}, Anchors(), None,
                          signin_summary=s)

    assert lure.signin_confirmed is True
    assert lure.tier == 1
    finding = [f for f in lure.provenance
               if f["source"] == "entra:signin_log"]
    assert finding, "the finding must be stated, with its evidence"
    assert finding[0]["weight"] == 0
    assert lure.score == before, "a recorded fact must not move the score"
    assert POLLER_IP in finding[0]["signal"]


def test_a_token_with_no_lure_in_the_corpus_is_its_own_finding(tmp_path):
    # Device code lures are often delivered over Teams precisely because the
    # code expires in fifteen minutes. Silence here is a result, not a gap.
    from postmortem.signin import analyze_signin_logs
    from postmortem.scoring import signin_lure_window

    s = analyze_signin_logs(_phished_pair(tmp_path))
    out = signin_lure_window([], s, window_minutes=20)

    assert out["confirmed"] == []
    assert len(out["tokens_without_lure"]) == 1
    assert out["tokens_without_lure"][0]["ip"] == POLLER_IP
    assert "Teams" in out["note"]


def test_no_signin_log_changes_nothing(tmp_path):
    # Every existing run must behave exactly as before.
    from postmortem.scoring import signin_lure_window, run_scenario_analysis
    from postmortem.models import Anchors

    r = _lure_record("Hello", "Ordinary message.",
                     "Tue, 25 Aug 2026 15:33:00 +0000")
    for empty in (None, {}):
        out = signin_lure_window([r], empty)
        assert out["available"] is False
        assert out["confirmed"] == []

    _s, _rsn, verdict = run_scenario_analysis([r], {"acme.com"}, Anchors(), None)
    assert r.signin_confirmed is False
    assert verdict["signin_lures"]["available"] is False


def test_confirmed_messages_rank_above_higher_scoring_ones(tmp_path):
    # The cost of weight 0: ordering by score alone buried the best-evidenced
    # message in the case under whatever content heuristic ranked highest.
    from postmortem.reporting import candidate_sort_key

    bland = _lure_record("Device enrollment", "Body.",
                         "Tue, 25 Aug 2026 15:33:00 +0000")
    bland.score = 2
    bland.signin_confirmed = True

    noisy = _lure_record("URGENT wire transfer", "Body.",
                         "Tue, 25 Aug 2026 15:33:00 +0000",
                         path="/m/noisy.eml")
    noisy.score = 31

    deleted = _lure_record("Remittance", "Body.",
                           "Tue, 25 Aug 2026 15:33:00 +0000",
                           path="/m/deleted.eml")
    deleted.score = 0
    deleted.audit_confirmed = True

    order = [r.path for r in sorted([noisy, bland, deleted],
                                    key=candidate_sort_key)]
    assert order[-1] == "/m/noisy.eml", order
    assert set(order[:2]) == {"/m/lure.eml", "/m/deleted.eml"}



# --------------------------------------------------------------------------
# Persistence: what keeps the attacker in after the obvious remediation
#
# The other sections of this tool answer what happened. These answer whether
# it is still happening, which is the question a client acts on tonight and
# the one a report can most easily get wrong -- an OAuth consent grant leaves
# no trace in mail or in sign-in data, so a report built from those alone can
# say "remediated" while the attacker still reads the mailbox.
# --------------------------------------------------------------------------
PERSIST_ATK = "45.147.230.88"
ADMIN_IP = "198.51.100.5"


def _audit_event(activity, when, ip, target, perms="", result="success"):
    return {
        "activityDateTime": when,
        "activityDisplayName": activity,
        "result": result,
        "initiatedBy": {"user": {"userPrincipalName": "victim@acme.com",
                                 "ipAddress": ip}},
        "targetResources": [{
            "displayName": target, "id": "sp-1", "type": "ServicePrincipal",
            "modifiedProperties": [{"displayName": "ConsentAction.Permissions",
                                    "newValue": perms}]}],
    }


def _write(tmp_path, name, payload):
    import json
    p = tmp_path / name
    if name.endswith(".csv"):
        p.write_text(payload, encoding="utf-8")
    else:
        p.write_text(json.dumps(payload), encoding="utf-8")
    return str(p)


def _compromise():
    from datetime import datetime, timezone
    return datetime(2026, 8, 25, 15, 40, tzinfo=timezone.utc)


def test_a_consent_grant_is_the_worst_case_and_says_so(tmp_path):
    from postmortem.persistence import parse_entra_audit, analyze_persistence

    rows = [_audit_event("Consent to application", "2026-08-25T15:47:00Z",
                         PERSIST_ATK, "Mail Archiver Pro",
                         "Mail.ReadWrite Mail.Send offline_access")]
    events = parse_entra_audit([__import__("postmortem.persistence",
                                           fromlist=["_flatten"])._flatten(r)
                                for r in rows])
    out = analyze_persistence({"entra_audit": events},
                              attacker_ips=[PERSIST_ATK],
                              compromise_dt=_compromise(),
                              victim_users=["victim@acme.com"])
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["kind"] == "oauth_consent"
    assert f["by_attacker"] is True
    assert PERSIST_ATK in f["attribution"]
    assert f["mail_scopes"] == ["mail.readwrite", "mail.send"]
    assert f["durable_scopes"] == ["offline_access"]

    # The whole point: neither of the two things a client always does removes
    # it, and the report has to say so in those words.
    assert f["survives_password_reset"] == "survives"
    assert f["survives_token_revocation"] == "survives"
    assert out["survives_both_count"] == 1
    assert "do NOT remove this" in f["not_fixed_by"]


def test_ordinary_administration_is_not_a_finding(tmp_path):
    # A tenant has legitimate consents. Reporting every one of them buries the
    # attacker's, which is the same as not finding it.
    from postmortem.persistence import (parse_entra_audit, analyze_persistence,
                                        _flatten)

    rows = [
        _audit_event("Consent to application", "2026-06-02T11:00:00Z",
                     ADMIN_IP, "Adobe Acrobat", "User.Read"),
        _audit_event("Consent to application", "2026-08-25T15:47:00Z",
                     PERSIST_ATK, "Mail Archiver Pro", "Mail.ReadWrite"),
    ]
    events = parse_entra_audit([_flatten(r) for r in rows])
    out = analyze_persistence({"entra_audit": events},
                              attacker_ips=[PERSIST_ATK],
                              compromise_dt=_compromise(),
                              victim_users=["victim@acme.com"])
    names = [t for f in out["findings"] for t in f["targets"]]
    assert names == ["Mail Archiver Pro"], names


def test_an_unreadable_scope_is_kept_not_assumed_harmless(tmp_path):
    # The dangerous version of the filter above. "We could not read what this
    # application asked for" must never be treated as "it asked for nothing".
    from postmortem.persistence import (parse_entra_audit, analyze_persistence,
                                        _flatten, scopes_were_readable)

    assert scopes_were_readable("Mail.ReadWrite offline_access")
    assert not scopes_were_readable("")
    assert not scopes_were_readable("consent granted by administrator")

    rows = [_audit_event("Consent to application", "2026-06-02T11:00:00Z",
                         ADMIN_IP, "Unknown App", "")]
    out = analyze_persistence(
        {"entra_audit": parse_entra_audit([_flatten(r) for r in rows])},
        attacker_ips=[PERSIST_ATK], compromise_dt=_compromise())
    assert len(out["findings"]) == 1
    assert out["findings"][0]["by_attacker"] is False
    assert out["findings"][0]["targets"] == ["Unknown App"]


def test_attribution_needs_a_recorded_ground(tmp_path):
    # The failure that would put a remediation instruction in front of a client
    # for something their own administrator did.
    from postmortem.persistence import (parse_entra_audit, analyze_persistence,
                                        _flatten)

    rows = [_audit_event("Add member to role", "2026-08-26T09:00:00Z",
                         ADMIN_IP, "Exchange Administrator")]
    events = parse_entra_audit([_flatten(r) for r in rows])

    # No attacker address established at all: nothing is attributed.
    bare = analyze_persistence({"entra_audit": events})
    assert bare["findings"][0]["by_attacker"] is False
    assert bare["confirmed_count"] == 0
    assert any("nothing below is attributed" in w for w in bare["warnings"])

    # Attacker address known, but this event is not from it.
    known = analyze_persistence({"entra_audit": events},
                                attacker_ips=[PERSIST_ATK],
                                compromise_dt=_compromise(),
                                victim_users=["victim@acme.com"])
    assert known["findings"][0]["by_attacker"] is True  # in-window, victim acct
    assert "compromise window" in known["findings"][0]["attribution"]

    # ... and an event before the window is neither.
    old = parse_entra_audit([_flatten(
        _audit_event("Add member to role", "2026-01-01T09:00:00Z", ADMIN_IP,
                     "Exchange Administrator"))])
    out = analyze_persistence({"entra_audit": old}, attacker_ips=[PERSIST_ATK],
                              compromise_dt=_compromise(),
                              victim_users=["victim@acme.com"])
    assert out["findings"][0]["by_attacker"] is False
    assert out["findings"][0]["attribution"] == ""


def test_a_failed_attempt_is_not_a_mechanism(tmp_path):
    from postmortem.persistence import parse_entra_audit, _flatten

    rows = [_audit_event("Consent to application", "2026-08-25T15:47:00Z",
                         PERSIST_ATK, "Mail Archiver Pro", "Mail.ReadWrite",
                         result="failure")]
    assert parse_entra_audit([_flatten(r) for r in rows]) == []


def test_a_grant_that_predates_the_log_is_still_found(tmp_path):
    # The audit log only shows consents granted inside its window. One granted
    # earlier is invisible there and is the more dangerous of the two, because
    # nothing else would ever surface it.
    from postmortem.persistence import parse_oauth_permissions, analyze_persistence

    rows = [
        {"applicationname": "Invoice Sync Helper", "clientid": "z9y8x7",
         "permission": "full_access_as_app offline_access",
         "id": "grant-4410", "permissiontype": "Application"},
        {"applicationname": "Adobe Acrobat", "clientid": "d4",
         "permission": "User.Read", "id": "grant-1"},
    ]
    grants = parse_oauth_permissions(rows)
    # The benign one never becomes a finding at all.
    assert [g["targets"][0] for g in grants] == ["Invoice Sync Helper"]

    out = analyze_persistence({"oauth_permissions": grants})
    f = out["findings"][0]
    assert "full_access_as_app" in f["mail_scopes"]
    assert f["survives_password_reset"] == "survives"
    assert f["grant_id"] == "grant-4410"


def test_a_surviving_grant_inherits_the_consent_attribution(tmp_path):
    # The audit log says the attacker consented; the grant export says it is
    # still there. The second decides whether remediation is finished, so it
    # must not sit in a review pile while the first is flagged confirmed.
    from postmortem.persistence import (parse_entra_audit, parse_oauth_permissions,
                                        analyze_persistence, _flatten)

    events = parse_entra_audit([_flatten(_audit_event(
        "Consent to application", "2026-08-25T15:47:00Z", PERSIST_ATK,
        "Mail Archiver Pro", "Mail.ReadWrite offline_access"))])
    grants = parse_oauth_permissions([
        {"applicationname": "Mail Archiver Pro", "clientid": "a1b2c3",
         "permission": "Mail.ReadWrite offline_access", "id": "grant-7781"}])

    out = analyze_persistence({"entra_audit": events, "oauth_permissions": grants},
                             attacker_ips=[PERSIST_ATK],
                             compromise_dt=_compromise(),
                             victim_users=["victim@acme.com"])
    existing = [f for f in out["findings"] if f["source"] == "oauth_permissions"]
    assert existing and existing[0]["by_attacker"] is True
    assert "still present" in existing[0]["attribution"]
    assert out["confirmed_count"] == 2


def test_remediation_carries_the_real_identifiers(tmp_path):
    # A command with <id> in it is a command the analyst has to go and look up.
    from postmortem.persistence import parse_oauth_permissions, analyze_persistence, \
        remediation_plan

    grants = parse_oauth_permissions([
        {"applicationname": "Mail Archiver Pro", "clientid": "a1b2c3",
         "permission": "Mail.ReadWrite offline_access", "id": "grant-7781"}])
    plan = remediation_plan(analyze_persistence({"oauth_permissions": grants}))
    assert len(plan) == 1
    assert "-OAuth2PermissionGrantId grant-7781" in plan[0]["action"]
    assert "-ServicePrincipalId a1b2c3" in plan[0]["action"]
    assert "<id>" not in plan[0]["action"]


def test_rules_and_forwarding_join_the_same_action_list(tmp_path):
    # A client working through remediation needs one page, not a page per data
    # source. Rules come from the audit log, consents from the directory log.
    from postmortem.persistence import remediation_plan

    audit = {
        "malicious_rules": [{"time": "2026-08-25T15:54:33Z", "user": "victim@acme.com",
                             "client_ip": PERSIST_ATK, "keywords": ["invoice"],
                             "forwards": [], "delete": True}],
        "forwarding_rules": [{"time": "2026-08-25T15:55:00Z", "user": "victim@acme.com",
                        "client_ip": PERSIST_ATK,
                        "forwards": ["exfil@attacker.example"]}],
    }
    plan = remediation_plan(None, audit)
    kinds = [a["kind"] for a in plan]
    assert "inbox_rule" in kinds and "forwarding" in kinds
    assert all(a["by_attacker"] for a in plan)
    assert [a["priority"] for a in plan] == [1, 2]
    fwd = [a for a in plan if a["kind"] == "forwarding"][0]
    assert "exfil@attacker.example" in fwd["target"]


def test_the_action_list_leads_with_what_survives(tmp_path):
    from postmortem.persistence import (parse_entra_audit, analyze_persistence,
                                        remediation_plan, _flatten)

    events = parse_entra_audit([_flatten(e) for e in [
        _audit_event("Add device", "2026-08-25T15:58:00Z", PERSIST_ATK, "WIN-TEMP01"),
        _audit_event("Consent to application", "2026-08-25T15:47:00Z",
                     PERSIST_ATK, "Mail Archiver Pro", "Mail.ReadWrite offline_access"),
    ]])
    out = analyze_persistence({"entra_audit": events}, attacker_ips=[PERSIST_ATK],
                              compromise_dt=_compromise())
    plan = remediation_plan(out)
    assert plan[0]["kind"] == "oauth_consent", [a["kind"] for a in plan]
    assert plan[0]["survives_password_reset"] == "survives"


def test_no_persistence_data_is_unknown_not_clean(tmp_path):
    # The honest answer without the data is "cannot be assessed". Reporting a
    # clean bill of health from sources that structurally cannot see a consent
    # grant is the single worst thing this module could do.
    from postmortem.persistence import analyze_persistence

    out = analyze_persistence({})
    assert out["available"] is False
    assert out["findings"] == []
    assert any("CANNOT be assessed" in w for w in out["warnings"])

    # And a partial collection says which half is missing.
    partial = analyze_persistence({"entra_audit": []}, attacker_ips=[PERSIST_ATK])
    assert any("Get-OAuthPermissionsGraph" in w for w in partial["warnings"])


def test_only_devices_registered_in_the_window_are_reported(tmp_path):
    # The tenant's ordinary laptops are not a finding and would bury the one
    # the attacker joined.
    from postmortem.persistence import parse_devices, analyze_persistence

    devices = parse_devices([
        {"displayname": "DESKTOP-OLD", "deviceid": "d1",
         "registrationdatetime": "2024-03-01T09:00:00Z"},
        {"displayname": "WIN-TEMP01", "deviceid": "d2",
         "registrationdatetime": "2026-08-25T15:58:00Z"},
    ])
    out = analyze_persistence({"devices": devices}, attacker_ips=[PERSIST_ATK],
                              compromise_dt=_compromise())
    assert [f["name"] for f in out["findings"]] == ["WIN-TEMP01"]


# ---- the MES dispatcher --------------------------------------------------
def test_files_are_identified_by_name_then_header(tmp_path):
    from postmortem.mes import identify

    # Filename alone is enough when it is unambiguous.
    p = tmp_path / "OAuthPermissions.csv"
    p.write_text("ApplicationName,Permission\nX,Mail.Read\n", encoding="utf-8")
    assert identify(str(p)) == "oauth_permissions"

    # "AuditLogs" matches both the directory audit and the unified audit log,
    # so the header has to break the tie -- and getting this wrong would feed
    # a UAL export to the directory parser and report nothing.
    d = tmp_path / "AuditLogs-entra.json"
    d.write_text('[{"activityDisplayName":"Consent to application",'
                 '"initiatedBy":{},"targetResources":[]}]', encoding="utf-8")
    assert identify(str(d)) == "entra_audit"

    u = tmp_path / "AuditLogs-ual.csv"
    u.write_text("CreationTime,RecordType,AuditData\n2026-01-01,1,{}\n",
                 encoding="utf-8")
    assert identify(str(u)) == "unified_audit"


def test_an_unrecognised_file_is_reported_not_skipped(tmp_path):
    # An analyst who exported something and does not see it counted needs to
    # know the tool did not read it.
    from postmortem.mes import discover

    (tmp_path / "MFA.csv").write_text("UserPrincipalName,MFAEnabled\na,True\n",
                                      encoding="utf-8")
    (tmp_path / "notes.json").write_text('[{"hello":"world"}]', encoding="utf-8")
    by_kind, unrecognised, seen = discover(str(tmp_path))

    assert seen == 2
    assert "mfa" in by_kind
    assert [p.endswith("notes.json") for p in unrecognised] == [True]


def test_an_explicit_flag_overrides_what_discovery_found(tmp_path):
    from postmortem.mes import collect

    tree = tmp_path / "mes"
    tree.mkdir()
    (tree / "OAuthPermissions.csv").write_text(
        "ApplicationName,Permission,Id\nDiscovered,Mail.Read,g1\n",
        encoding="utf-8")
    other = tmp_path / "hand-picked.csv"
    other.write_text("ApplicationName,Permission,Id\nChosen,Mail.Send,g2\n",
                     encoding="utf-8")

    found = collect(str(tree))
    assert [g["targets"][0] for g in found["sources"]["oauth_permissions"]] \
        == ["Discovered"]

    overridden = collect(str(tree), {"oauth_permissions": str(other)})
    assert [g["targets"][0] for g in overridden["sources"]["oauth_permissions"]] \
        == ["Chosen"]


def test_csv_and_json_are_both_read(tmp_path):
    from postmortem.persistence import load_rows

    c = tmp_path / "a.csv"
    c.write_text("UserPrincipalName,MFAEnabled\nvictim@acme.com,True\n",
                 encoding="utf-8")
    assert load_rows(str(c))[0]["userprincipalname"] == "victim@acme.com"

    j = tmp_path / "b.json"
    j.write_text('{"value":[{"UserPrincipalName":"victim@acme.com"}]}',
                 encoding="utf-8")
    assert load_rows(str(j))[0]["userprincipalname"] == "victim@acme.com"

    # A semicolon export, which is what a European locale produces.
    s = tmp_path / "c.csv"
    s.write_text("UserPrincipalName;MFAEnabled\nvictim@acme.com;True\n",
                 encoding="utf-8")
    assert load_rows(str(s))[0]["userprincipalname"] == "victim@acme.com"

    assert load_rows(str(tmp_path / "missing.csv")) == []


def test_persistence_reaches_the_timeline_and_serialises(tmp_path):
    from postmortem.persistence import (parse_entra_audit, analyze_persistence,
                                        strip_private, _flatten)
    from postmortem.scoring import build_attack_timeline
    import json

    events = parse_entra_audit([_flatten(_audit_event(
        "Consent to application", "2026-08-25T15:47:00Z", PERSIST_ATK,
        "Mail Archiver Pro", "Mail.ReadWrite offline_access"))])
    out = analyze_persistence({"entra_audit": events}, attacker_ips=[PERSIST_ATK],
                              compromise_dt=_compromise())

    timeline = build_attack_timeline([], None, out)
    assert len(timeline) == 1
    e = timeline[0]
    assert e.source == "persistence"
    assert e.stage == "persistence"
    assert "Mail Archiver Pro" in e.subject
    assert e.client_ip == PERSIST_ATK
    assert e.score == 0, "a recorded fact carries no score"

    # The parsed datetimes are working values and are not serialisable.
    json.dumps(strip_private(out))

    # And the timeline is inert without persistence, as every existing run is.
    assert build_attack_timeline([], None, None) == []



# --------------------------------------------------------------------------
# Tenant directory and mailbox configuration
#
# Everything the tool knows about the client's own organisation is otherwise
# inferred from the corpus: internal domains from who appears on both sides of
# enough messages, known contacts from who sends often enough to look
# established. Both inferences are load-bearing and both fail the same way --
# a colleague who rarely emails this mailbox never becomes familiar, so their
# name being copied is invisible.
# --------------------------------------------------------------------------

def _dir_users():
    from postmortem.directory import parse_users
    return parse_users([
        {"userprincipalname": "jane.doe@acme.com", "displayname": "Jane Doe",
         "jobtitle": "Chief Financial Officer", "department": "Finance",
         "accountenabled": "True",
         "proxyaddresses": "smtp:j.doe@acme.com;smtp:jane@acme.com"},
        {"userprincipalname": "ap@acme.com", "displayname": "Accounts Payable",
         "jobtitle": "AP Clerk", "accountenabled": "True"},
    ])


def test_the_directory_names_who_was_impersonated(tmp_path):
    # The finding the corpus cannot make. Jane emails this mailbox twice a
    # year, so she is not a "frequent sender" and the display-name check has
    # nothing to compare against -- yet her name on an outside address is the
    # entire attack.
    from postmortem.directory import Directory

    d = Directory(_dir_users(), ["acme.com"])
    imp = d.impersonation_of("Jane Doe", "j.doe@acrne-corp.example")
    assert imp is not None
    assert imp["real_address"] == "jane.doe@acme.com"
    assert imp["title"] == "Chief Financial Officer"
    assert imp["observed_address"] == "j.doe@acrne-corp.example"

    # It really being her is not impersonation -- including on an alias, which
    # the corpus would have treated as a different person entirely.
    assert d.impersonation_of("Jane Doe", "jane.doe@acme.com") is None
    assert d.impersonation_of("Jane Doe", "jane@acme.com") is None
    # A name nobody in the directory has says nothing either way.
    assert d.impersonation_of("Bob Stranger", "bob@ext.example") is None


def test_display_names_match_the_way_a_human_reads_them(tmp_path):
    # An attacker copies what the recipient sees, not what the directory
    # stores, so punctuation, case and word order must not defeat the match.
    from postmortem.directory import Directory

    d = Directory(_dir_users(), ["acme.com"])
    for spelling in ("Jane Doe", "jane doe", "JANE DOE", "Doe, Jane",
                     "Jane  Doe", "Jane Doe."):
        assert d.impersonation_of(spelling, "x@ext.example"), spelling
    assert d.impersonation_of("Janet Doe", "x@ext.example") is None


def test_accepted_domains_replace_the_inferred_ones(tmp_path):
    from postmortem.directory import parse_accepted_domains, Directory

    doms = parse_accepted_domains([
        {"domainname": "acme.com", "domaintype": "Authoritative"},
        {"domainname": "ACME-CORP.COM", "domaintype": "Authoritative"},
        {"domainname": "", "domaintype": "x"},
    ])
    assert doms == ["acme-corp.com", "acme.com"]

    # A domain the tenant's own accounts sign in under counts even when the
    # accepted-domain export was not collected.
    d = Directory(_dir_users(), [])
    assert d.is_internal_domain("acme.com")
    assert not d.is_internal_domain("acrne-corp.example")


def test_ordinary_mail_management_is_not_persistence(tmp_path):
    # Every tenant has rules filing mail into Archive. Reporting each of them
    # as suspected persistence is how an action list stops being read.
    from postmortem.directory import parse_mailbox_rules

    rules = parse_mailbox_rules([
        {"rulename": "Archive old", "mailbox": "ap@acme.com",
         "movetofolder": "Archive"},
        {"rulename": "Newsletters", "mailbox": "ap@acme.com",
         "movetofolder": "Junk"},
        # ... but a folder with no ordinary use does count,
        {"rulename": ".", "mailbox": "ap@acme.com", "movetofolder": "RSS Feeds"},
        # ... as does one that files AND selects on concealment keywords,
        {"rulename": "x", "mailbox": "ap@acme.com", "movetofolder": "Archive",
         "subjectcontainswords": "invoice,wire"},
        # ... and forwarding or deleting is concealment by itself.
        {"rulename": "f", "mailbox": "ap@acme.com",
         "forwardto": "exfil@attacker.example"},
        {"rulename": "d", "mailbox": "ap@acme.com", "deletemessage": "True"},
    ])
    conceals = [r["name"] for r in rules if r["conceals"]]
    assert conceals == [".", "x", "f", "d"], conceals


def test_configuration_the_audit_log_never_saw_created(tmp_path):
    # The audit log can only report what happened while it was watching. A
    # rule that predates its window is invisible there, and its silence reads
    # exactly like the rule's absence.
    from postmortem.directory import (parse_mailbox_rules,
                                      parse_mailbox_permissions,
                                      config_drift, Directory)

    sources = {
        "mailbox_rules": parse_mailbox_rules([
            {"rulename": "recorded", "mailbox": "ap@acme.com",
             "forwardto": "known@attacker.example"},
            {"rulename": "unrecorded", "mailbox": "ap@acme.com",
             "forwardto": "exfil@attacker.example"},
        ]),
        "mailbox_permissions": parse_mailbox_permissions([
            {"identity": "ap@acme.com", "user": "jane.doe@acme.com",
             "accessrights": "FullAccess"},
            {"identity": "ap@acme.com",
             "user": "consultant@external-partner.example",
             "accessrights": "FullAccess"},
            # Self and machine principals are noise, never findings.
            {"identity": "ap@acme.com", "user": "NT AUTHORITY\\\\SELF",
             "accessrights": "FullAccess"},
        ]),
    }
    audit = {"malicious_rules": [
        {"time": "2026-08-26T10:00:00Z", "user": "ap@acme.com",
         "client_ip": "45.147.230.88", "forwards": ["known@attacker.example"],
         "keywords": [], "move_to": ""}]}

    drift = config_drift(sources, audit, Directory(_dir_users(), ["acme.com"]))
    assert drift["available"] is True
    # The rule the audit log explains is not reported again here.
    assert [r["name"] for r in drift["unexplained_rules"]] == ["unrecorded"]
    assert drift["external_forwarders"] == 1

    # Delegation to a colleague is normal; to an outside address is not.
    assert drift["external_delegates"] == 1
    ext = [d for d in drift["delegations"] if d["external"]]
    assert ext[0]["trustee"] == "consultant@external-partner.example"
    assert all("nt authority" not in d["trustee"] for d in drift["delegations"])

    # And it is offered as unexplained, never as proven.
    assert "not proof" in drift["note"]


def test_drift_becomes_remediation_without_claiming_attribution(tmp_path):
    from postmortem.directory import parse_mailbox_rules, config_drift, Directory
    from postmortem.persistence import remediation_plan

    sources = {"mailbox_rules": parse_mailbox_rules([
        {"rulename": "hidden", "mailbox": "ap@acme.com",
         "forwardto": "exfil@attacker.example"}])}
    drift = config_drift(sources, None, Directory(_dir_users(), ["acme.com"]))

    plan = remediation_plan(None, None, drift)
    assert len(plan) == 1
    a = plan[0]
    assert a["kind"] == "inbox_rule"
    # Unattributed: it predates the window rather than being tied to anyone.
    assert a["by_attacker"] is False
    assert "not recorded in the audit log window" in a["attribution"]
    assert a["survives_password_reset"] == "survives"
    assert "exfil@attacker.example" in a["grants"]


def test_attacker_attributed_actions_outrank_unexplained_ones(tmp_path):
    from postmortem.directory import parse_mailbox_rules, config_drift, Directory
    from postmortem.persistence import remediation_plan

    drift = config_drift(
        {"mailbox_rules": parse_mailbox_rules([
            {"rulename": "old", "mailbox": "ap@acme.com",
             "forwardto": "legacy@partner.example"}])},
        None, Directory(_dir_users(), ["acme.com"]))
    audit = {"forwarding_rules": [
        {"time": "2026-08-26T10:00:00Z", "user": "ap@acme.com",
         "client_ip": "45.147.230.88", "forwards": ["exfil@attacker.example"]}]}

    plan = remediation_plan(None, audit, drift)
    assert plan[0]["by_attacker"] is True
    assert plan[0]["kind"] == "forwarding"
    assert plan[-1]["by_attacker"] is False


# ---- E4: the audit-status export settles what UNKNOWN was hiding ---------
def test_disabled_auditing_is_a_different_answer_from_unknown(tmp_path):
    from postmortem.directory import parse_mailbox_audit_status, audit_coverage_for
    from postmortem.scoring import exposure_scope

    status = parse_mailbox_audit_status([
        {"identity": "ap@acme.com", "auditenabled": "False",
         "auditowner": "", "auditlogagelimit": "90"}])
    cov = audit_coverage_for(status, "ap@acme.com")
    assert cov["mailbox_matched"] is True
    assert cov["audit_enabled"] is False

    summary = {"message_index": {"by_message_id": {}},
               "coverage": {"operations": [("HardDelete", 1)]}}
    out = exposure_scope([], summary, cov)
    assert out["available"] is False
    assert out["audit_status_known"] is True
    assert "DISABLED" in out["reason"]
    assert "licensing" in out["reason"]


def test_enabled_auditing_makes_silence_meaningful(tmp_path):
    from postmortem.directory import parse_mailbox_audit_status, audit_coverage_for
    from postmortem.scoring import exposure_scope

    status = parse_mailbox_audit_status([
        {"identity": "ap@acme.com", "auditenabled": "True",
         "auditowner": "MailItemsAccessed, HardDelete, Update"}])
    cov = audit_coverage_for(status, "ap@acme.com")
    assert cov["records_mail_access"] is True

    out = exposure_scope([], {"message_index": {"by_message_id": {}},
                              "coverage": {"operations": [("HardDelete", 1)]}},
                         cov)
    assert out["meaningful_silence"] is True
    assert "evidence rather than a licensing gap" in out["reason"]

    # Enabled, but not recording reads: a third answer again.
    partial = audit_coverage_for(parse_mailbox_audit_status([
        {"identity": "ap@acme.com", "auditenabled": "True",
         "auditowner": "HardDelete, Update"}]), "ap@acme.com")
    out2 = exposure_scope([], {"message_index": {"by_message_id": {}},
                               "coverage": {"operations": [("HardDelete", 1)]}},
                          partial)
    assert out2.get("meaningful_silence") is not True
    assert "not in the audited action set" in out2["reason"]


def test_without_the_status_export_the_answer_stays_unknown(tmp_path):
    # The honest default must survive: no status export means the old answer.
    from postmortem.scoring import exposure_scope

    out = exposure_scope([], {"message_index": {"by_message_id": {}},
                              "coverage": {"operations": [("HardDelete", 1)]}})
    assert out["available"] is False
    assert out["audit_status_known"] is False
    assert "UNKNOWN" in out["reason"]
    assert "Get-MailboxAuditStatus" in out["reason"]


def test_status_for_the_wrong_mailbox_claims_nothing(tmp_path):
    from postmortem.directory import parse_mailbox_audit_status, audit_coverage_for

    status = parse_mailbox_audit_status([
        {"identity": "someone@other.example", "auditenabled": "True"},
        {"identity": "another@other.example", "auditenabled": "True"},
    ])
    cov = audit_coverage_for(status, "ap@acme.com")
    assert cov["mailbox_matched"] is False
    assert "none matches" in cov["note"]
    assert audit_coverage_for({}, "ap@acme.com") == {}


def test_directory_sources_are_discovered_and_routed(tmp_path):
    from postmortem.mes import identify, collect

    u = tmp_path / "Users.csv"
    u.write_text("UserPrincipalName,DisplayName,AccountEnabled\n"
                 "jane.doe@acme.com,Jane Doe,True\n", encoding="utf-8")
    assert identify(str(u)) == "users"

    s = tmp_path / "MailboxAuditStatus.csv"
    s.write_text("Identity,AuditEnabled,AuditOwner\nap@acme.com,False,\n",
                 encoding="utf-8")
    assert identify(str(s)) == "mailbox_audit_status"

    # Inbox rules and transport rules are different things and used to share
    # one recogniser, which sent tenant-wide rules to the mailbox parser.
    i = tmp_path / "InboxRules.csv"
    i.write_text("RuleName,Mailbox,ForwardTo\nx,a@b.com,c@d.com\n", encoding="utf-8")
    t = tmp_path / "TransportRules.csv"
    t.write_text("Name,State,RedirectMessageTo\ny,Enabled,c@d.com\n", encoding="utf-8")
    assert identify(str(i)) == "mailbox_rules"
    assert identify(str(t)) == "transport_rules"

    bundle = collect(str(tmp_path))
    # Audit status is keyed by mailbox: it must merge as a map, not a list.
    assert isinstance(bundle["sources"]["mailbox_audit_status"], dict)
    assert "ap@acme.com" in bundle["sources"]["mailbox_audit_status"]
    assert len(bundle["sources"]["users"]) == 1


def test_no_directory_changes_nothing(tmp_path):
    # Every existing run must behave exactly as before.
    from postmortem.directory import build_directory, config_drift
    from postmortem.scoring import run_scenario_analysis
    from postmortem.models import Anchors

    empty = build_directory({})
    assert not empty
    assert empty.impersonation_of("Jane Doe", "x@y.example") is None
    assert config_drift({})["available"] is False

    r = make_record(sender_email="a@ext.example", sender_domain="ext.example",
                    path="/m/1.eml")
    r.body = "Hello."
    r.urls = []; r.url_analysis = []; r.attachments = []
    r.attachment_details = []; r.authentication_results = {}
    _s, _rsn, verdict = run_scenario_analysis([r], {"acme.com"}, Anchors(),
                                              None, directory=None)
    assert verdict["exposure_scope"] == {} or not verdict["exposure_scope"].get(
        "available")



# --------------------------------------------------------------------------
# Reply-To: the finding that crashed a production run
#
# score_initial_email read `record.reply_to`, which EmailRecord has never had
# -- it has `in_reply_to` (the threading header) and `reply_to_mismatch` (a
# bool), but the address itself was parsed and then thrown away. The branch
# only runs for a message whose Reply-To domain differs from its From domain
# AND which reaches initial-email scoring, so a whole corpus could analyse
# cleanly and the next one would die four thousand events in.
#
# No test covered it, which is exactly how it shipped.
# --------------------------------------------------------------------------
def _reply_to_record(path="/m/rt.eml", sender="ap@supplier.example",
                     reply_to="attacker@gmail.example"):
    r = make_record(sender_email=sender, sender_domain=sender.split("@")[1],
                    subject="Updated remittance details", path=path,
                    date="Wed, 26 Aug 2026 09:00:00 +0000")
    r.body = ("Please update our bank details before the next payment run "
              "and confirm the wire transfer today.")
    r.urls = []; r.url_domains = []; r.url_analysis = []
    r.attachments = []; r.attachment_details = []
    r.authentication_results = {"reply_to": reply_to}
    return r


def test_a_reply_to_mismatch_does_not_crash_the_run(tmp_path):
    from postmortem.scoring import run_scenario_analysis
    from postmortem.models import Anchors

    r = _reply_to_record()
    # The crash was an AttributeError raised inside scoring, so simply
    # completing is most of the assertion.
    run_scenario_analysis([r], {"acme.com"}, Anchors())

    assert r.reply_to_mismatch is True
    assert r.reply_to_address == "attacker@gmail.example"


def test_the_reply_to_finding_names_both_addresses(tmp_path):
    # The mismatch flag alone cannot say WHERE a reply would have gone, which
    # is the whole evidence for the finding.
    from postmortem.scoring import run_scenario_analysis
    from postmortem.models import Anchors

    r = _reply_to_record()
    run_scenario_analysis([r], {"acme.com"}, Anchors())

    found = [f for f in (list(r.provenance) + list(r.scenario_findings))
             if f["source"] == "header:Reply-To"]
    assert found, "the Reply-To finding must be recorded"
    for f in found:
        assert "ap@supplier.example" in f["matched"], f
        assert "attacker@gmail.example" in f["matched"], f


def test_a_matching_reply_to_is_not_a_finding(tmp_path):
    from postmortem.scoring import run_scenario_analysis
    from postmortem.models import Anchors

    same = _reply_to_record(reply_to="ap@supplier.example")
    none = _reply_to_record(path="/m/rt2.eml", reply_to="")
    run_scenario_analysis([same, none], {"acme.com"}, Anchors())

    assert same.reply_to_mismatch is False
    assert none.reply_to_mismatch is False
    for r in (same, none):
        assert not [f for f in (list(r.provenance) + list(r.scenario_findings))
                    if f["source"] == "header:Reply-To"]


def test_every_record_attribute_scoring_touches_actually_exists(tmp_path):
    # The general form of the bug: scoring reads an attribute off a record
    # that EmailRecord does not define, and nothing notices until a corpus
    # happens to take that branch. Cheaper to assert statically than to hope
    # a fixture covers every path.
    import ast
    import dataclasses
    import io
    import os
    from postmortem.models import EmailRecord

    known = {f.name for f in dataclasses.fields(EmailRecord)}
    known |= {n for n in dir(EmailRecord) if not n.startswith("__")}
    # `r` is also a conventional name for a dict row or a regex match in these
    # files, so anything that is a method of a builtin container says the
    # variable is not a record and the access is not evidence of anything.
    for builtin in (dict, str, list, set, tuple):
        known |= {n for n in dir(builtin) if not n.startswith("__")}
    known |= {"group", "groups", "groupdict", "start", "end", "span"}
    record_vars = {"r", "record", "rec"}

    here = os.path.dirname(os.path.abspath(__file__))
    missing = []
    for name in ("scoring.py", "reporting.py", "iocs.py", "clustering.py"):
        path = os.path.join(here, "postmortem", name)
        if not os.path.exists(path):
            continue
        tree = ast.parse(io.open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id in record_vars
                    and not node.attr.startswith("_")
                    and node.attr not in known):
                missing.append("%s:%d  %s.%s"
                               % (name, node.lineno, node.value.id, node.attr))
    assert not missing, "attributes EmailRecord does not define:\n" + "\n".join(missing)



# --------------------------------------------------------------------------
# Forced-branch sweep
#
# Two crashes shipped inside a month with the same shape: a flag set in one
# pass, and a value read in another that assumed the flag implied it.
# `record.reply_to` did not exist at all; `attach_notes[0]` indexed a list
# that a separate boolean claimed was populated. Neither was reachable from
# any fixture, so 168 passing tests said nothing about either.
#
# Coverage by example cannot fix that -- there are too many flag
# combinations to enumerate by hand. These take both extremes instead: a
# record with every field set, and a record with nothing set, through every
# entry point. A finding branch that reads something it should not is then a
# test failure rather than a run that dies four thousand events in.
# --------------------------------------------------------------------------
def _maximal_record(path="/m/max.eml"):
    """Every flag true, every collection populated. Coherent, not realistic."""
    import dataclasses
    from postmortem.models import EmailRecord

    r = EmailRecord(path=path, filename=path.rsplit("/", 1)[-1])
    for f in dataclasses.fields(EmailRecord):
        if f.name in ("path", "filename"):
            continue
        t = str(f.type)
        if "bool" in t:
            setattr(r, f.name, True)
        elif "list" in t:
            setattr(r, f.name, ["alpha", "beta"])
        elif "dict" in t:
            setattr(r, f.name, {"k": "v"})
        elif "float" in t:
            setattr(r, f.name, 0.9)
        elif "int" in t:
            setattr(r, f.name, 3)
        elif "str" in t and not getattr(r, f.name):
            setattr(r, f.name, "x")

    # Enough coherence to traverse: parsable addresses, a real date, and the
    # structured fields in the shapes their readers expect.
    r.sender_email = "ap@supplier.example"
    r.sender_domain = "supplier.example"
    r.sender_name = "Jane Doe"
    r.recipients = ["victim@acme.com"]
    r.cc = []
    r.date = "Wed, 26 Aug 2026 09:00:00 +0000"
    r.subject = "Updated remittance details"
    r.body = "Please update the bank details and wire the payment today."
    r.message_id = "<max@supplier.example>"
    r.authentication_results = {
        "reply_to": "attacker@gmail.example",
        "received": ["from a by b; Wed, 26 Aug 2026 09:00:00 +0000"],
    }
    r.urls = ["https://evil.example/owa/login"]
    r.url_domains = ["evil.example"]
    r.url_analysis = [{"url": "https://evil.example/owa/login", "risk_score": 12,
                       "suspicious_score": 12, "path": "/owa/login",
                       "registrable_domain": "evil.example", "flags": []}]
    r.attachments = ["a.zip"]
    r.attachment_details = [{"flags": ["archive contains executable"],
                             "name": "a.zip", "sha256": "d" * 64}]
    r.audit_events = [{"operation": "HardDelete", "time": "2026-08-26T10:00:00Z",
                       "client_ip": "203.0.113.9", "verb": "hard-deleted",
                       "by_attacker": True, "deliberate": True,
                       "folder": "\\\\Inbox", "subject": "x", "user": "v@acme.com"}]
    r.directory_impersonation = {"real_address": "jane.doe@acme.com",
                                 "display_name": "Jane Doe", "title": "CFO",
                                 "department": "", "observed_address": r.sender_email,
                                 "other_matches": []}
    r.signin_events = []
    r.provenance = []
    r.scenario_findings = []
    r.indicators = []
    r.scenario_reasons = []
    return r


def test_every_finding_branch_survives_a_fully_populated_record(tmp_path):
    # This is the test that would have caught attach_notes[0]: the flag says
    # there is a dangerous attachment, and the branch indexes a list computed
    # separately that can legitimately be empty.
    from postmortem import scoring
    from postmortem.models import Anchors

    anchors = Anchors()
    scoring.score_initial_email(_maximal_record(), "ato", anchors)
    scoring.score_initial_email(_maximal_record("/m/b.eml"), "impersonation", anchors)
    scoring.calculate_score(_maximal_record("/m/c.eml"), {"acme.com"}, set())
    scoring.classify_attack_stage(_maximal_record("/m/d.eml"))
    scoring.candidate_score(_maximal_record("/m/e.eml"))

    recs = [_maximal_record("/m/f.eml"), _maximal_record("/m/g.eml")]
    _s, _r, verdict = scoring.run_scenario_analysis(recs, {"acme.com"}, anchors)
    assert verdict["tier_counts"]

    scoring.build_attack_timeline(recs, None, None)
    scoring.build_evidence_graph(recs)


def test_the_attachment_finding_survives_a_flag_without_notes(tmp_path):
    # The exact divergence: a record restored from a cache written by an
    # earlier parser carries attachment_threat=True while the current
    # summary produces nothing. It must still name something.
    from postmortem.scoring import score_initial_email
    from postmortem.models import Anchors

    r = _maximal_record("/m/att.eml")
    r.attachment_details = []          # summary will now yield no notes ...
    r.attachments = []
    r.attachment_threat = True         # ... but the flag survives from before
    r.attachment_threat_note = ""      # and the note is gone too

    score_initial_email(r, "ato", Anchors())
    found = [f for f in r.scenario_findings if f["category"] == "attachment"]
    assert found, "the finding must still be emitted"
    assert "unspecified" in found[0]["signal"]

    # With a note retained, that is what gets named.
    r2 = _maximal_record("/m/att2.eml")
    r2.attachment_details = []
    r2.attachments = []
    r2.attachment_threat = True
    r2.attachment_threat_note = "YARA: maldoc_dropper"
    score_initial_email(r2, "ato", Anchors())
    found2 = [f for f in r2.scenario_findings if f["category"] == "attachment"]
    assert "YARA: maldoc_dropper" in found2[0]["signal"]


def test_every_entry_point_survives_an_empty_corpus(tmp_path):
    # The other extreme, and the one that guards the [0]-on-empty family.
    from postmortem import scoring, reporting
    from postmortem.models import EmailRecord, Anchors

    anchors = Anchors()
    bare = EmailRecord(path="/m/bare.eml", filename="bare.eml")

    scoring.score_initial_email(bare, "ato", anchors)
    scoring.calculate_score(EmailRecord(path="/a", filename="a"), set(), set())
    scoring.candidate_score(EmailRecord(path="/b", filename="b"))
    scoring.classify_attack_stage(EmailRecord(path="/c", filename="c"))
    scoring.run_scenario_analysis([], set(), Anchors())
    scoring.build_attack_timeline([], None, None)
    scoring.build_evidence_graph([])
    scoring.corpus_baseline([])
    scoring.identify_internal_domains([])
    scoring.assign_tiers([], "ato", anchors)
    scoring.exposure_scope([], None)
    scoring.deletion_completeness([], None)
    scoring.attacker_authorship([], None, anchors)
    scoring.replay_rules([], None)
    scoring.signin_lure_window([], None)
    reporting.candidate_sort_key(EmailRecord(path="/e", filename="e"))


def test_every_printer_survives_nothing_to_print(tmp_path):
    # A printer that raises on an absent section turns an optional input into
    # a required one, which is how an evidence source nobody supplied becomes
    # a crash.
    from postmortem import reporting, scoring
    from postmortem.models import EmailRecord, Anchors

    _s, _r, verdict = scoring.run_scenario_analysis(
        [EmailRecord(path="/f", filename="f")], set(), Anchors())

    for name in ("print_audit_join", "print_deletion_completeness",
                 "print_attacker_authorship", "print_exposure_scope",
                 "print_rule_replay", "print_signin_lures"):
        fn = getattr(reporting, name, None)
        if fn:
            fn(verdict)
            fn({})
            fn(None)

    for name in ("print_persistence", "print_remediation", "print_mes_manifest",
                 "print_directory", "print_signin_analysis",
                 "print_attacker_ip_activity", "print_audit_summary"):
        fn = getattr(reporting, name, None)
        if fn:
            fn(None)
            fn({})



# --------------------------------------------------------------------------
# Build verification
#
# The code is edited on one machine and run on another, and it travels by
# hand. The same defect survived two syncs and produced two identical
# tracebacks an hour into two separate runs, because an incomplete copy
# imports cleanly, passes a grep for whatever was last fixed, and runs the
# old logic anyway. Nothing in the tool could tell the difference.
# --------------------------------------------------------------------------
def _fake_package(tmp_path, files=None):
    """A miniature package directory with a manifest beside it."""
    from postmortem.build_check import write_manifest

    pkg = tmp_path / "postmortem"
    pkg.mkdir()
    for name, body in (files or {"a.py": "A = 1\n", "b.py": "B = 2\n"}).items():
        (pkg / name).write_text(body, encoding="utf-8")
    write_manifest(pkg, tool_version="9.9", parser_version="9.9-test")
    return pkg


def test_a_complete_copy_verifies(tmp_path):
    from postmortem.build_check import verify

    pkg = _fake_package(tmp_path)
    result = verify(pkg)
    assert result["checked"] is True
    assert result["ok"] is True
    assert result["build_id"] == result["expected"]
    assert result["differing"] == [] and result["missing"] == []


def test_bulk_term_matching_agrees_with_matching_one_at_a_time(tmp_path):
    """The optimisation must be invisible in behaviour, only in time.

    Scoring ran one compiled regex per phrase over the full body -- 66 scans
    per message, 95% of calculate_score's time proving negatives. The bulk
    form rejects a phrase whose first word is absent before running the
    regex, which cannot turn a match into a miss; this asserts that over
    text with the awkward cases: flexible whitespace, case, punctuation.
    """
    import random
    from postmortem.scoring import term_present, terms_present, _COMBO_TERMS
    from postmortem.config import PHISHING_TERMS

    phrases = list(PHISHING_TERMS) + list(_COMBO_TERMS)
    vocab = ("the please review attached account invoice payment wire transfer "
             "bank details urgent immediately confidential password login sign "
             "in click here gift card remittance today action required").split()

    random.seed(4)
    for i in range(600):
        text = " ".join(random.choices(vocab, k=random.randint(3, 50)))
        if i % 3 == 0:
            text = text.replace(" ", "  ", 3)      # flexible whitespace
        if i % 5 == 0:
            text = text.upper()                     # case
        if i % 11 == 0:
            text = text + " don't tell anyone."     # punctuation in a phrase
        assert terms_present(text, phrases) == {
            p for p in phrases if term_present(p, text)}, text[:80]

    assert terms_present("", phrases) == set()
    assert terms_present("anything", []) == set()


def test_the_combination_term_lists_have_one_source(tmp_path):
    # Writing the scanned set out by hand dropped eight terms the first time,
    # silently: remittance, payment, change bank, don't tell and others
    # stopped matching while every test still passed.
    from postmortem.scoring import (_COMBO_TERMS, _PAYMENT_TERMS,
                                    _URGENCY_COMBO_TERMS, _SECRECY_TERMS)

    for group in (_PAYMENT_TERMS, _URGENCY_COMBO_TERMS, _SECRECY_TERMS):
        assert group, "a combination group must not be empty"
        for term in group:
            assert term in _COMBO_TERMS, term
    assert len(_COMBO_TERMS) == (len(_PAYMENT_TERMS) + len(_URGENCY_COMBO_TERMS)
                                 + len(_SECRECY_TERMS))
    # The terms that were dropped, named so a future edit cannot lose them again.
    for term in ("remittance", "payment", "change bank", "don't tell",
                 "keep this confidential", "do not tell"):
        assert term in _COMBO_TERMS, term


def test_a_checkout_style_is_not_a_stale_file(tmp_path):
    """git on Windows rewrites line endings; that is not a code change.

    Hashing raw bytes meant a correct, complete copy pulled through git with
    core.autocrlf=true reported EVERY file stale. A verifier that cries wolf
    on a good deployment is worse than none: it teaches the analyst to
    ignore the one warning that matters.
    """
    from postmortem.build_check import verify, file_digests

    pkg = _fake_package(tmp_path, {"a.py": "A = 1\nB = 2\n",
                                   "b.py": "C = 3\n"})
    before = dict(file_digests(pkg))

    for name in ("a.py", "b.py"):
        raw = (pkg / name).read_bytes()
        (pkg / name).write_bytes(raw.replace(b"\n", b"\r\n"))
    assert (pkg / "a.py").read_bytes().count(b"\r\n") == 2, "fixture must be CRLF"

    assert file_digests(pkg) == before, "line endings must not change the digest"
    result = verify(pkg)
    assert result["ok"] is True, result
    assert result["differing"] == []

    # ... but an actual content change is still caught, CRLF or not.
    (pkg / "a.py").write_bytes(b"A = 999\r\nB = 2\r\n")
    bad = verify(pkg)
    assert bad["ok"] is False
    assert bad["differing"] == ["a.py"]


def test_a_stale_file_is_named(tmp_path):
    # The real failure: everything copied except one file, which keeps its
    # previous content. The question the analyst has is not "is something
    # wrong" but "what do I copy again", so the answer has to be a filename.
    from postmortem.build_check import verify, describe

    pkg = _fake_package(tmp_path)
    (pkg / "a.py").write_text("A = 999  # stale\n", encoding="utf-8")

    result = verify(pkg)
    assert result["ok"] is False
    assert result["differing"] == ["a.py"]
    assert result["missing"] == []
    assert result["build_id"] != result["expected"]

    text = "\n".join(describe(result))
    assert "a.py" in text
    assert "STALE" in text


def test_a_file_that_never_arrived_is_named(tmp_path):
    from postmortem.build_check import verify, describe

    pkg = _fake_package(tmp_path)
    (pkg / "b.py").unlink()

    result = verify(pkg)
    assert result["ok"] is False
    assert result["missing"] == ["b.py"]
    assert "b.py" in "\n".join(describe(result))


def test_an_extra_file_is_not_a_failure(tmp_path):
    # A scratch file left in the package directory is untidy, not a stale
    # deployment, and treating it as one would train the warning to be ignored.
    from postmortem.build_check import verify

    pkg = _fake_package(tmp_path)
    (pkg / "scratch.py").write_text("# notes\n", encoding="utf-8")

    result = verify(pkg)
    assert result["ok"] is True
    assert result["extra"] == ["scratch.py"]


def test_a_tree_with_no_manifest_still_runs(tmp_path):
    # Every copy that predates this mechanism must behave exactly as before.
    # The failure being guarded against is silence, so the one thing this
    # must never do is introduce a new way to stop.
    from postmortem.build_check import verify, describe, read_manifest

    pkg = tmp_path / "postmortem"
    pkg.mkdir()
    (pkg / "a.py").write_text("A = 1\n", encoding="utf-8")

    assert read_manifest(pkg) is None
    result = verify(pkg)
    assert result["checked"] is False
    assert result["ok"] is True
    assert result["build_id"]
    assert describe(result) == []


def test_an_unreadable_manifest_is_not_fatal(tmp_path):
    from postmortem.build_check import verify

    pkg = _fake_package(tmp_path)
    (pkg / "BUILD.json").write_text("{ this is not json", encoding="utf-8")

    result = verify(pkg)
    assert result["checked"] is False
    assert result["ok"] is True


def test_the_build_id_changes_with_content_not_with_name(tmp_path):
    # Two copies both calling themselves 8.3 with different content must not
    # produce the same id -- that identity is the entire point.
    from postmortem.build_check import build_id, file_digests

    pkg = _fake_package(tmp_path)
    before = build_id(file_digests(pkg))
    (pkg / "a.py").write_text("A = 2\n", encoding="utf-8")
    after = build_id(file_digests(pkg))
    assert before != after

    # ... and it is stable for identical content.
    (pkg / "a.py").write_text("A = 1\n", encoding="utf-8")
    assert build_id(file_digests(pkg)) == before


def test_the_shipped_package_matches_its_own_manifest(tmp_path):
    # Guards the release step itself: a manifest regenerated before the last
    # edit is worse than none, because it reports a clean tree as clean while
    # the deployed copy of it is not.
    from postmortem.build_check import verify

    result = verify()
    if not result["checked"]:
        import pytest
        pytest.skip("no BUILD.json in this working tree")
    assert result["ok"], (
        "BUILD.json is out of date with the package it sits in; "
        "regenerate it before syncing. differing=%s missing=%s"
        % (result["differing"], result["missing"]))



# --------------------------------------------------------------------------
# Weight tuning from the first real corpus (117,299 messages, 263 Tier 1)
#
# The measurements these encode:
#   rule-keyword anchor   87.1% of corpus, +3, lift 1.16x -> 44% of all score
#   missing Date header   20,985 fires, ~47 Tier 1 expected, 0 observed
#   Received out of order  4,001 fires, ~9 expected, 0 observed
#   auth failed (hard)     7,323 fires, lift 11.8x, scoring only +3
# --------------------------------------------------------------------------
def _kw_record(subject, body, path):
    r = make_record(sender_email="ap@ext.example", sender_domain="ext.example",
                    subject=subject, path=path,
                    date="Wed, 26 Aug 2026 09:00:00 +0000")
    r.body = body
    r.urls = []; r.url_domains = []; r.url_analysis = []
    r.attachments = []; r.attachment_details = []
    r.authentication_results = {}
    return r


def test_a_rule_keyword_matches_on_word_boundaries(tmp_path):
    # `kw in text` made 'pay' match 'company' and 'repay'. On a real corpus
    # the field-blind substring check fired on 87.1% of messages.
    from postmortem.scoring import build_rule_policy
    from postmortem.models import Anchors

    hit = _kw_record("Invoice", "Please pay this week.", "/m/1.eml")
    miss = _kw_record("Company news", "The company will repay the loan.",
                      "/m/2.eml")

    anchors = Anchors()
    anchors.rule_keywords = ["pay"]
    policy = build_rule_policy([hit, miss], anchors, None)

    # Both messages contain the letters "pay"; only one contains the word.
    assert policy["counts"]["pay"] == 1, policy["counts"]


def test_a_keyword_is_matched_in_the_field_the_rule_filtered_on(tmp_path):
    # A rule matching a word in the SUBJECT is a different rule from one
    # matching it anywhere in the body. Replaying them as one is why the
    # anchor found 102,153 messages where replay_rules found 11,820.
    from postmortem.scoring import build_rule_policy
    from postmortem.models import Anchors

    subject_only = _kw_record("Remittance advice", "Nothing notable.", "/m/a.eml")
    body_only = _kw_record("Monthly update", "See the remittance attached.",
                           "/m/b.eml")

    anchors = Anchors()
    anchors.rule_keywords = ["remittance"]
    audit = {"malicious_rules": [
        {"conditions": {"subject": ["remittance"]}, "keywords": ["remittance"]}]}

    policy = build_rule_policy([subject_only, body_only], anchors, audit)
    assert policy["fields"]["remittance"] == {"subject"}
    assert policy["counts"]["remittance"] == 1, policy["counts"]

    # With no recorded condition, look everywhere: not knowing where the rule
    # looked is a reason to look broadly, not to skip the keyword.
    loose = build_rule_policy([subject_only, body_only], anchors,
                              {"malicious_rules": [{"keywords": ["remittance"]}]})
    assert loose["fields"]["remittance"] == {"subject", "body"}
    assert loose["counts"]["remittance"] == 2


def test_a_keyword_matching_most_of_the_corpus_stops_scoring(tmp_path):
    # The measured failure: +3 on 87% of a corpus is a constant offset, not a
    # signal. It stays visible as a finding -- the investigator supplied it --
    # but it must not rank anything.
    from postmortem.scoring import build_rule_policy, run_scenario_analysis
    from postmortem.models import Anchors

    records = [_kw_record("Update %d" % i, "Regarding the invoice attached.",
                          "/m/%d.eml" % i) for i in range(20)]
    rare = _kw_record("One off", "About the chargeback only.", "/m/rare.eml")
    records.append(rare)

    anchors = Anchors()
    anchors.rule_keywords = ["invoice", "chargeback"]
    policy = build_rule_policy(records, anchors, None)

    # 20 of 21 messages -- far over the cap.
    assert "invoice" in policy["over_cap"]
    # 1 of 21 -- selects something, so it still counts.
    assert "chargeback" not in policy["over_cap"]

    run_scenario_analysis(records, {"acme.com"}, anchors)
    over = [r for r in records if "invoice" in (r.rule_target_keywords or [])]
    assert over == [], "a keyword over the cap must not mark messages"
    assert rare.rule_target is True
    assert rare.rule_target_keywords == ["chargeback"]


def test_the_two_measured_dead_signals_score_nothing(tmp_path):
    # Both still reported -- they are true facts about the message -- but
    # neither moves the score, having landed on zero of 263 Tier 1 findings.
    from postmortem.config import CONFIG

    pw = CONFIG["priority_weights"]
    assert pw["date_anomaly_missing"] == 0
    assert pw["received_anomaly_out_of_order"] == 0
    # The other variants of each check are untouched: nothing was measured
    # against them, so nothing justifies zeroing them.
    assert pw["date_anomaly"] > 0
    assert pw["received_anomaly"] > 0


def test_a_missing_date_is_reported_but_not_scored(tmp_path):
    from postmortem.scoring import run_scenario_analysis
    from postmortem.models import Anchors

    r = _kw_record("Hello", "Body text.", "/m/nodate.eml")
    r.date = ""
    run_scenario_analysis([r], {"acme.com"}, Anchors())

    found = [f for f in r.provenance if f["source"] == "header:Date"]
    assert found, "the finding must still be stated"
    assert all(f["weight"] == 0 for f in found), found


def test_an_out_of_order_chain_is_zeroed_only_when_it_stands_alone(tmp_path):
    # A note that ALSO reports a missing or truncated chain is a different
    # observation and keeps its weight.
    from postmortem.config import CONFIG

    pw = CONFIG["priority_weights"]
    alone = "Received timestamps out of order (possible forged hop)"
    combined = "no Received chain on an external message; " + alone

    def weight_for(note):
        return (pw.get("received_anomaly_out_of_order", 0)
                if "out of order" in note and ";" not in note
                else pw["received_anomaly"])

    assert weight_for(alone) == 0
    assert weight_for(combined) == pw["received_anomaly"] > 0


def test_the_highest_lift_signals_were_raised(tmp_path):
    from postmortem.config import CONFIG, PHISHING_TERMS

    # 11.8x lift over 7,323 messages, previously hardcoded at 3.
    assert CONFIG["priority_weights"]["auth_fail_hard"] == 5
    # 10.7x and 5.4x, both previously at 2.
    assert PHISHING_TERMS["sign in"] == 4
    assert PHISHING_TERMS["urgent"] == 3


# ---- the diagnostic's own defects ---------------------------------------
def test_one_audit_finding_stays_one_signal(tmp_path):
    # 197 of 250 signal rows were the same finding split by timestamp,
    # because \\b\\d[\\d,]*\\b cannot match the 24 in "24T17" -- 4 and T are
    # both word characters, so the boundary fails.
    from postmortem.diagnostic import template, scan_for_identifiers

    a = template("Audit log: this message was read by bob@acme.com at "
                 "2026-08-24T17:32:46Z from 203.0.113.9")
    b = template("Audit log: this message was read by jane@acme.com at "
                 "2026-08-24T18:05:11Z from 198.51.100.2")
    assert a == b, (a, b)
    assert "<timestamp>" in a
    assert "2026" not in a and "24T17" not in a
    assert not scan_for_identifiers(a)

    # Other timestamp shapes template too.
    for stamp in ("2026-08-24 17:32:46", "2026-08-24T17:32:46.123456Z",
                  "2026-08-24T17:32:46+02:00", "2026-08-24T17:32"):
        out = template("seen at %s here" % stamp)
        assert "<timestamp>" in out, (stamp, out)
        assert "2026" not in out, (stamp, out)


def test_the_corpus_date_span_is_computed(tmp_path):
    # Read from a manifest key build_run_manifest never wrote, so it reported
    # null on every run -- including a corpus spanning 179 days.
    from postmortem import diagnostic

    records = []
    for day, path in ((1, "/m/a.eml"), (31, "/m/b.eml")):
        r = _kw_record("s", "b", path)
        r.date = "Wed, %02d Aug 2026 09:00:00 +0000" % day
        records.append(r)

    doc = diagnostic.build(records, verdict={}, manifest={})
    assert doc["corpus"]["date_span_days"] == 30, doc["corpus"]

    # One message, or none, has no span -- and must not raise.
    assert diagnostic.build(records[:1], verdict={}, manifest={})[
        "corpus"]["date_span_days"] is None
    assert diagnostic.build([], verdict={}, manifest={})[
        "corpus"]["date_span_days"] is None


def test_no_rule_keywords_changes_nothing(tmp_path):
    # Every run without --rule-keyword must behave exactly as before.
    from postmortem.scoring import build_rule_policy, run_scenario_analysis
    from postmortem.models import Anchors

    r = _kw_record("Hello", "Ordinary message.", "/m/plain.eml")
    policy = build_rule_policy([r], Anchors(), None)
    assert policy == {"fields": {}, "over_cap": set(), "counts": {},
                      "total": 0, "cap": 0.0}

    run_scenario_analysis([r], {"acme.com"}, Anchors())
    assert r.rule_target is False
    assert r.rule_target_keywords == []



# --------------------------------------------------------------------------
# C2: what a file IS, not what it is called
#
# calculate_score judged attachments purely by filename suffix. The offline
# content inspection -- magic-byte sniffing, macro detection, embedded
# credential forms, double extensions -- was parsed, stored on the record,
# used by the scenario score, and ignored by the score that ranks the review
# queue. So invoice.exe sent as invoice.pdf scored as an ordinary PDF, which
# is the exact case magic-byte sniffing exists to catch.
# --------------------------------------------------------------------------
def _attach_record(name, details, path="/m/att.eml"):
    from postmortem.models import EmailRecord

    r = EmailRecord(path=path, filename=path.rsplit("/", 1)[-1])
    r.sender_email = "ap@supplier.example"
    r.sender_domain = "supplier.example"
    r.subject = "Invoice attached"
    r.date = "Wed, 26 Aug 2026 09:00:00 +0000"
    r.body = "Please see attached."
    r.recipients = ["v@acme.com"]
    r.urls = []; r.url_domains = []; r.url_analysis = []
    r.attachments = [name]
    r.attachment_details = [dict(details, filename=name)]
    r.authentication_results = {}
    return r


def _attach_findings(record):
    return [f for f in record.provenance
            if f["category"] == "attachment" and f["weight"]]


def test_renaming_an_executable_no_longer_hides_it(tmp_path):
    # The whole point. Both messages carry the same executable; one of them
    # lies about it. The liar must not score lower.
    from postmortem.scoring import calculate_score

    honest = _attach_record("invoice.exe", {"sniffed_type": "pe_executable"},
                            "/m/honest.eml")
    disguised = _attach_record("invoice.pdf",
                               {"ext_mismatch": True,
                                "sniffed_type": "pe_executable"},
                               "/m/disguised.eml")
    benign = _attach_record("report.pdf", {}, "/m/benign.eml")

    for r in (honest, disguised, benign):
        calculate_score(r, {"acme.com"}, set())

    assert disguised.score >= honest.score, (disguised.score, honest.score)
    assert disguised.score > benign.score
    sig = " ".join(f["signal"] for f in _attach_findings(disguised))
    assert "disguised executable" in sig
    # The evidence names both claims, so a reader can check it.
    matched = " ".join(f["matched"] for f in _attach_findings(disguised))
    assert "pe_executable" in matched and ".pdf" in matched


def test_the_executable_kinds_come_from_parsing(tmp_path):
    # Restating this set by hand got it wrong on the first attempt -- the real
    # kinds are underscored and there are three, not seven -- which would have
    # silently downgraded every disguised executable to an ordinary mismatch.
    from postmortem.parsing import _EXECUTABLE_KINDS
    from postmortem.scoring import _EXECUTABLE_SNIFF_KINDS

    assert _EXECUTABLE_SNIFF_KINDS is _EXECUTABLE_KINDS
    assert "pe_executable" in _EXECUTABLE_SNIFF_KINDS


def test_a_mismatch_that_is_not_an_executable_scores_lower(tmp_path):
    # Content that simply is not what it claims is worth reporting, but it is
    # not the same finding as a disguised binary.
    from postmortem.scoring import calculate_score

    exe = _attach_record("a.pdf", {"ext_mismatch": True,
                                   "sniffed_type": "pe_executable"}, "/m/1.eml")
    other = _attach_record("b.pdf", {"ext_mismatch": True,
                                     "sniffed_type": "html"}, "/m/2.eml")
    for r in (exe, other):
        calculate_score(r, {"acme.com"}, set())

    assert exe.score > other.score
    assert "does not match its name" in " ".join(
        f["signal"] for f in _attach_findings(other))


def test_macros_are_found_in_a_file_that_does_not_declare_them(tmp_path):
    # A .doc carrying macros is the classic, and the extension pass cannot
    # see it -- only .docm and friends are in MACRO_EXTENSIONS.
    from postmortem.scoring import calculate_score

    plain = _attach_record("notes.doc", {"macro": True}, "/m/doc.eml")
    calculate_score(plain, {"acme.com"}, set())
    assert "Macros found" in " ".join(f["signal"] for f in _attach_findings(plain))

    # A .docm already scores for its extension; it must not be charged twice
    # for the same observation.
    declared = _attach_record("notes.docm", {"macro": True}, "/m/docm.eml")
    calculate_score(declared, {"acme.com"}, set())
    sigs = [f["signal"] for f in _attach_findings(declared)]
    assert sum(1 for s in sigs if "acro" in s) == 1, sigs


def test_a_credential_form_in_an_attachment_scores(tmp_path):
    from postmortem.scoring import calculate_score

    form = _attach_record("login.html", {"html_form": True}, "/m/f.eml")
    plain = _attach_record("page.html", {}, "/m/p.eml")
    for r in (form, plain):
        calculate_score(r, {"acme.com"}, set())

    assert form.score > plain.score
    assert "credential form" in " ".join(
        f["signal"] for f in _attach_findings(form))


def test_a_deceptive_name_is_its_own_finding(tmp_path):
    # invoice.pdf.scr earns both: the name is deceptive AND the extension is
    # executable. Two distinct observations, not one counted twice.
    from postmortem.scoring import calculate_score

    r = _attach_record("invoice.pdf.scr", {"suspicious_name": True})
    calculate_score(r, {"acme.com"}, set())
    sigs = " ".join(f["signal"] for f in _attach_findings(r))
    assert "Deceptive attachment name" in sigs
    assert "Executable/script attachment" in sigs


def test_an_ordinary_attachment_still_scores_nothing_for_being_one(tmp_path):
    # B5 must survive: presence is context, not evidence.
    from postmortem.scoring import calculate_score

    r = _attach_record("Q3-report.pdf", {"sniffed_type": "pdf"})
    calculate_score(r, {"acme.com"}, set())
    assert _attach_findings(r) == []

    zipped = _attach_record("Q3-report.zip", {"sniffed_type": "zip"},
                            "/m/z.eml")
    calculate_score(zipped, {"acme.com"}, set())
    assert _attach_findings(zipped) == []


def test_details_without_a_matching_filename_are_ignored_quietly(tmp_path):
    # The details list is keyed back to the attachment by name. A record whose
    # two lists disagree -- which a cache row from an earlier parser can
    # produce -- must not raise, and must not attribute one file's content to
    # another.
    from postmortem.scoring import calculate_score
    from postmortem.models import EmailRecord

    r = EmailRecord(path="/m/odd.eml", filename="odd.eml")
    r.sender_email = "a@b.example"; r.sender_domain = "b.example"
    r.subject = "x"; r.body = "y"; r.date = "Wed, 26 Aug 2026 09:00:00 +0000"
    r.recipients = ["v@acme.com"]
    r.urls = []; r.url_domains = []; r.url_analysis = []
    r.attachments = ["real.pdf"]
    r.attachment_details = [{"filename": "something-else.pdf",
                             "ext_mismatch": True,
                             "sniffed_type": "pe_executable"}]
    r.authentication_results = {}
    calculate_score(r, {"acme.com"}, set())
    assert "disguised" not in " ".join(f["signal"] for f in r.provenance)

    # And missing details entirely is fine.
    r2 = _attach_record("a.pdf", {}, "/m/nodet.eml")
    r2.attachment_details = []
    calculate_score(r2, {"acme.com"}, set())
