"""Unit and integration tests for postmortem.

Run with:  python -m pytest test_postmortem.py -q
       or:  python test_postmortem.py        (falls back to a built-in runner)

These lock down the parsing, scoring, clustering, tiering, attachment
inspection, IOC extraction and config behaviour so the scoring logic can be
changed safely. They construct messages in memory; no network or real mailbox
is required.
"""

import copy
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
