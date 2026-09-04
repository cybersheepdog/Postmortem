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
    find_lookalike, v8_candidate_score, classify_attack_stage,
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
    cand, score, reasons = v8_candidate_score(r)
    assert cand and "base64-encoded content in body" in reasons
    # ...but an inline data: image alone must NOT promote a benign newsletter.
    r2 = make_record(subject="monthly newsletter",
                     body="<img src='data:image/png;base64," + "A" * 200 + "'>")
    assert not v8_candidate_score(r2)[0]


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
