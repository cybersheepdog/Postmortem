

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
