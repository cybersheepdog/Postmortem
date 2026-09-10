"""Optional YARA scanning of attachments (``--yara-rules``).

Requires the optional ``yara-python`` package. Degrades gracefully: if yara is
not installed it warns and skips the scan rather than failing the run.

``--yara-rules`` accepts either a single ``.yar``/``.yara`` file OR a directory
of them (searched recursively). Each file is validated independently so one bad
file -- a rule needing a module that isn't available, a syntax error, etc. --
is skipped with a warning instead of killing the whole scan. The survivors are
then merged into one namespaced ruleset, so each attachment is matched once
rather than once per rule file; per-file namespacing keeps rule identifiers
from colliding across files. Common external variables (filename/extension/...)
are declared so real-world rulesets compile. Fully offline: it matches local
attachment bytes and makes no network call.
"""

def _flag(record, filename, rule_names):
    from postmortem.scoring import make_finding
    sig = f"YARA match in attachment {filename}: {rule_names}"
    record.indicators = list(dict.fromkeys(list(record.indicators) + [sig]))
    record.provenance = list(record.provenance) + [make_finding(
        sig, category="attachment", source="yara", matched=rule_names,
        weight=10, severity="high")]
    record.score += 10
    record.tier = 1


def scan_records(records, rules_path, tiers=(1, 2), workers=None):
    """Scan Tier 1/2 records' attachments against the compiled rule set(s).

    Returns {matches, attachments, messages, rules_loaded, rules_failed,
    available}. `available` is False only when yara-python is missing.

    The scan itself lives in :mod:`postmortem.attachment_scan`, which decodes
    each message's attachments once and runs every enabled scanner over them in
    parallel. Callers that want both YARA and QR should invoke that module's
    ``run_passes`` directly so the attachments are decoded once rather than
    once per pass.
    """
    from postmortem.attachment_scan import run_passes
    result, _ = run_passes(
        records, rules_path=rules_path, want_qr=False, tiers=tiers,
        requested_workers=workers,
    )
    return result
