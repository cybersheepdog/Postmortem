"""Optional YARA scanning of attachments (``--yara-rules``).

Requires the optional ``yara-python`` package. Degrades gracefully: if yara is
not installed or the rules do not compile, it warns and skips the scan rather
than failing the run. Rules are compiled once and reused. Fully offline once the
rules are loaded -- it matches local attachment bytes and makes no network call.
"""

import sys

from postmortem.parsing import iter_attachment_payloads


def _load_rules(rules_path):
    try:
        import yara
    except Exception:
        print("[!] --yara-rules given but yara-python is not installed; "
              "skipping YARA scan.", file=sys.stderr)
        return None
    try:
        return yara.compile(filepath=str(rules_path))
    except Exception as exc:
        print(f"[!] Could not compile YARA rules {rules_path}: {exc}; "
              "skipping YARA scan.", file=sys.stderr)
        return None


def _flag(record, filename, rule_names):
    from postmortem.scoring import make_finding
    sig = f"YARA match in attachment {filename}: {rule_names}"
    record.indicators = list(dict.fromkeys(list(record.indicators) + [sig]))
    record.provenance = list(record.provenance) + [make_finding(
        sig, category="attachment", source="yara", matched=rule_names,
        weight=10, severity="high")]
    record.score += 10
    record.tier = 1


def scan_records(records, rules_path, tiers=(1, 2)):
    """Scan Tier 1/2 records' attachments against the rules. Returns hit count."""
    rules = _load_rules(rules_path)
    if rules is None:
        return 0
    hits = 0
    for r in records:
        if r.tier not in tiers:
            continue
        for filename, _ctype, payload in iter_attachment_payloads(r.path):
            if not payload:
                continue
            try:
                matches = rules.match(data=payload)
            except Exception:
                continue
            if matches:
                names = ", ".join(sorted({getattr(m, "rule", str(m)) for m in matches}))
                _flag(r, filename, names)
                hits += 1
    return hits
