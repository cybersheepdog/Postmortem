"""Optional YARA scanning of attachments (``--yara-rules``).

Requires the optional ``yara-python`` package. Degrades gracefully: if yara is
not installed it warns and skips the scan rather than failing the run.

``--yara-rules`` accepts either a single ``.yar``/``.yara`` file OR a directory
of them (searched recursively). Each file is compiled independently so one bad
file -- a rule needing a module that isn't available, a duplicate identifier,
etc. -- is skipped with a warning instead of killing the whole scan. Common
external variables (filename/extension/...) are declared so real-world rulesets
compile. Fully offline: it matches local attachment bytes and makes no network
call.
"""

import sys
from pathlib import Path

from postmortem.parsing import iter_attachment_payloads

# External variables many public rulesets (e.g. signature-base) reference. They
# must be declared at compile time; real per-attachment values are passed at
# match time.
_EXTERNALS = {
    "filename": "", "filepath": "", "extension": "", "filetype": "",
    "owner": "", "md5": "",
}


def _compile_rules(rules_path):
    """Compile a .yar file or a directory of them.

    Returns (compiled_rules_list, loaded_count, failed_count, available_bool).
    """
    try:
        import yara
    except Exception:
        print("[!] --yara-rules given but yara-python is not installed; "
              "skipping YARA scan.", file=sys.stderr)
        return [], 0, 0, False

    path = Path(rules_path)
    if path.is_dir():
        files = sorted(f for f in path.rglob("*")
                       if f.suffix.lower() in (".yar", ".yara"))
    else:
        files = [path]

    compiled, loaded, failed = [], 0, 0
    for f in files:
        try:
            compiled.append(yara.compile(filepath=str(f), externals=_EXTERNALS))
            loaded += 1
        except Exception as exc:
            failed += 1
            print(f"[i] Skipped YARA rule file {f.name}: {exc}", file=sys.stderr)
    if failed:
        print(f"[i] YARA: compiled {loaded} rule file(s), skipped {failed} "
              "that failed to compile.", file=sys.stderr)
    if not compiled:
        print(f"[!] No usable YARA rules found at {rules_path}; skipping scan.",
              file=sys.stderr)
    return compiled, loaded, failed, True


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
    """Scan Tier 1/2 records' attachments against the compiled rule set(s).

    Returns {matches, attachments, messages, rules_loaded, rules_failed,
    available}. `available` is False only when yara-python is missing.
    """
    compiled, loaded, failed, available = _compile_rules(rules_path)
    base = {"matches": 0, "attachments": 0, "messages": 0,
            "rules_loaded": loaded, "rules_failed": failed, "available": available}
    if not compiled:
        return base

    hits = attachments = messages = 0
    for r in records:
        if r.tier not in tiers:
            continue
        messages += 1
        for filename, ctype, payload in iter_attachment_payloads(r.path):
            if not payload:
                continue
            attachments += 1
            ext = Path(filename).suffix.lstrip(".").lower()
            externals = {"filename": filename, "filepath": filename,
                         "extension": ext, "filetype": ctype or "",
                         "owner": "", "md5": ""}
            names = set()
            for ruleset in compiled:
                try:
                    for m in ruleset.match(data=payload, externals=externals):
                        names.add(getattr(m, "rule", str(m)))
                except Exception:
                    continue
            if names:
                _flag(r, filename, ", ".join(sorted(names)))
                hits += 1
    base.update({"matches": hits, "attachments": attachments, "messages": messages})
    return base