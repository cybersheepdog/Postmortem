"""Shared, parallel attachment scanning for the YARA and QR passes.

Both optional passes need the same thing: the decoded bytes of every
attachment on a Tier 1/2 message. Run separately, each one re-opened the
``.eml``, re-parsed the whole MIME tree and re-decoded every attachment, so a
run with both enabled paid that cost twice on top of the parse the pipeline had
already done. This module does it once per message and hands the bytes to
whichever scanners are enabled.

It is also where the two passes become parallel. Both were plain ``for`` loops
over the suspect set, which on a large corpus is the single longest phase of a
run and used one core to do it. Work is distributed with a process pool sized
by :mod:`postmortem.resources`, falling back to in-process execution when the
job is small, when only one worker is available, or when the platform cannot
create a pool at all -- the same graceful-degradation contract the rest of the
pipeline follows.

YARA rulesets are compiled once in the parent and handed to workers as a saved
binary, so a large signature-base tree is not recompiled per process. Rule
files are also merged into a single namespaced ruleset, which turns N match
calls per attachment (one per rule file) into one.
"""

import hashlib
import os
import sys
import tempfile

from pathlib import Path

from postmortem.parsing import iter_attachment_payloads
from postmortem import resources

# External variables many public rulesets (e.g. signature-base) reference. They
# must be declared at compile time; real per-attachment values are passed at
# match time.
EXTERNALS = {
    "filename": "", "filepath": "", "extension": "", "filetype": "",
    "owner": "", "md5": "",
}

# Per-process state, populated by the pool initializer. Compiled YARA rules and
# the zbar decoder are not picklable, so each worker builds its own once rather
# than receiving them per job.
_STATE = {"rules": None, "decode": None}


def fingerprint(rules_path=None, want_qr=False, tiers=(1, 2)) -> str:
    """Identify this attachment-scan configuration.

    Stored on each record the scan touches, so a resumed run skips records it
    already scanned and re-scans them when the configuration changes. The YARA
    rule *contents* are hashed, not just the path: swapping in an updated
    signature-base under the same directory name must invalidate prior results,
    or the run would report yesterday's findings.
    """
    digest = hashlib.sha256()
    digest.update(b"qr=1" if want_qr else b"qr=0")
    digest.update(str(sorted(tiers)).encode())
    if rules_path:
        path = Path(rules_path)
        files = (sorted(f for f in path.rglob("*")
                        if f.suffix.lower() in (".yar", ".yara"))
                 if path.is_dir() else [path])
        for f in files:
            digest.update(str(f.name).encode("utf-8", "replace"))
            try:
                with f.open("rb") as fh:
                    for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                        digest.update(chunk)
            except OSError:
                digest.update(b"<unreadable>")
    return digest.hexdigest()[:16]


# ---------------------------------------------------------------------------
# YARA rule preparation (parent side, once per run)
# ---------------------------------------------------------------------------
def prepare_yara(rules_path):
    """Validate and merge a rule file or directory into one compiled ruleset.

    Returns ``(plan, loaded, failed, available)``. ``plan`` is a dict the
    workers use to rebuild the ruleset; it is ``None`` when nothing usable
    compiled. ``available`` is False only when yara-python is missing.

    Each file is compiled on its own first so one broken file -- a rule needing
    an unavailable module, a syntax error -- is skipped with a warning instead
    of killing the scan, exactly as before. The survivors are then merged into
    a single ruleset under one namespace per file, which keeps rule identifiers
    from colliding across files while collapsing the per-attachment work from
    one match call per file to one in total.
    """
    try:
        import yara
    except Exception:
        print("[!] --yara-rules given but yara-python is not installed; "
              "skipping YARA scan.", file=sys.stderr)
        return None, 0, 0, False

    path = Path(rules_path)
    if path.is_dir():
        files = sorted(f for f in path.rglob("*")
                       if f.suffix.lower() in (".yar", ".yara"))
    else:
        files = [path]

    good, failed = [], 0
    for f in files:
        try:
            yara.compile(filepath=str(f), externals=EXTERNALS)
            good.append(f)
        except Exception as exc:
            failed += 1
            print(f"[i] Skipped YARA rule file {f.name}: {exc}", file=sys.stderr)

    loaded = len(good)
    if failed:
        print(f"[i] YARA: compiled {loaded} rule file(s), skipped {failed} "
              "that failed to compile.", file=sys.stderr)
    if not good:
        print(f"[!] No usable YARA rules found at {rules_path}; skipping scan.",
              file=sys.stderr)
        return None, loaded, failed, True

    namespaces = {f"ns{i}": str(f) for i, f in enumerate(good)}
    try:
        merged = yara.compile(filepaths=namespaces, externals=EXTERNALS)
    except Exception as exc:
        # Merging can still fail on pathological rulesets. Fall back to the
        # previous behavior: workers compile each file separately.
        print(f"[i] YARA: could not merge rule files ({exc}); "
              "falling back to per-file matching.", file=sys.stderr)
        return ({"mode": "files", "files": [str(f) for f in good]},
                loaded, failed, True)

    # Save the compiled form so each worker loads a binary instead of
    # recompiling a large tree from source.
    try:
        handle, blob = tempfile.mkstemp(prefix="postmortem_yara_", suffix=".bin")
        os.close(handle)
        merged.save(blob)
        return ({"mode": "blob", "blob": blob}, loaded, failed, True)
    except Exception as exc:
        print(f"[i] YARA: could not cache compiled rules ({exc}); "
              "workers will compile from source.", file=sys.stderr)
        return ({"mode": "merged", "namespaces": namespaces},
                loaded, failed, True)


def _build_rules(plan):
    """Rebuild the compiled ruleset inside a worker (or in-process)."""
    if not plan:
        return None
    import yara
    mode = plan.get("mode")
    if mode == "blob":
        return [yara.load(plan["blob"])]
    if mode == "merged":
        return [yara.compile(filepaths=plan["namespaces"], externals=EXTERNALS)]
    if mode == "files":
        out = []
        for f in plan["files"]:
            try:
                out.append(yara.compile(filepath=f, externals=EXTERNALS))
            except Exception:
                continue
        return out
    return None


# Why the QR decoder is unavailable, when it is. Distinguishing "not
# installed" from "installed but cannot load its native library" matters:
# pyzbar on Windows needs the Visual C++ runtime, and without it the import
# raises even though pip reports the package as present. Reporting the real
# error saves the analyst reinstalling a package that is already there.
QR_UNAVAILABLE_REASON = ""


def _build_decoder():
    """Return a QR decode callable, or None with the reason recorded."""
    global QR_UNAVAILABLE_REASON
    try:
        from pyzbar.pyzbar import decode as zbar_decode
        from PIL import Image
    except Exception as exc:
        QR_UNAVAILABLE_REASON = f"{type(exc).__name__}: {exc}"
        return None
    QR_UNAVAILABLE_REASON = ""

    import io

    def decode(payload):
        try:
            img = Image.open(io.BytesIO(payload))
            return [d.data.decode("utf-8", "ignore") for d in zbar_decode(img)]
        except Exception:
            return []
    return decode


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------
def _init_worker(yara_plan, want_qr):
    _STATE["rules"] = _build_rules(yara_plan)
    _STATE["decode"] = _build_decoder() if want_qr else None


def _scan_one(path):
    """Scan every attachment of one message with whichever scanners are armed.

    Returns ``(path, yara_hits, qr_hits, attachment_count)`` where ``yara_hits``
    is a list of ``(filename, "rule, names")`` and ``qr_hits`` a list of
    ``(filename, decoded_text)``. Returning plain tuples keeps the payload
    across the process boundary small: attachment bytes never travel back.
    """
    rules = _STATE.get("rules")
    decode = _STATE.get("decode")
    yara_hits, qr_hits = [], []
    attachments = 0

    for filename, ctype, payload in iter_attachment_payloads(path):
        if not payload:
            continue
        attachments += 1

        if rules:
            ext = Path(filename).suffix.lstrip(".").lower()
            externals = {"filename": filename, "filepath": filename,
                         "extension": ext, "filetype": ctype or "",
                         "owner": "", "md5": ""}
            names = set()
            for ruleset in rules:
                try:
                    for m in ruleset.match(data=payload, externals=externals):
                        names.add(getattr(m, "rule", str(m)))
                except Exception:
                    continue
            if names:
                yara_hits.append((filename, ", ".join(sorted(names))))

        if decode is not None and str(ctype).startswith("image/"):
            for text in decode(payload):
                qr_hits.append((filename, text))

    return path, yara_hits, qr_hits, attachments


# ---------------------------------------------------------------------------
# Orchestration (parent side)
# ---------------------------------------------------------------------------
# Below this many messages the pool costs more than it saves.
_POOL_MIN_JOBS = 64


def scan(records, yara_plan=None, want_qr=False, tiers=(1, 2), requested_workers=None):
    """Scan the suspect records once, feeding both enabled scanners.

    Yields ``(record, yara_hits, qr_hits, attachment_count)`` as results
    arrive. Findings are applied by the caller so that scoring, provenance and
    URL analysis stay in the parent process and remain identical to the serial
    implementation.
    """
    targets = [r for r in records if r.tier in tiers]
    if not targets:
        return

    by_path = {}
    for record in targets:
        by_path.setdefault(str(record.path), []).append(record)
    paths = [str(r.path) for r in targets]

    phase = "yara" if yara_plan else "qr"
    workers, why = resources.plan_workers(phase, requested=requested_workers)
    if len(paths) < _POOL_MIN_JOBS:
        workers = 1

    if workers > 1:
        try:
            from concurrent.futures import ProcessPoolExecutor
            executor = ProcessPoolExecutor(
                max_workers=workers,
                initializer=_init_worker,
                initargs=(yara_plan, want_qr),
            )
        except Exception as exc:  # pragma: no cover - environment dependent
            print(f"\n[!] Attachment-scan pool unavailable "
                  f"({type(exc).__name__}: {exc}); using serial execution.",
                  file=sys.stderr)
            workers = 1
        else:
            print(f"  attachment-scan workers: {workers} ({why})")
            chunksize = max(1, len(paths) // (workers * 4))
            with executor:
                for path, yara_hits, qr_hits, n in executor.map(
                    _scan_one, paths, chunksize=chunksize
                ):
                    for record in by_path.get(path, ()):
                        yield record, yara_hits, qr_hits, n
            return

    # Serial path: same work, same order, no pool.
    _init_worker(yara_plan, want_qr)
    for path in paths:
        _, yara_hits, qr_hits, n = _scan_one(path)
        for record in by_path.get(path, ()):
            yield record, yara_hits, qr_hits, n


def cleanup(yara_plan):
    """Remove the cached compiled-rule blob, if one was written."""
    if yara_plan and yara_plan.get("mode") == "blob":
        try:
            os.unlink(yara_plan["blob"])
        except Exception:
            pass


def run_passes(records, rules_path=None, want_qr=False, tiers=(1, 2),
               requested_workers=None, resume=True):
    """Run the YARA and/or QR passes over the suspects in a single sweep.

    Returns ``(yara_result, qr_hits)``. ``yara_result`` matches the dict the
    standalone YARA pass has always returned, so callers and reports are
    unaffected. Flagging is delegated to the existing per-pass ``_flag``
    helpers, keeping scoring weights, provenance records and tier promotion
    byte-for-byte identical to the serial implementation.
    """
    # Imported here rather than at module scope: those modules import this one.
    from postmortem.yara_scan import _flag as yara_flag
    from postmortem.qr_scan import _flag as qr_flag
    from postmortem.urls import extract_urls

    yara_plan = None
    loaded = failed = 0
    available = True
    if rules_path:
        yara_plan, loaded, failed, available = prepare_yara(rules_path)

    yara_result = {"matches": 0, "attachments": 0, "messages": 0,
                   "replayed": 0, "scanned": 0,
                   "rules_loaded": loaded, "rules_failed": failed,
                   "available": available}
    qr_hits = 0

    if want_qr and _build_decoder() is None:
        reason = QR_UNAVAILABLE_REASON or "pyzbar/Pillow could not be imported"
        print(f"[!] --scan-qr given but the QR decoder is unavailable: {reason}",
              file=sys.stderr)
        if "shared library" in reason.lower() or "dll" in reason.lower():
            print("[!] pyzbar is installed but its native zbar library did not "
                  "load. On Windows this is usually the missing Visual C++ "
                  "Redistributable (vcredist x64); on Linux, libzbar0.",
                  file=sys.stderr)
        print(f"[!] Interpreter: {sys.executable}", file=sys.stderr)
        want_qr = False

    if not yara_plan and not want_qr:
        return yara_result, 0

    stamp = fingerprint(rules_path if yara_plan else None, want_qr, tiers)
    targets = records
    replay = []
    if resume:
        targets, replay = [], []
        for record in records:
            if getattr(record, "enrichment_fingerprint", "") == stamp:
                replay.append(record)
            else:
                targets.append(record)
        if replay:
            print(f"  ({len(replay)} record(s) already scanned with this "
                  "configuration; replaying stored hits)")

    messages = attachments = matches = replayed = 0

    def apply_hits(record, stored):
        """Turn stored hits into findings via the normal flagging path."""
        nonlocal matches, qr_hits
        for hit in stored:
            if hit.get("kind") == "yara":
                yara_flag(record, hit.get("filename", ""), hit.get("detail", ""))
                matches += 1
            elif hit.get("kind") == "qr":
                qr_flag(record, hit.get("filename", ""), hit.get("detail", ""))
                qr_hits += 1

    # Records carrying results from an identical earlier scan: re-apply their
    # findings without touching the disk. Scoring has already been recomputed
    # from scratch by this point in the run, which is exactly why the hits are
    # stored as data and replayed rather than trusted from the cached record.
    for record in replay:
        replayed += 1
        stored = list(getattr(record, "enrichment_hits", []) or [])
        if stored:
            messages += 1
            apply_hits(record, stored)

    try:
        for record, hits, qrs, n_att in scan(
            targets, yara_plan=yara_plan, want_qr=want_qr, tiers=tiers,
            requested_workers=requested_workers,
        ):
            messages += 1
            attachments += n_att
            fresh = [{"kind": "yara", "filename": f, "detail": names}
                     for f, names in hits]
            for filename, text in qrs:
                for url in extract_urls(text):
                    fresh.append({"kind": "qr", "filename": filename,
                                  "detail": url})
            # Replace rather than extend: a re-scan supersedes whatever an
            # earlier configuration recorded for this message.
            record.enrichment_hits = fresh
            record.enrichment_fingerprint = stamp
            apply_hits(record, fresh)
    finally:
        cleanup(yara_plan)

    if yara_plan:
        yara_result.update({"matches": matches, "attachments": attachments,
                            "messages": messages, "replayed": replayed,
                            "scanned": len(targets)})
    return yara_result, qr_hits
