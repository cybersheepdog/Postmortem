"""Ingest Outlook PST/OST and Unix/Gmail MBOX mail containers into .eml files.

The rest of the pipeline is path-based: it scans a directory of .eml files and
several forensic signals (folder concealment, cross-path duplicate reuse, the
per-message cache) key off the file path. Rather than special-casing containers
everywhere, this module *explodes* a PST/OST/MBOX into a staging directory of
.eml files and lets the normal pipeline run over them.

Extraction preserves the source folder hierarchy in the output path
(e.g. ``.../Deleted Items/000123.eml``), so the concealment signals that look
for folder names like "Deleted Items", "Recoverable Items", "RSS Feeds" or
"Junk Email" fire on container input exactly as they do on a folder of .eml.

Dependencies:
  * MBOX uses only the Python standard library (`mailbox`), so it always works.
  * PST/OST use the optional `pypff` (libpff) binding when installed. Without
    it, PST/OST are skipped with an actionable message pointing at `readpst`.

Everything is offline: it reads a local file and writes local .eml files.
"""

import json
import mailbox
import os
import mimetypes
import re
import shutil
import sys
from email import message_from_string, policy
from email.message import EmailMessage
from pathlib import Path

from postmortem import resources

CONTAINER_SUFFIXES = {".pst", ".ost", ".mbox"}

# Gmail Takeout stores one flat mbox with an X-Gmail-Labels header per message.
# Map the labels that carry concealment meaning onto the canonical Outlook
# folder names the concealment signals already recognize.
_LABEL_TO_FOLDER = {
    "trash": "Deleted Items",
    "bin": "Deleted Items",
    "spam": "Junk Email",
    "junk": "Junk Email",
}


def is_container(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in CONTAINER_SUFFIXES


def find_containers(root: Path) -> list[Path]:
    """Return PST/OST/MBOX files under `root` (or `root` itself if it is one)."""
    if is_container(root):
        return [root]
    if not root.is_dir():
        return []
    out = []
    for p in sorted(root.rglob("*")):
        # Never descend into our own extraction output.
        if ".postmortem_extracted" in p.parts:
            continue
        if is_container(p):
            out.append(p)
    return out


def _safe_component(name: str) -> str:
    """Sanitize one folder/path component for the local filesystem."""
    name = (name or "").strip().strip("/\\")
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    name = name.rstrip(". ")  # Windows dislikes trailing dot/space
    return name[:120] or "_"


def _write_eml(out_dir: Path, folder_parts, seq: int, raw: bytes) -> None:
    target_dir = out_dir
    for part in folder_parts:
        comp = _safe_component(part)
        if comp:
            target_dir = target_dir / comp
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / f"{seq:06d}.eml").write_bytes(raw)


# --------------------------------------------------------------------------
# MBOX (standard library)
# --------------------------------------------------------------------------
def _mbox_folder(message, default: str) -> str:
    """Route an mbox message to a folder name that preserves concealment intent.

    Honors an explicit ``X-Folder`` header (PST->mbox conversions keep it) and
    Gmail's ``X-Gmail-Labels`` (Trash/Spam become Deleted Items/Junk Email).
    """
    xfolder = message.get("X-Folder", "")
    if xfolder:
        tail = re.split(r"[\\/]", str(xfolder).strip())[-1]
        if tail:
            return tail
    labels = message.get("X-Gmail-Labels", "")
    if labels:
        parts = [p.strip() for p in str(labels).split(",") if p.strip()]
        for p in parts:
            mapped = _LABEL_TO_FOLDER.get(p.lower())
            if mapped:
                return mapped
        if parts:
            return parts[0]
    return default


def extract_mbox(path: Path, out_dir: Path, manifest=None,
                 checkpoint=None, checkpoint_every: int = 2000) -> dict:
    """Explode an mbox into .eml, resumably.

    mbox has no folder structure to parallelize across and the stdlib reader is
    sequential, so resume is by message position: the manifest records how many
    messages have been written and a restart skips straight past them. Sequence
    numbers come from the message's position in the file, so a resumed run
    writes exactly the filenames an uninterrupted one would.
    """
    box = mailbox.mbox(str(path))
    default_folder = _safe_component(path.stem) or "mbox"
    resume_from = int((manifest or {}).get("mbox_position", 0) or 0)
    written = int((manifest or {}).get("messages_written", 0) or 0)
    folders = set((manifest or {}).get("folders") or [])
    position = 0
    try:
        for seq, key in enumerate(box.keys(), 1):
            position = seq
            if seq <= resume_from:
                continue
            try:
                raw = box.get_bytes(key)
                msg = box.get_message(key)
            except Exception:
                continue
            folder = _mbox_folder(msg, default_folder)
            folders.add(folder)
            _write_eml(out_dir, [folder], seq, raw)
            written += 1
            if checkpoint and written % checkpoint_every == 0:
                checkpoint(seq, written, sorted(folders))
    finally:
        box.close()
    return {
        "type": "mbox", "messages_written": written,
        "folders": sorted(folders), "note": "",
        "mbox_position": position,
        "resumed_from": resume_from,
    }


# --------------------------------------------------------------------------
# PST / OST (optional pypff / libpff)
# --------------------------------------------------------------------------
# Bumped when the extraction output changes shape, so a manifest written by an
# older version is not trusted for resume.
EXTRACTOR_VERSION = "2-parallel-resumable"

# Name of the per-container manifest that records what was extracted and
# whether the extraction finished. Its absence (or an "incomplete" state) is
# what makes a crashed extraction visibly incomplete instead of silently
# passing for a finished one.
MANIFEST_NAME = ".postmortem_extract.json"


def _pst_available() -> bool:
    try:
        import pypff
        return pypff is not None
    except Exception:
        return False


def _pst_reconstruct_eml(message) -> bytes:
    """Rebuild an RFC822 .eml from a pypff message.

    The internet transport headers preserve From/To/Subject/Date/Message-ID and
    the SPF/DKIM/DMARC Authentication-Results, so they are used verbatim as the
    header block. Attachments are re-attached as real MIME parts so the offline
    attachment inspection (macros, HTML login forms, double extensions) runs on
    container input too.
    """
    headers = message.get_transport_headers() or ""
    if isinstance(headers, bytes):
        headers = headers.decode("utf-8", "replace")

    body = ""
    for getter in ("get_plain_text_body", "get_html_body", "get_rtf_body"):
        try:
            val = getattr(message, getter)()
        except Exception:
            val = None
        if val:
            body = val.decode("utf-8", "replace") if isinstance(val, bytes) else str(val)
            break

    # Collect attachments (name + bytes) when present.
    attachments = []
    try:
        for i in range(message.number_of_attachments):
            att = message.get_attachment(i)
            try:
                name = att.get_name() or f"attachment_{i}"
            except Exception:
                name = f"attachment_{i}"
            try:
                size = att.get_size()
                data = att.read_buffer(size) if size else b""
            except Exception:
                data = b""
            attachments.append((str(name), data))
    except Exception:
        pass

    if headers.strip():
        base = message_from_string(headers, policy=policy.default)
    else:
        # No internet headers (internal Exchange item): synthesize minimal ones.
        base = EmailMessage()
        for hdr, getter in (("Subject", "get_subject"),
                            ("From", "get_sender_name")):
            try:
                v = getattr(message, getter)()
            except Exception:
                v = None
            if v:
                base[hdr] = str(v)

    if not attachments:
        # Simple case: keep the original header block, append the body.
        header_block = headers if headers.strip() else _headers_to_str(base)
        return (header_block.rstrip("\r\n") + "\r\n\r\n" + body).encode("utf-8", "replace")

    # Attachments present: build a fresh MIME message carrying the original
    # headers plus the body and re-attached files.
    out = EmailMessage()
    for key, value in _safe_items(base):
        kl = key.lower()
        if kl in ("content-type", "content-transfer-encoding", "mime-version"):
            continue
        try:
            out[key] = value
        except Exception:
            continue
    out.set_content(body or "")
    for name, data in attachments:
        ctype, _ = mimetypes.guess_type(name)
        maintype, subtype = (ctype.split("/", 1) if ctype else ("application", "octet-stream"))
        try:
            out.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
        except Exception:
            continue
    return out.as_bytes()


def _safe_items(msg) -> list:
    """Header name/value pairs, tolerant of headers the stdlib cannot parse.

    ``policy.default`` parses header values on access and raises on malformed
    ones (e.g. a Message-ID with an empty local part), which would otherwise
    abort an entire mailbox extraction. Fall back to the raw source values.
    """
    try:
        return list(msg.items())
    except Exception:
        try:
            return [(k, str(v)) for k, v in msg.raw_items()]
        except Exception:
            return []


def _headers_to_str(msg) -> str:
    return "".join(f"{k}: {v}\r\n" for k, v in _safe_items(msg))


# --------------------------------------------------------------------------
# Folder planning
# --------------------------------------------------------------------------
def _resolve_folder(pff, address):
    """Navigate to a folder by its index path from the root."""
    folder = pff.get_root_folder()
    for index in address:
        folder = folder.get_sub_folder(index)
    return folder


def _plan_folders(folder, address, path_parts, plan, counter):
    """Depth-first enumeration of folders, assigning each a sequence range.

    This walks names and message *counts* only -- it never reconstructs a
    message -- so it is cheap even on a very large PST. Assigning each folder a
    contiguous, pre-computed sequence range up front is what lets folders be
    extracted out of order, in parallel, and still land on exactly the
    filenames a single-threaded depth-first walk would have produced.
    """
    try:
        name = folder.get_name()
    except Exception:
        name = None
    parts = path_parts + ([name] if name else [])

    try:
        n_msgs = int(folder.number_of_sub_messages)
    except Exception:
        n_msgs = 0

    if n_msgs:
        plan.append({
            "address": list(address),
            "parts": list(parts) or ["Top of Outlook data file"],
            "folder": "/".join(parts),
            "count": n_msgs,
            "start": counter[0],
        })
        counter[0] += n_msgs
    elif parts:
        # Recorded so the folder list in the summary stays complete.
        plan.append({
            "address": list(address), "parts": list(parts),
            "folder": "/".join(parts), "count": 0, "start": counter[0],
        })

    try:
        n_sub = int(folder.number_of_sub_folders)
    except Exception:
        n_sub = 0
    for i in range(n_sub):
        try:
            sub = folder.get_sub_folder(i)
        except Exception:
            continue
        _plan_folders(sub, tuple(address) + (i,), parts, plan, counter)


def _extract_folder(job):
    """Extract one folder's messages. Runs in a worker process.

    Each worker opens its own read-only handle on the PST; libpff handles
    cannot cross a process boundary. Sequence numbers come from the plan, so
    two workers never contend for a filename.
    """
    pst_path, out_dir, address, parts, start, count = job
    import pypff
    pff = pypff.file()
    written = failed = 0
    try:
        pff.open(str(pst_path))
        folder = _resolve_folder(pff, address)
        for i in range(count):
            try:
                message = folder.get_sub_message(i)
                raw = _pst_reconstruct_eml(message)
            except Exception:
                # A message that cannot be reconstructed leaves a numbering gap
                # rather than shifting every later message, so filenames stay
                # stable across runs and map to a fixed position in the PST.
                failed += 1
                continue
            _write_eml(Path(out_dir), parts, start + i + 1, raw)
            written += 1
    except Exception:
        return {"address": list(address), "written": written,
                "failed": failed, "error": True}
    finally:
        try:
            pff.close()
        except Exception:
            pass
    return {"address": list(address), "written": written,
            "failed": failed, "error": False}


def extract_pst(path: Path, out_dir: Path, workers=None, manifest=None,
                progress=None, checkpoint=None) -> dict:
    """Explode a PST/OST into .eml, in parallel, resumably.

    Folders are enumerated first (names and message counts only, which is
    cheap), each is assigned a contiguous sequence range, and the ranges are
    handed to a process pool. Completed folders are recorded in `manifest` as
    they finish, so an interrupted extraction resumes at folder granularity
    instead of starting the container again -- or, worse, being mistaken for a
    finished one.
    """
    if not _pst_available():
        return {
            "type": "pst", "messages_written": 0, "folders": [],
            "note": ("pypff/libpff is not installed, so PST/OST cannot be read "
                     "directly. Install it (`pip install libpff-python`) or "
                     f"convert first: `readpst -e -o <outdir> \"{path.name}\"` "
                     "and point this tool at <outdir>."),
            "skipped": True,
        }
    import pypff

    # ---- plan -------------------------------------------------------------
    pff = pypff.file()
    plan = []
    try:
        pff.open(str(path))
        _plan_folders(pff.get_root_folder(), (), [], plan, [0])
    finally:
        try:
            pff.close()
        except Exception:
            pass

    folders = sorted(p["folder"] for p in plan if p["folder"])
    work = [p for p in plan if p["count"]]
    total_messages = sum(p["count"] for p in work)

    # "folder_state" maps a folder's address to what it extracted;
    # "folders" is the human-readable name list and must not be used here.
    done = dict((manifest or {}).get("folder_state") or {})
    pending = [p for p in work if "/".join(map(str, p["address"])) not in done]
    resumed = len(work) - len(pending)

    written = sum(int(v.get("written", 0)) for v in done.values())
    failed = sum(int(v.get("failed", 0)) for v in done.values())

    if not pending:
        return {"type": path.suffix.lower().lstrip("."),
                "messages_written": written, "messages_failed": failed,
                "folders": folders, "note": "", "resumed_folders": resumed,
                "total_messages": total_messages, "plan": plan}

    jobs = [
        (str(path), str(out_dir), tuple(p["address"]), p["parts"],
         p["start"], p["count"])
        for p in pending
    ]

    n_workers, why = resources.plan_workers("extract", requested=workers)
    n_workers = min(n_workers, len(jobs))
    if n_workers > 1:
        print(f"  {path.name}: {len(pending)} folder(s), {total_messages} "
              f"message(s), {n_workers} workers ({why})"
              + (f", resuming past {resumed} completed folder(s)" if resumed else ""))
    def record(result, completed, total):
        """Fold one finished folder into the running state and checkpoint.

        Checkpointing here rather than at the end of the container is the
        whole point of the exercise: a machine that loses power mid-PST comes
        back knowing exactly which folders are already on disk.
        """
        nonlocal written, failed
        key = "/".join(map(str, result["address"]))
        done[key] = {"written": result["written"], "failed": result["failed"]}
        written += result["written"]
        failed += result["failed"]
        if checkpoint:
            checkpoint(done, written, failed, completed, total)
        if progress:
            progress(completed, total, result)

    pooled = False
    if n_workers > 1:
        try:
            from concurrent.futures import ProcessPoolExecutor, as_completed
            with ProcessPoolExecutor(max_workers=n_workers) as executor:
                futures = [executor.submit(_extract_folder, j) for j in jobs]
                pooled = True
                for completed, future in enumerate(as_completed(futures), 1):
                    record(future.result(), completed, len(jobs))
        except Exception as exc:  # pragma: no cover - environment dependent
            print(f"[!] Extraction pool unavailable ({type(exc).__name__}: "
                  f"{exc}); extracting serially.", file=sys.stderr)
            pooled = False
    if not pooled:
        for completed, job in enumerate(jobs, 1):
            record(_extract_folder(job), completed, len(jobs))

    return {
        "type": path.suffix.lower().lstrip("."),
        "messages_written": written,
        "messages_failed": failed,
        "folders": folders,
        "note": "",
        "resumed_folders": resumed,
        "total_messages": total_messages,
        "folder_state": done,
        "plan": plan,
    }


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
def _container_identity(path: Path) -> dict:
    """Identity of the source container, so a changed PST is never resumed."""
    try:
        st = path.stat()
        return {"size": st.st_size, "mtime_ns": st.st_mtime_ns}
    except OSError:
        return {"size": -1, "mtime_ns": -1}


def read_manifest(target: Path) -> dict:
    """Load a prior extraction's manifest, or {} when there is none."""
    manifest_path = Path(target) / MANIFEST_NAME
    try:
        with manifest_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_manifest(target: Path, data: dict) -> None:
    """Persist the manifest atomically.

    Written via a temporary file and replaced in place: a manifest truncated
    by a power cut would claim an extraction finished when it did not, which
    is the exact failure this file exists to prevent.
    """
    target = Path(target)
    target.mkdir(parents=True, exist_ok=True)
    manifest_path = target / MANIFEST_NAME
    tmp = target / (MANIFEST_NAME + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(data, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, manifest_path)
    except OSError as exc:
        print(f"[!] Could not write extraction manifest for {target}: {exc}",
              file=sys.stderr)


def _manifest_usable(manifest: dict, path: Path) -> bool:
    """True when `manifest` describes a finished extraction of *this* file."""
    if not manifest or not manifest.get("completed"):
        return False
    if manifest.get("extractor_version") != EXTRACTOR_VERSION:
        return False
    return manifest.get("source") == _container_identity(path)


def ingest_container(path: Path, out_dir: Path, reingest: bool = False,
                     workers=None, resume: bool = True) -> dict:
    """Explode one container into `out_dir`.

    Reuse of a prior extraction is decided by the manifest that extraction
    wrote, not by whether the output directory happens to contain any .eml
    files. A run that died part way through leaves no completion marker, so
    it is resumed (folder by folder, for PST/OST) rather than being mistaken
    for finished -- which previously meant every later run silently analyzed a
    truncated mailbox.
    """
    stem = _safe_component(path.stem) or "container"
    target = out_dir / stem
    if reingest and target.exists():
        shutil.rmtree(target, ignore_errors=True)

    manifest = {} if reingest else read_manifest(target)

    if _manifest_usable(manifest, path):
        if manifest.get("pruned"):
            print(f"[!] {path.name}: this extraction was pruned to flagged "
                  "messages only. This run therefore analyzes a SUBSET of the "
                  "mailbox: unflagged messages are absent and totals will not "
                  "match the original run. Use --reingest to re-extract every "
                  "message.", file=sys.stderr)
        return {
            "container": str(path), "type": path.suffix.lower().lstrip("."),
            "messages_written": int(manifest.get("messages_written", 0)),
            "folders": list(manifest.get("folders") or []),
            "note": "reused prior extraction (use --reingest to redo)",
            "output_dir": str(target), "reused": True,
        }

    partial = bool(manifest) and not manifest.get("completed")
    if partial and not resume:
        # An unfinished extraction that we are told not to resume must not be
        # mixed with a fresh one; start the container over.
        shutil.rmtree(target, ignore_errors=True)
        manifest = {}
        partial = False
    if partial:
        print(f"[i] {path.name}: resuming an extraction that did not finish.",
              file=sys.stderr)
    if manifest and manifest.get("extractor_version") != EXTRACTOR_VERSION:
        # Output shape changed since that manifest was written.
        shutil.rmtree(target, ignore_errors=True)
        manifest = {}
    if manifest and manifest.get("source") not in (None, _container_identity(path)):
        print(f"[i] {path.name}: source container changed since the last "
              "extraction; re-extracting.", file=sys.stderr)
        shutil.rmtree(target, ignore_errors=True)
        manifest = {}

    identity = _container_identity(path)

    def _base_manifest():
        return {
            "extractor_version": EXTRACTOR_VERSION,
            "source": identity,
            "container": str(path),
            "completed": False,
        }

    def pst_checkpoint(folder_state, written, failed, completed, total):
        data = _base_manifest()
        data.update({
            "messages_written": written,
            "messages_failed": failed,
            "folder_state": folder_state,
            "folders_done": completed,
            "folders_total": total,
        })
        write_manifest(target, data)

    def mbox_checkpoint(position, written, folders):
        data = _base_manifest()
        data.update({
            "messages_written": written,
            "mbox_position": position,
            "folders": folders,
        })
        write_manifest(target, data)

    suffix = path.suffix.lower()
    if suffix == ".mbox":
        result = extract_mbox(path, target, manifest=manifest,
                              checkpoint=mbox_checkpoint)
    elif suffix in (".pst", ".ost"):
        result = extract_pst(path, target, workers=workers, manifest=manifest,
                             checkpoint=pst_checkpoint)
    else:
        result = {"type": suffix.lstrip("."), "messages_written": 0,
                  "folders": [], "note": "unsupported container type"}

    if not result.get("skipped"):
        write_manifest(target, {
            "extractor_version": EXTRACTOR_VERSION,
            "source": _container_identity(path),
            "container": str(path),
            "completed": True,
            "messages_written": int(result.get("messages_written", 0)),
            "messages_failed": int(result.get("messages_failed", 0)),
            "folders": list(result.get("folders") or []),
            "folder_state": result.get("folder_state") or {},
            "mbox_position": int(result.get("mbox_position", 0) or 0),
        })
    result.pop("plan", None)
    result.pop("folder_state", None)
    result["container"] = str(path)
    result["output_dir"] = str(target)
    return result


def ingest_all(root: Path, out_dir: Path, reingest: bool = False,
               workers=None, resume: bool = True) -> dict:
    """Find and explode every container under `root` into `out_dir`.

    Containers are processed one at a time, but each PST/OST is itself
    extracted across a process pool of folders, so a single very large
    container parallelizes just as well as many small ones.

    Returns a summary with per-container results and totals.
    """
    containers = find_containers(root)
    results = []
    total = 0
    skipped = []
    for c in containers:
        r = ingest_container(c, out_dir, reingest=reingest, workers=workers,
                             resume=resume)
        results.append(r)
        total += int(r.get("messages_written", 0))
        if r.get("skipped"):
            skipped.append(r)
        if r.get("note") and not r.get("reused"):
            print(f"[i] {Path(c).name}: {r['note']}", file=sys.stderr)
        if r.get("resumed_folders"):
            print(f"[i] {Path(c).name}: resumed past "
                  f"{r['resumed_folders']} already-extracted folder(s)",
                  file=sys.stderr)
        if r.get("messages_failed"):
            print(f"[i] {Path(c).name}: {r['messages_failed']} message(s) "
                  "could not be reconstructed (numbering gaps mark them)",
                  file=sys.stderr)
    return {
        "containers_found": len(containers),
        "messages_written": total,
        "results": results,
        "skipped": skipped,
        "output_dir": str(out_dir),
    }


# --------------------------------------------------------------------------
# Retention: keep only the extracted messages that matter
# --------------------------------------------------------------------------
def prune_to_hits(extract_dir: Path, records, keep_tiers=(1, 2),
                  dry_run: bool = False) -> dict:
    """Delete extracted .eml files that no signal flagged.

    Exploding a large PST corpus writes one small file per message, and on a
    202GB mailbox the staging directory can dwarf the containers it came from.
    Most of those messages are Tier 3 and will never be opened by anyone.

    Deliberately narrow, because this deletes evidence:

      * it only ever touches files beneath `extract_dir`, so a directory of
        .eml the investigator supplied themselves is never at risk;
      * anything at a kept tier, or carrying an attachment-scan hit, stays; and
      * the container manifest is marked as pruned, so a later run reusing that
        extraction is told the staging directory is no longer the full mailbox.

    Understand what this costs before enabling it. The pipeline builds its
    corpus by walking the staging directory, so pruned messages are gone from
    every future run over that directory -- not merely absent from disk. The
    analysis cache still holds their records, but nothing looks them up,
    because their files are no longer discovered. Message totals, campaign
    clustering, the "deleted or moved to low-visibility folders" counts and the
    corpus hash in the run manifest all change accordingly.

    So this is a close-out step, for reclaiming disk once an investigation is
    finished, not a routine optimization. ``--reingest`` re-extracts the full
    mailbox from the container when the unflagged messages are needed again.
    """
    extract_dir = Path(extract_dir).resolve()
    keep = set()
    for record in records:
        if record.tier in keep_tiers or getattr(record, "enrichment_hits", None):
            keep.add(str(Path(record.path).resolve()))

    removed = kept = 0
    freed = 0
    failures = 0
    for path in extract_dir.rglob("*.eml"):
        resolved = str(path.resolve())
        if resolved in keep:
            kept += 1
            continue
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        if dry_run:
            removed += 1
            freed += size
            continue
        try:
            path.unlink()
            removed += 1
            freed += size
        except OSError:
            failures += 1

    if not dry_run and removed:
        # Mark every container manifest under this directory, so reuse of the
        # extraction cannot quietly pass for a full mailbox.
        for manifest_path in extract_dir.rglob(MANIFEST_NAME):
            target = manifest_path.parent
            data = read_manifest(target)
            if data:
                data["pruned"] = True
                data["pruned_keep_tiers"] = list(keep_tiers)
                write_manifest(target, data)

    return {"removed": removed, "kept": kept, "bytes_freed": freed,
            "failures": failures, "dry_run": dry_run}
