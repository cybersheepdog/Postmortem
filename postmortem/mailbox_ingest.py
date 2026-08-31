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

import mailbox
import mimetypes
import re
import shutil
import sys
from email import message_from_string, policy
from email.message import EmailMessage
from pathlib import Path

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


def extract_mbox(path: Path, out_dir: Path) -> dict:
    box = mailbox.mbox(str(path))
    default_folder = _safe_component(path.stem) or "mbox"
    written = 0
    folders = set()
    try:
        for seq, key in enumerate(box.keys(), 1):
            try:
                raw = box.get_bytes(key)
                msg = box.get_message(key)
            except Exception:
                continue
            folder = _mbox_folder(msg, default_folder)
            folders.add(folder)
            _write_eml(out_dir, [folder], seq, raw)
            written += 1
    finally:
        box.close()
    return {
        "type": "mbox", "messages_written": written,
        "folders": sorted(folders), "note": "",
    }


# --------------------------------------------------------------------------
# PST / OST (optional pypff / libpff)
# --------------------------------------------------------------------------
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
    for key, value in base.items():
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


def _headers_to_str(msg) -> str:
    return "".join(f"{k}: {v}\r\n" for k, v in msg.items())


def _pst_walk(folder, path_parts, out_dir, counter) -> set:
    """Depth-first walk of pypff folders, extracting messages under their path."""
    folders_seen = set()
    try:
        name = folder.get_name()
    except Exception:
        name = None
    parts = path_parts + ([name] if name else [])
    if parts:
        folders_seen.add("/".join(parts))

    try:
        n_msgs = folder.number_of_sub_messages
    except Exception:
        n_msgs = 0
    for i in range(n_msgs):
        try:
            message = folder.get_sub_message(i)
            raw = _pst_reconstruct_eml(message)
        except Exception:
            continue
        counter[0] += 1
        _write_eml(out_dir, parts or ["Top of Outlook data file"], counter[0], raw)

    try:
        n_sub = folder.number_of_sub_folders
    except Exception:
        n_sub = 0
    for i in range(n_sub):
        try:
            sub = folder.get_sub_folder(i)
        except Exception:
            continue
        folders_seen |= _pst_walk(sub, parts, out_dir, counter)
    return folders_seen


def extract_pst(path: Path, out_dir: Path) -> dict:
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
    pff = pypff.file()
    counter = [0]
    folders = set()
    try:
        pff.open(str(path))
        root = pff.get_root_folder()
        folders = _pst_walk(root, [], out_dir, counter)
    finally:
        try:
            pff.close()
        except Exception:
            pass
    return {
        "type": path.suffix.lower().lstrip("."),
        "messages_written": counter[0],
        "folders": sorted(folders), "note": "",
    }


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
def ingest_container(path: Path, out_dir: Path, reingest: bool = False) -> dict:
    """Explode one container into `out_dir`. Idempotent unless `reingest`."""
    stem = _safe_component(path.stem) or "container"
    target = out_dir / stem
    if reingest and target.exists():
        shutil.rmtree(target, ignore_errors=True)
    existing = list(target.rglob("*.eml")) if target.exists() else []
    if existing and not reingest:
        return {
            "container": str(path), "type": path.suffix.lower().lstrip("."),
            "messages_written": len(existing), "folders": [],
            "note": "reused prior extraction (use --reingest to redo)",
            "output_dir": str(target), "reused": True,
        }

    suffix = path.suffix.lower()
    if suffix == ".mbox":
        result = extract_mbox(path, target)
    elif suffix in (".pst", ".ost"):
        result = extract_pst(path, target)
    else:
        result = {"type": suffix.lstrip("."), "messages_written": 0,
                  "folders": [], "note": "unsupported container type"}
    result["container"] = str(path)
    result["output_dir"] = str(target)
    return result


def ingest_all(root: Path, out_dir: Path, reingest: bool = False) -> dict:
    """Find and explode every container under `root` into `out_dir`.

    Returns a summary with per-container results and totals.
    """
    containers = find_containers(root)
    results = []
    total = 0
    skipped = []
    for c in containers:
        r = ingest_container(c, out_dir, reingest=reingest)
        results.append(r)
        total += int(r.get("messages_written", 0))
        if r.get("skipped"):
            skipped.append(r)
        if r.get("note") and not r.get("reused"):
            print(f"[i] {Path(c).name}: {r['note']}", file=sys.stderr)
    return {
        "containers_found": len(containers),
        "messages_written": total,
        "results": results,
        "skipped": skipped,
        "output_dir": str(out_dir),
    }
