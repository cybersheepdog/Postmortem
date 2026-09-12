"""Verify that the deployed copy of the package is the one that was built.

The code is edited in one place and run in another, and it travels by hand.
A file missed in transit leaves a tree that imports cleanly, passes a grep for
whatever was last fixed, and still runs the old logic -- which is how the same
defect survived two syncs and produced two identical tracebacks an hour into
two separate runs.

The mechanism is deliberately dumb: a manifest of per-file SHA-256 digests is
written beside the package when the code is finished, and travels with it. At
startup the live files are hashed and compared. A complete copy matches. An
incomplete one names the files that differ, which is the question the analyst
actually has -- not "is something wrong" but "what do I copy again".

It is advisory and never fatal: a tree with no manifest, or a manifest that
cannot be read, runs exactly as before. The failure this guards against is
silence, so the only thing it must never do is add a new way to stop.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

MANIFEST_NAME = "BUILD.json"


def _package_dir():
    import postmortem
    return Path(postmortem.__file__).resolve().parent


def _hash_file(path):
    """SHA-256 of the file's CONTENT, with line endings normalised to LF.

    Hashing raw bytes was wrong for the pipeline this actually travels:
    git on Windows converts LF to CRLF on checkout by default
    (core.autocrlf=true), so a correct, complete copy hashed differently
    from the tree it came from and every file was reported stale. That is a
    false alarm of the worst kind -- it trains the analyst to ignore the
    warning, which is the one thing this must never do.

    Normalising line endings is the narrowest fix that survives git: the
    question is whether the CODE matches, and a checkout style is not a
    difference in code. Nothing else is normalised -- whitespace, encoding
    and content are all still compared exactly.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def file_digests(pkg_dir=None):
    """{filename: sha256} for every .py in the package, sorted by name."""
    pkg_dir = Path(pkg_dir or _package_dir())
    out = {}
    for name in sorted(os.listdir(pkg_dir)):
        if not name.endswith(".py"):
            continue
        digest = _hash_file(pkg_dir / name)
        if digest:
            out[name] = digest
    return out


def build_id(digests=None):
    """Ten hex characters identifying the whole package at once."""
    digests = digests if digests is not None else file_digests()
    h = hashlib.sha256()
    for name, digest in sorted(digests.items()):
        h.update(name.encode("utf-8"))
        h.update(digest.encode("ascii"))
    return h.hexdigest()[:10]


def write_manifest(pkg_dir=None, tool_version="", parser_version=""):
    """Record the current tree. Run after finishing a change, before syncing."""
    pkg_dir = Path(pkg_dir or _package_dir())
    digests = file_digests(pkg_dir)
    doc = {
        "schema": "postmortem-build/1",
        "tool_version": tool_version,
        "parser_version": parser_version,
        "build_id": build_id(digests),
        "file_count": len(digests),
        "files": digests,
    }
    path = pkg_dir / MANIFEST_NAME
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
        fh.write("\n")
    return path, doc


def read_manifest(pkg_dir=None):
    pkg_dir = Path(pkg_dir or _package_dir())
    try:
        with open(pkg_dir / MANIFEST_NAME, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) and doc.get("files") else None


def verify(pkg_dir=None):
    """Compare the live files against the manifest.

    Returns a dict. `checked` is False when there is no manifest to check
    against, which is not a failure -- it is simply a tree that predates this
    mechanism, and it must keep working.
    """
    pkg_dir = Path(pkg_dir or _package_dir())
    doc = read_manifest(pkg_dir)
    if not doc:
        return {"checked": False, "ok": True, "build_id": build_id(
            file_digests(pkg_dir)), "expected": "", "differing": [],
            "missing": [], "extra": []}

    expected = doc.get("files") or {}
    actual = file_digests(pkg_dir)

    differing = sorted(n for n in expected if n in actual
                       and actual[n] != expected[n])
    missing = sorted(n for n in expected if n not in actual)
    # Extra files are reported but never treated as a failure: a scratch file
    # left in the package directory is untidy, not a stale deployment.
    extra = sorted(n for n in actual if n not in expected)

    return {
        "checked": True,
        "ok": not (differing or missing),
        "build_id": build_id(actual),
        "expected": doc.get("build_id", ""),
        "tool_version": doc.get("tool_version", ""),
        "differing": differing,
        "missing": missing,
        "extra": extra,
    }


def describe(result, width=78):
    """Human-readable lines for a verify() result, or [] when it all matches."""
    if not result.get("checked") or result.get("ok"):
        return []
    lines = [
        "THIS COPY DOES NOT MATCH THE BUILD IT CLAIMS TO BE.",
        "  expected build %s, this tree is %s"
        % (result.get("expected") or "?", result.get("build_id")),
    ]
    if result["missing"]:
        lines.append("  MISSING (never copied): " + ", ".join(result["missing"]))
    if result["differing"]:
        lines.append("  STALE (older content):  " + ", ".join(result["differing"]))
    lines.append("  Re-copy the whole package directory, then run again.")
    return lines
