#!/usr/bin/env python3
"""Check a deployed copy of postmortem against the build manifest beside it.

Run this after syncing, before running an analysis:

    python verify_build.py

Standalone on purpose. `python -m postmortem --verify-build` does the same
job, but it cannot run when a module is missing altogether -- the package
fails to import long before the check would execute, and a missing module is
precisely the case worth catching. This script locates the package by path
and loads only the hashing helper, so it works on a tree too broken to start.

Exit codes:  0 matches (or no manifest to compare against)
             3 mismatch -- the files named must be copied again
             4 the package directory could not be found
"""

import importlib.util
import json
import os
import sys
from pathlib import Path


def _load_build_check(pkg_dir):
    """Import postmortem/build_check.py by path, without importing the package."""
    target = pkg_dir / "build_check.py"
    if not target.exists():
        return None
    spec = importlib.util.spec_from_file_location("_pm_build_check", target)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:
        return None
    return module


def _fallback_report(pkg_dir):
    """Compare against the manifest with no help from the package at all.

    Used when build_check.py is itself one of the files that went missing --
    which would otherwise leave the verifier unable to report the very
    problem it exists to report.
    """
    import hashlib

    manifest = pkg_dir / "BUILD.json"
    if not manifest.exists():
        print("  manifest   none beside %s" % pkg_dir)
        return 0
    try:
        with open(manifest, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        print("  manifest   unreadable: %s" % exc)
        return 0

    expected = doc.get("files") or {}
    actual = {}
    for name in sorted(os.listdir(pkg_dir)):
        if not name.endswith(".py"):
            continue
        h = hashlib.sha256()
        with open(pkg_dir / name, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        actual[name] = h.hexdigest()

    missing = sorted(n for n in expected if n not in actual)
    differing = sorted(n for n in expected if n in actual
                       and actual[n] != expected[n])
    if not (missing or differing):
        print("  result     MATCHES the recorded build (%s)"
              % doc.get("build_id", "?"))
        return 0
    print("  result     MISMATCH against build %s" % doc.get("build_id", "?"))
    if missing:
        print("  MISSING (never copied): " + ", ".join(missing))
    if differing:
        print("  STALE (older content):  " + ", ".join(differing))
    print("  Re-copy the whole package directory, then run again.")
    return 3


def main(argv):
    here = Path(__file__).resolve().parent
    pkg_dir = Path(argv[1]).resolve() if len(argv) > 1 else here / "postmortem"
    if not pkg_dir.is_dir():
        print("Package directory not found: %s" % pkg_dir, file=sys.stderr)
        print("Pass it explicitly:  python verify_build.py <path-to-postmortem>",
              file=sys.stderr)
        return 4

    print("postmortem build verification")
    print("  package    %s" % pkg_dir)

    checker = _load_build_check(pkg_dir)
    if checker is None:
        print("  note       build_check.py is missing from this copy")
        return _fallback_report(pkg_dir)

    result = checker.verify(pkg_dir)
    print("  build id   %s" % result["build_id"])
    if not result["checked"]:
        print("  manifest   none (this tree predates the build manifest)")
        return 0
    print("  expected   %s" % (result["expected"] or "?"))
    if result["ok"]:
        print("  result     MATCHES the recorded build")
        if result["extra"]:
            print("  note       extra file(s), not a problem: %s"
                  % ", ".join(result["extra"]))
        return 0
    print("  result     MISMATCH")
    for line in checker.describe(result):
        print("  " + line)
    return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
