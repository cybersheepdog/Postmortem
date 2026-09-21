#!/usr/bin/env python3
"""Read an Entra ID sign-in log export on its own, without a mail corpus.

This used to carry its own copy of the device code analysis. That copy was
built on the two-leg premise -- a phished flow shows up as an interactive
victim leg and a non-interactive attacker leg on one correlation ID -- which
published research contradicts: Entra records the sign-in where the
authentication was INITIATED, so a phish can be a single record carrying the
attacker's address. `postmortem.signin` was corrected; this file was not,
and two copies of one analysis with one of them wrong is worse than none.

It is now a thin wrapper over the library. Everything it prints is exactly
what `python -m postmortem <corpus> --signin-logs <folder>` prints for the
sign-in section, with the same single-record scoring, expected-client
suppression, tenant client baseline, AiTM profile, legacy-auth, MFA-fatigue
and spray checks. Use the full run when you also have the mailbox: the audit
log is what turns a sign-in finding into an attribution.

Usage:
    python find_device_code_flow.py <folder-or-file> [--json out.json]
                                    [--devices <Get-Devices export>] [--no-color]
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from postmortem import term  # noqa: E402
from postmortem.reporting import (  # noqa: E402
    print_signin_analysis, print_entry_vectors)
from postmortem.signin import analyze_signin_logs  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("path", help="sign-in export: a JSON/JSONL file or a "
                                 "folder of them")
    ap.add_argument("--devices", default="",
                    help="Get-Devices export, so the owner's own registered "
                         "devices are not read as attacker addresses")
    ap.add_argument("--json", default="",
                    help="also write the full summary as JSON here")
    ap.add_argument("--no-color", action="store_true", help="plain output")
    args = ap.parse_args(argv)

    term.set_enabled(not args.no_color and term.supports_color())

    devices = None
    if args.devices:
        try:
            from postmortem import persistence as P
            devices = P.parse_devices(P.load_rows(args.devices))
        except Exception as exc:  # a bad export must not stop the read
            print(f"[!] devices export not read ({exc}); continuing without it",
                  file=sys.stderr)

    summary = analyze_signin_logs(args.path, devices=devices)
    if not summary:
        print(f"[!] nothing readable at {args.path}", file=sys.stderr)
        return 2

    print_signin_analysis(summary)
    print_entry_vectors(summary)
    print()
    print("  For attribution against the mailbox, run the full tool with "
          "--signin-logs (or --mes-dir); token replay and the exposure scope "
          "need the unified audit log.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, default=str)
        print(f"  JSON written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
