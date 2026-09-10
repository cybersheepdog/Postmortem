"""Process-pool worker functions.

These live in their own module rather than in ``__main__.py`` for a reason that
is invisible on Linux and fatal on Windows.

A process pool has to send the worker function to each child. On Linux the
default start method is ``fork``, so the child already has the parent's memory
and any function is reachable. On Windows -- and on macOS since 3.8 -- the
start method is ``spawn``: the child is a fresh interpreter that re-imports the
function by its module path. A function defined in ``postmortem/__main__.py``
and reached via ``python -m postmortem`` has the module path ``__main__``, and
in the child ``__main__`` is a bare frozen module that contains nothing::

    AttributeError: Can't get attribute '_parse_uncached_worker'
        on <module '__main__' (<class '_frozen_importlib.BuiltinImporter'>)>
    concurrent.futures.process.BrokenProcessPool: A process in the process pool
        was terminated abruptly ...

Every worker died on startup, the pool broke, and the run aborted -- so
parallel parsing and deep enrichment never worked on Windows at all. Defining
them here gives them a real, importable module path that ``spawn`` can resolve.

Anything handed to a process pool belongs in this module.
"""

import sys
from pathlib import Path

from postmortem.parsing import parse_eml
from postmortem.urls import analyze_url_robust, extract_url_domains


def _parse_uncached_worker(path):
    """Top-level (picklable) parse worker for the process pool.

    Never propagates an exception: a single unparseable message (malformed
    headers, a MIME structure the stdlib chokes on) must degrade to one skipped
    file, not abort a run of tens of thousands of messages partway through.
    """
    try:
        return path, parse_eml(path, deep=False)
    except Exception as exc:  # pragma: no cover - defensive
        print(
            f"\n[!] Skipping {path}: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return path, None


def _deep_url_set(deep_record) -> list[str]:
    """All URLs to analyze for a deeply-parsed record, including links found in
    HTML hrefs (parse_eml surfaces those only inside url_analysis) and links
    embedded in attachments, so credential-phish links carried in HTML-only mail
    or inside an attachment are not missed."""
    href_urls = [
        str(a.get("url") or "")
        for a in (deep_record.url_analysis or [])
    ]
    attach_urls = [
        u
        for a in (deep_record.attachment_details or [])
        if isinstance(a, dict)
        for u in (a.get("embedded_urls") or [])
    ]
    return [
        u for u in dict.fromkeys(list(deep_record.urls) + href_urls + attach_urls)
        if u
    ]


def _deep_analyze_worker(job):
    """Top-level (picklable) deep-enrichment worker for the process pool.

    Returns only picklable data; the parent process applies it to the shared
    record list. URL analysis is deduplicated within this worker exactly as the
    in-process cache does (strip key, analyze once, hand back an independent
    copy) so results are identical regardless of pool type.
    """
    index, path = job
    try:
        deep_record = parse_eml(Path(path), deep=True)
    except Exception as exc:  # pragma: no cover - defensive
        print(
            f"\n[!] Skipping deep analysis of {path}: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return index, None
    if deep_record is None:
        return index, None

    all_urls = _deep_url_set(deep_record)
    local_cache = {}
    url_analysis = []
    for url in all_urls:
        key = url.strip()
        if key not in local_cache:
            local_cache[key] = analyze_url_robust(key)
        url_analysis.append(dict(local_cache[key]))

    precursor_evidence = [
        indicator
        for analysis in url_analysis
        for indicator in analysis.get("indicators", [])
    ]
    return index, {
        "urls": all_urls,
        "url_domains": extract_url_domains(all_urls),
        "attachments": deep_record.attachments,
        "attachment_details": deep_record.attachment_details,
        "url_analysis": url_analysis,
        "precursor_evidence": precursor_evidence,
    }


