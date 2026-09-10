"""Optional QR-code ("quishing") detection (``--scan-qr``).

Requires the optional ``pyzbar`` + ``Pillow`` packages. Decodes QR codes found
in image attachments and runs any decoded URL through the offline URL analyzer,
catching phishing links that hide inside an image to evade text-based scanning.
Degrades gracefully if the libraries are missing. Image parsing is wrapped so a
malformed image never crashes the run. When the YARA pass is enabled too, both
share a single decode of each message's attachments.
"""

from postmortem.urls import analyze_url_robust


def _flag(record, filename, url):
    from postmortem.scoring import make_finding
    sig = f"QR code in attachment {filename} links to {url}"
    record.indicators = list(dict.fromkeys(list(record.indicators) + [sig]))
    record.provenance = list(record.provenance) + [make_finding(
        sig, category="url", source="qr_code", matched=url,
        weight=6, severity="high")]
    analysis = analyze_url_robust(url)
    analysis["source"] = "qr_code"
    record.url_analysis = list(record.url_analysis) + [analysis]
    record.score += 6
    record.tier = 1


def scan_records(records, tiers=(1, 2), workers=None):
    """Decode QR codes in Tier 1/2 image attachments. Returns URL hit count.

    The decode itself lives in :mod:`postmortem.attachment_scan`, which shares
    one attachment decode between this pass and the YARA pass and runs them in
    parallel.
    """
    from postmortem.attachment_scan import run_passes
    _, hits = run_passes(
        records, rules_path=None, want_qr=True, tiers=tiers,
        requested_workers=workers,
    )
    return hits
