"""Optional QR-code ("quishing") detection (``--scan-qr``).

Requires the optional ``pyzbar`` + ``Pillow`` packages. Decodes QR codes found
in image attachments and runs any decoded URL through the offline URL analyzer,
catching phishing links that hide inside an image to evade text-based scanning.
Degrades gracefully if the libraries are missing. Image parsing is wrapped so a
malformed image never crashes the run.
"""

import io
import sys

from postmortem.parsing import iter_attachment_payloads
from postmortem.urls import extract_urls, analyze_url_robust


def _make_decoder():
    try:
        from pyzbar.pyzbar import decode as zbar_decode
        from PIL import Image
    except Exception:
        return None

    def decode(payload):
        try:
            img = Image.open(io.BytesIO(payload))
            return [d.data.decode("utf-8", "ignore") for d in zbar_decode(img)]
        except Exception:
            return []
    return decode


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


def scan_records(records, tiers=(1, 2)):
    """Decode QR codes in Tier 1/2 image attachments. Returns URL hit count."""
    decode = _make_decoder()
    if decode is None:
        print("[!] --scan-qr given but pyzbar/Pillow are not installed; "
              "skipping QR scan.", file=sys.stderr)
        return 0
    hits = 0
    for r in records:
        if r.tier not in tiers:
            continue
        for filename, ctype, payload in iter_attachment_payloads(r.path):
            if not str(ctype).startswith("image/") or not payload:
                continue
            for text in decode(payload):
                for url in extract_urls(text):
                    _flag(r, filename, url)
                    hits += 1
    return hits
