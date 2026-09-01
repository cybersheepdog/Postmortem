"""Optional offline geolocation / ASN enrichment (``--geoip-db``).

Given one or more local MaxMind GeoLite2 databases (City/Country and/or ASN),
this resolves the country and hosting ASN/organization of a message's
originating IP and its Received-chain hops, and raises two signals:

  * suspicious geography -- a hop in a country outside the org's expected set
    (``--expected-countries``), which is circumstantial on its own;
  * high-abuse hosting -- the ASN organization matches a configured keyword list
    (``high_abuse_asn_keywords``), a stronger corroborator.

Fully offline: it reads local ``.mmdb`` files and makes no network call. Needs
the ``maxminddb`` reader (a dependency of ``geoip2``); degrades gracefully with
a warning if the reader or the databases are absent. Private/reserved IPs are
ignored.
"""

import ipaddress
import re
import sys

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _public_ips(text_values):
    """Yield distinct public IPv4 addresses found in the given header strings."""
    seen = set()
    for value in text_values or []:
        for m in _IP_RE.finditer(str(value)):
            ip = m.group(0)
            if ip in seen:
                continue
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.is_global:
                seen.add(ip)
                yield ip


class GeoResolver:
    """Wraps one or more opened GeoLite2 .mmdb readers. Offline-safe."""

    def __init__(self, db_paths):
        self.readers = []
        try:
            import maxminddb
        except Exception:
            print("[!] --geoip-db given but the 'maxminddb' reader is not "
                  "installed; skipping geolocation.", file=sys.stderr)
            return
        for path in db_paths or []:
            try:
                self.readers.append(maxminddb.open_database(str(path)))
            except Exception as exc:
                print(f"[!] Could not open GeoIP database {path}: {exc}",
                      file=sys.stderr)

    def available(self):
        return bool(self.readers)

    def lookup(self, ip):
        """Return {country, asn, org} merged across the opened databases."""
        out = {"country": "", "asn": "", "org": ""}
        for reader in self.readers:
            try:
                rec = reader.get(ip)
            except Exception:
                rec = None
            if not isinstance(rec, dict):
                continue
            country = (rec.get("country") or {}).get("iso_code") or \
                (rec.get("registered_country") or {}).get("iso_code")
            if country and not out["country"]:
                out["country"] = country
            asn = rec.get("autonomous_system_number")
            if asn and not out["asn"]:
                out["asn"] = f"AS{asn}"
            org = rec.get("autonomous_system_organization")
            if org and not out["org"]:
                out["org"] = org
        return out

    def close(self):
        for reader in self.readers:
            try:
                reader.close()
            except Exception:
                pass


def annotate_records(records, resolver, expected_countries, high_abuse_keywords,
                     tiers=(1, 2)):
    """Geolocate suspect messages' IPs and raise geography / hosting signals.

    Returns (geo_flags, host_flags) counts. Findings are added with provenance
    and a modest score bump; geography is left circumstantial (no tier change).
    """
    from postmortem.scoring import make_finding

    expected = {c.strip().upper() for c in (expected_countries or []) if c.strip()}
    keywords = [k.lower() for k in (high_abuse_keywords or [])]
    geo_hits = host_hits = 0

    for r in records:
        if r.tier not in tiers:
            continue
        auth = r.authentication_results or {}
        ips = list(_public_ips(
            ([r.origin_ip] if r.origin_ip else []) + list(auth.get("received", []))
        ))
        if not ips:
            continue

        countries, asns, orgs = [], [], []
        for ip in ips:
            info = resolver.lookup(ip)
            if info["country"]:
                countries.append(info["country"])
            if info["asn"]:
                asns.append((info["asn"], info["org"], ip))
            if info["org"]:
                orgs.append(info["org"])

        # Record the origin IP's geo/ASN (first IP is the submission hop).
        first = resolver.lookup(ips[0])
        r.origin_country = first["country"]
        r.origin_asn = first["asn"]
        r.origin_org = first["org"]

        if expected and countries:
            unexpected = sorted({c for c in countries if c not in expected})
            if unexpected:
                r.suspicious_geo = True
                geo_hits += 1
                sig = ("Message routed through unexpected country/countries: "
                       + ", ".join(unexpected))
                _add(r, sig, make_finding(
                    sig, category="geo", source="geoip",
                    matched=", ".join(unexpected),
                    weight=CONFIG_WEIGHT("suspicious_geo")))

        abusive = [(asn, org, ip) for (asn, org, ip) in asns
                   if org and any(k in org.lower() for k in keywords)]
        if abusive:
            r.high_abuse_host = True
            host_hits += 1
            label = ", ".join(sorted({f"{org} ({asn})" for asn, org, _ in abusive}))
            sig = f"Originating IP is on a high-abuse hosting network: {label}"
            _add(r, sig, make_finding(
                sig, category="geo", source="geoip_asn", matched=label,
                weight=CONFIG_WEIGHT("high_abuse_host")))

    return geo_hits, host_hits


def _add(record, indicator, finding):
    record.indicators = list(dict.fromkeys(list(record.indicators) + [indicator]))
    record.provenance = list(record.provenance) + [finding]
    record.score += int(finding.get("weight", 0))


def CONFIG_WEIGHT(name):
    from postmortem.config import CONFIG
    return CONFIG["priority_weights"].get(name, 0)
