"""
ip_intel.py
-----------
Enriches originating IP addresses with geolocation + reputation data,
and emits structured evidence items (see evidence_types.py).

- Geolocation: ip-api.com (free, no key required)
- Reputation: AbuseIPDB (needs config.ABUSEIPDB_API_KEY) — degrades
  gracefully and just skips reputation scoring if no key is set.
"""

import requests
import config
from evidence_types import make_evidence

IP_API_URL = "http://ip-api.com/json/{ip}"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

VPN_TOR_HOSTING_KEYWORDS = (
    "vpn", "proxy", "tor", "hosting", "digitalocean", "ovh",
    "amazon", "aws", "google cloud", "azure", "linode", "vultr",
)


def geolocate_ip(ip: str) -> dict:
    try:
        resp = requests.get(IP_API_URL.format(ip=ip), timeout=5)
        data = resp.json()
        if data.get("status") != "success":
            return {"ip": ip, "error": data.get("message", "lookup failed")}
        return {
            "ip": ip, "country": data.get("country"), "countryCode": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"), "isp": data.get("isp"), "org": data.get("org"),
            "as": data.get("as"), "lat": data.get("lat"), "lon": data.get("lon"),
        }
    except requests.RequestException as e:
        return {"ip": ip, "error": str(e)}


def check_abuse_reputation(ip: str) -> dict:
    if not config.ABUSEIPDB_API_KEY:
        return {"ip": ip, "checked": False, "note": "ABUSEIPDB_API_KEY not configured"}
    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"}, timeout=5,
        )
        data = resp.json().get("data", {})
        return {
            "ip": ip, "checked": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "is_tor": data.get("isTor"), "usage_type": data.get("usageType"),
        }
    except requests.RequestException as e:
        return {"ip": ip, "checked": False, "error": str(e)}


def enrich_ip(ip: str) -> dict:
    """Combines geolocation + reputation, and produces structured evidence for this IP."""
    geo = geolocate_ip(ip)
    rep = check_abuse_reputation(ip)
    evidence = []

    org_text = f"{geo.get('isp', '')} {geo.get('org', '')} {geo.get('as', '')}".lower()
    if any(kw in org_text for kw in VPN_TOR_HOSTING_KEYWORDS):
        evidence.append(make_evidence(
            "suspicious_hosting_infra", "medium",
            f"Originating IP {ip} is associated with hosting/VPN/cloud infrastructure ({geo.get('org')})",
            "ip_intel", {"ip": ip, "org": geo.get("org")}))

    if rep.get("checked"):
        score = rep.get("abuse_confidence_score") or 0
        if score >= 50:
            evidence.append(make_evidence(
                "ip_abuse_reputation", "high",
                f"IP {ip} has a high abuse confidence score ({score}/100) on AbuseIPDB",
                "ip_intel", {"ip": ip, "score": score}))
        elif score >= 20:
            evidence.append(make_evidence(
                "ip_abuse_reputation", "medium",
                f"IP {ip} has a moderate abuse confidence score ({score}/100) on AbuseIPDB",
                "ip_intel", {"ip": ip, "score": score}))
        if rep.get("is_tor"):
            evidence.append(make_evidence(
                "tor_exit_node", "high", f"IP {ip} is a known Tor exit node",
                "ip_intel", {"ip": ip}))

    return {"geolocation": geo, "reputation": rep, "evidence": evidence}


def run(parsed_email: dict) -> dict:
    """
    Expects parsed_email['candidate_ips'] = ["1.2.3.4", ...], ideally seeded
    from the earliest relay hop found by header_analysis.
    """
    ips = parsed_email.get("candidate_ips") or []
    reports = {}
    all_evidence = []

    for ip in ips:
        r = enrich_ip(ip)
        reports[ip] = r
        all_evidence.extend(r["evidence"])

    return {"ip_reports": reports, "evidence": all_evidence}