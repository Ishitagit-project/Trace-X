"""
url_domain.py
-------------
Analyzes links/domains found in the email body (extracted by Member 3's
parser) for phishing indicators, and emits structured evidence items.
"""

import socket
import tldextract
from evidence_types import make_evidence

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "gq", "tk", "cf", "ml", "work", "info", "loan"}
BRAND_KEYWORDS = (
    "paypal", "microsoft", "office365", "apple", "amazon", "google",
    "bankofamerica", "chase", "netflix", "irs", "docusign",
)


def is_ip_literal(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except (OSError, socket.error):
        return False


def analyze_url(url: str) -> dict:
    evidence = []
    ext = tldextract.extract(url)
    domain = ".".join(part for part in [ext.domain, ext.suffix] if part)
    host = ext.fqdn or domain

    if host and is_ip_literal(host):
        evidence.append(make_evidence(
            "url_ip_literal", "medium", f"URL uses a raw IP address instead of a domain: {url}",
            "url_domain", {"url": url}))

    if domain in URL_SHORTENERS:
        evidence.append(make_evidence(
            "url_shortener", "low",
            f"URL uses a link-shortening service ({domain}) which can mask the real destination",
            "url_domain", {"url": url, "domain": domain}))

    if ext.suffix in SUSPICIOUS_TLDS:
        evidence.append(make_evidence(
            "url_suspicious_tld", "low", f"URL domain uses a commonly-abused TLD (.{ext.suffix}): {domain}",
            "url_domain", {"url": url, "domain": domain}))

    lowered = (ext.domain or "").lower()
    for brand in BRAND_KEYWORDS:
        if brand in lowered and lowered != brand:
            evidence.append(make_evidence(
                "url_brand_impersonation", "high",
                f"Domain '{domain}' appears to impersonate the brand '{brand}'",
                "url_domain", {"url": url, "domain": domain, "brand": brand}))
            break

    if "@" in url.split("//")[-1]:
        evidence.append(make_evidence(
            "url_obfuscation", "high",
            f"URL contains '@' which can be used to obfuscate the real destination: {url}",
            "url_domain", {"url": url}))

    if host.startswith("xn--") or ".xn--" in host:
        evidence.append(make_evidence(
            "url_punycode", "high",
            f"URL uses punycode encoding, often used for homograph/lookalike attacks: {host}",
            "url_domain", {"url": url, "host": host}))

    if host.count("-") >= 3:
        evidence.append(make_evidence(
            "url_suspicious_tld", "low",
            f"URL domain has an unusually high number of hyphens (possible lookalike): {host}",
            "url_domain", {"url": url, "host": host}))

    return {"url": url, "domain": domain, "evidence": evidence}


def run(parsed_email: dict) -> dict:
    urls = parsed_email.get("urls") or []
    reports = []
    all_evidence = []

    for url in urls:
        r = analyze_url(url)
        reports.append(r)
        all_evidence.extend(r["evidence"])

    return {"url_reports": reports, "evidence": all_evidence}