"""
scoring.py
----------
Turns the combined structured evidence from header_analysis, ip_intel,
and url_domain into the final fields M2's backend/API schema needs:

  - threat_score : int 0-100
  - classification : one of CLASSIFICATION_VALUES
  - confidence : one of CONFIDENCE_VALUES
  - flag_status : one of FLAG_STATUS_VALUES  (drives the Evidence tab)

This is a transparent, rule-based baseline. Member 5's AI/NLP model can
layer on top of or override `classification` — keep `threat_score` and
`evidence` as the shared ground truth both of you build on.
"""

from evidence_types import score_from_evidence

# --- classification ---------------------------------------------------
# Evidence "type" values that strongly imply a specific classification.
MALWARE_TYPES = {"url_ip_literal", "url_obfuscation"}          # extend as attachment-hash checks are added
BEC_TYPES = {"reply_to_mismatch", "return_path_mismatch"}
PHISHING_TYPES = {"url_brand_impersonation", "url_punycode", "forged_relay_hop", "dmarc_fail"}
SPAM_TYPES = {"url_shortener", "url_suspicious_tld", "suspicious_sender_tld"}


def classify(evidence_list: list, threat_score: int) -> str:
    types_present = {e["type"] for e in evidence_list}

    if threat_score < 15:
        return "safe"
    if types_present & MALWARE_TYPES and threat_score >= 50:
        return "malware"
    if types_present & BEC_TYPES and threat_score >= 40:
        return "bec"
    if types_present & PHISHING_TYPES and threat_score >= 40:
        return "phishing"
    if types_present & SPAM_TYPES and threat_score < 40:
        return "spam"
    return "suspicious"  # evidence exists but doesn't cleanly fit a category yet


# --- confidence ---------------------------------------------------------
def confidence_score(evidence_list: list, header_result: dict) -> float:
    """
    Continuous 0-1 confidence score (needed as-is for the POST /api/analyses
    'confidence' field, which expects a float like 0.95 — not a bucket label).
    Reflects how much independent, corroborating evidence exists, not how
    bad the email looks. Capped low when underlying data is incomplete
    (e.g. no relay chain at all), even if the score looks high.
    """
    sources_hit = len({e["source"] for e in evidence_list})
    high_severity_count = sum(1 for e in evidence_list if e["severity"] == "high")

    relay = header_result.get("relay_chain_summary", {})
    data_incomplete = relay.get("hop_count", 0) == 0

    score = 0.3 + 0.15 * sources_hit + 0.1 * high_severity_count
    if data_incomplete:
        score = min(score, 0.4)
    return round(min(score, 0.98), 2)


def confidence_level(score: float) -> str:
    """Bucketed label (low/medium/high) derived from the same numeric score,
    for anywhere in the UI/dashboard that wants a label instead of a float."""
    if score >= 0.75:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


# --- flag_status (drives the Evidence tab: Detected / Suspicious / Flagged) --
def flag_status(threat_score: int, evidence_list: list) -> str:
    if threat_score >= 70:
        return "Flagged"
    if threat_score >= 30:
        return "Suspicious"
    if evidence_list:
        return "Detected"
    return "Detected"  # no case for "Clear" in the agreed vocabulary; adjust with M2 if needed


def combine(header_result: dict, ip_result: dict, url_result: dict) -> dict:
    all_evidence = header_result["evidence"] + ip_result["evidence"] + url_result["evidence"]
    threat_score = score_from_evidence(all_evidence)
    conf_score = confidence_score(all_evidence, header_result)

    return {
        "threat_score": threat_score,
        "classification": classify(all_evidence, threat_score),
        "confidence_score": conf_score,          # float 0-1, for the API payload
        "confidence": confidence_level(conf_score),  # low/medium/high, for internal/dashboard use
        "flag_status": flag_status(threat_score, all_evidence),
        "evidence": all_evidence,
    }


# --- narrative: summary + recommendations, for the POST /api/analyses payload ---
_AUTH_LABELS = {"spf_fail": "SPF", "dkim_fail": "DKIM", "dmarc_fail": "DMARC"}


def generate_summary(report: dict) -> str:
    """One-sentence, human-readable summary matching the tone of the example
    in M1_API_HANDOFF.md ('Email originated from a suspicious Russian IP with
    failed SPF and mismatched Return-Path.')."""
    trace = report["origin_trace"]
    types_present = {e["type"] for e in report["evidence"]}

    issues = []
    failed_auth = [label for etype, label in _AUTH_LABELS.items() if etype in types_present]
    if failed_auth:
        issues.append("failed " + "/".join(failed_auth))
    if "reply_to_mismatch" in types_present:
        issues.append("a mismatched Reply-To address")
    if "return_path_mismatch" in types_present:
        issues.append("a mismatched Return-Path")
    if "forged_relay_hop" in types_present:
        issues.append("a fabricated relay hop consistent with a man-in-the-middle")
    if "url_brand_impersonation" in types_present:
        issues.append("a brand-impersonating link")

    if trace["mitm_detected"]:
        geo = trace.get("suspect_hop_geolocation") or {}
        country = geo.get("country")
        origin_phrase = (f"a suspicious {country} IP (unverified — the relay chain was tampered with)"
                          if country else "an unverified IP, since the relay chain was tampered with")
    else:
        geo = trace.get("origin_geolocation") or {}
        country = geo.get("country")
        qualifier = "suspicious " if report["flag_status"] != "Detected" and country else ""
        origin_phrase = f"a {qualifier}{country} IP" if country else "an IP with unresolved geolocation"

    if not issues:
        return f"Email originated from {origin_phrase}. No significant authentication or header anomalies were found."
    return f"Email originated from {origin_phrase} with {' and '.join(issues[:2])}."


def generate_recommendations(report: dict) -> list:
    """Rule-based action list matching the 'recommendations' field shape in the handoff doc."""
    trace = report["origin_trace"]
    ip = trace.get("origin_ip") or (trace.get("suspect_hop") or {}).get("ip")
    recs = []

    if report["flag_status"] == "Flagged":
        if ip:
            recs.append(f"Block IP {ip} on perimeter firewall")
        recs.append("Quarantine email across all mailboxes")
    if report["flag_status"] in ("Flagged", "Suspicious") and report["classification"] in ("phishing", "bec"):
        recs.append("Notify the impersonated brand/domain owner if applicable")
    if trace["mitm_detected"]:
        recs.append("Escalate to forensic review — relay chain shows signs of tampering; "
                     "do not treat the reported origin as confirmed")
    if not recs:
        recs.append("No action required — continue standard monitoring")
    return recs