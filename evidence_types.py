"""
evidence_types.py
------------------
Shared vocabulary for every piece of forensic evidence Member 1 produces.

This is the contract M2 (backend/API) asked for:
  - a fixed, structured shape for each evidence item (not free-text strings)
  - a fixed severity scale that maps predictably to points -> threat_score
  - a fixed classification + confidence + flag_status vocabulary

Every check in header_analysis.py / ip_intel.py / url_domain.py should build
its findings using make_evidence() below, so the final report is uniform
regardless of which module produced the evidence.
"""

# Points a single evidence item contributes toward the 0-100 threat_score.
SEVERITY_POINTS = {
    "low": 5,
    "medium": 15,
    "high": 25,
}

# Fixed vocabulary of evidence "type" values. Keep this list in sync with
# whatever checks you add later - M2's frontend will likely map these to icons/labels.
EVIDENCE_TYPES = {
    # header_analysis.py
    "spf_fail", "dkim_fail", "dmarc_fail",
    "reply_to_mismatch", "return_path_mismatch", "suspicious_sender_tld",
    "relay_chain_missing", "relay_chain_out_of_order", "forged_relay_hop",
    "private_ip_mid_chain",
    # ip_intel.py
    "suspicious_hosting_infra", "ip_abuse_reputation", "tor_exit_node",
    # url_domain.py
    "url_ip_literal", "url_shortener", "url_suspicious_tld",
    "url_brand_impersonation", "url_obfuscation", "url_punycode",
}

CLASSIFICATION_VALUES = {"phishing", "spam", "bec", "malware", "safe", "suspicious"}
CONFIDENCE_VALUES = {"low", "medium", "high"}
FLAG_STATUS_VALUES = {"Detected", "Suspicious", "Flagged"}


def make_evidence(evidence_type: str, severity: str, description: str, source: str, raw: dict = None) -> dict:
    """
    Structured evidence item - this is the atomic unit that populates the
    'Investigation Evidence' section of the Case Detail view.

    type        : one of EVIDENCE_TYPES (fixed vocabulary, stable for the frontend)
    severity    : "low" | "medium" | "high"
    description : human-readable explanation, safe to render directly in the UI
    source      : which module found it - "header_analysis" | "ip_intel" | "url_domain"
    raw         : optional supporting data (ip, domain, hop index, etc.) for drill-down
    """
    assert severity in SEVERITY_POINTS, f"invalid severity: {severity}"
    return {
        "type": evidence_type,
        "severity": severity,
        "description": description,
        "source": source,
        "raw": raw or {},
    }


def score_from_evidence(evidence_list: list) -> int:
    """Sums severity points across all evidence items, capped at 100."""
    total = sum(SEVERITY_POINTS[e["severity"]] for e in evidence_list)
    return min(total, 100)