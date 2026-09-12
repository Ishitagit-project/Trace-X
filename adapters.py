"""
adapters.py
-----------
Translates between the team's REST API contract (M1_API_HANDOFF.md) and the
internal shapes header_analysis.py / ip_intel.py / url_domain.py / scoring.py
already work with.

IMPORTANT: the handoff doc only describes GET /api/emails/:id in prose
("security_headers: Received hops, SPF, DKIM, DMARC, Return-Path, Message-ID"),
not with a full example response body. `adapt_email_response()` below makes
a reasonable best-guess at the field names (and checks common camelCase /
snake_case variants) — confirm the real shape with M2/M3 and adjust the
alias lists if anything doesn't match. The analysis logic itself won't need
to change, only these field lookups.
"""


def _pick(d: dict, *keys, default=None):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def adapt_email_response(raw: dict) -> dict:
    """GET /api/emails/:id response -> internal parsed_email dict."""
    sh = raw.get("security_headers") or raw.get("securityHeaders") or {}

    received_chain = _pick(sh, "receivedHops", "received_chain", "received", default=[]) or []
    normalized_chain = [
        {
            "by": _pick(hop, "by", "receivedBy"),
            "from": _pick(hop, "from", "receivedFrom"),
            "ip": _pick(hop, "ip", "ipAddress"),
            "timestamp": _pick(hop, "timestamp", "date", "time"),
        }
        for hop in received_chain
    ]

    parsed = {
        "_id": raw.get("_id") or raw.get("id") or raw.get("emailId"),
        "subject": raw.get("subject"),
        "from": raw.get("from") or raw.get("fromAddress"),
        "reply_to": _pick(sh, "replyTo", "reply_to"),
        "return_path": _pick(sh, "returnPath", "return_path"),
        "spf_result": _pick(sh, "spf", "spfResult", default="none"),
        "dkim_result": _pick(sh, "dkim", "dkimResult", default="none"),
        "dmarc_result": _pick(sh, "dmarc", "dmarcResult", default="none"),
        "message_id": _pick(sh, "messageId", "message_id"),
        "received_chain": normalized_chain,
        "urls": raw.get("urls") or raw.get("extractedUrls") or [],
    }

    # ip -> ioc _id, so we know which IOC record to PATCH once analysis is done.
    # ASSUMPTION: the email response embeds already-extracted IOCs. Confirm the
    # real field/shape with M2 — adjust the keys below once known.
    ioc_map = {}
    for ioc in raw.get("iocs", []) or []:
        ip_val = ioc.get("value") or ioc.get("ip")
        ioc_id = ioc.get("_id") or ioc.get("id")
        if ip_val and ioc_id:
            ioc_map[ip_val] = ioc_id
    parsed["_ioc_map"] = ioc_map

    return parsed


def _extract_asn(geo: dict):
    """ip-api.com's 'as' field looks like 'AS15169 Google LLC' — split off just the ASN."""
    as_field = (geo or {}).get("as") or ""
    return as_field.split(" ")[0] if as_field else None


def build_analysis_payload(report: dict) -> dict:
    """Internal report (main.analyze_one output) -> POST /api/analyses body."""
    trace = report["origin_trace"]
    auth_raw = report["details"]["header_analysis"].get("auth_raw", {})
    types_present = {e["type"] for e in report["evidence"]}

    if trace["mitm_detected"]:
        ip = (trace.get("suspect_hop") or {}).get("ip")
        geo = trace.get("suspect_hop_geolocation") or {}
    else:
        ip = trace.get("origin_ip")
        geo = trace.get("origin_geolocation") or {}

    return {
        "emailId": report["email_id"],
        "classification": report["classification"],
        "threatScore": report["threat_score"],
        "confidence": report["confidence_score"],  # float 0-1, per their schema
        "summary": report["summary"],
        "forensicEvidence": {
            "originatingIP": ip,
            "geolocation": {
                "country": geo.get("country"),
                "countryCode": geo.get("countryCode"),
                "city": geo.get("city"),
                "isp": geo.get("isp"),
                "asn": _extract_asn(geo),
                "latitude": geo.get("lat"),
                "longitude": geo.get("lon"),
            } if geo else None,
            "authentication": {
                "spf": auth_raw.get("spf_result", "none"),
                "dkim": auth_raw.get("dkim_result", "none"),
                "dmarc": auth_raw.get("dmarc_result", "none"),
            },
            "replyToMismatch": "reply_to_mismatch" in types_present,
        },
        "recommendations": report["recommendations"],
    }


# Guessed status vocabulary for the IOC record — confirm the actual allowed
# values with M2 (the handoff doc's only example is "blocked").
_STATUS_BY_FLAG = {"Flagged": "blocked", "Suspicious": "watchlisted", "Detected": "monitored"}


def build_ioc_payload(geo: dict, flag_status: str) -> dict:
    """Geolocation dict -> PATCH /api/iocs/:id body."""
    status = _STATUS_BY_FLAG.get(flag_status, "monitored")
    if not geo:
        return {"status": status}
    return {
        "geolocation": {
            "country": geo.get("country"),
            "city": geo.get("city"),
            "region": geo.get("region"),
            "isp": geo.get("isp"),
            "asn": _extract_asn(geo),
            "latitude": geo.get("lat"),
            "longitude": geo.get("lon"),
        },
        "status": status,
    }