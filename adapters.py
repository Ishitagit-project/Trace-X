"""
adapters.py
-----------
Translates between the team's REST API contract (M1_API_HANDOFF.md) and the
internal shapes header_analysis.py / ip_intel.py / url_domain.py / scoring.py
already work with.
"""

import re


def _pick(d: dict, *keys, default=None):
    if not isinstance(d, dict):
        return default
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def _parse_hop_string(hop_str: str) -> dict:
    """Parses a raw Received header string into a hop dict."""
    if not isinstance(hop_str, str):
        return {}
    by_m = re.search(r'\bby\s+([^\s;()]+)', hop_str, re.IGNORECASE)
    from_m = re.search(r'\bfrom\s+([^\s;()]+)', hop_str, re.IGNORECASE)
    ip_m = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', hop_str)
    ts_m = re.search(r';\s*(.+)$', hop_str)

    return {
        "by": by_m.group(1) if by_m else None,
        "from": from_m.group(1) if from_m else None,
        "ip": ip_m.group(1) if ip_m else None,
        "timestamp": ts_m.group(1).strip() if ts_m else None,
    }


def _extract_auth_result(sh: dict, key: str, fallback_list_key: str = None) -> str:
    val = sh.get(key)
    if isinstance(val, str) and val.strip():
        return val.strip().lower()

    if fallback_list_key:
        items = sh.get(fallback_list_key) or []
        if isinstance(items, str):
            items = [items]
        combined = " ".join(items).lower()
        if "pass" in combined:
            return "pass"
        if "fail" in combined:
            return "fail"
        if "softfail" in combined:
            return "softfail"
    return "none"


def adapt_email_response(raw: dict) -> dict:
    """GET /api/emails/:id response -> internal parsed_email dict."""
    data = raw.get("data", raw) if isinstance(raw, dict) else raw
    sh = data.get("security_headers") or data.get("securityHeaders") or {}

    received_chain_raw = _pick(sh, "receivedHops", "received_chain", "received", default=[]) or []
    normalized_chain = []
    for hop in received_chain_raw:
        if isinstance(hop, dict):
            normalized_chain.append({
                "by": _pick(hop, "by", "receivedBy"),
                "from": _pick(hop, "from", "receivedFrom"),
                "ip": _pick(hop, "ip", "ipAddress"),
                "timestamp": _pick(hop, "timestamp", "date", "time"),
            })
        elif isinstance(hop, str):
            parsed_hop = _parse_hop_string(hop)
            if any(parsed_hop.values()):
                normalized_chain.append(parsed_hop)

    sender_val = data.get("sender") or data.get("from") or data.get("fromAddress")
    if isinstance(sender_val, list):
        sender_val = sender_val[0] if sender_val else ""

    reply_to_val = data.get("reply_to") or _pick(sh, "replyTo", "reply_to")
    if isinstance(reply_to_val, list):
        reply_to_val = reply_to_val[0] if reply_to_val else ""

    parsed = {
        "_id": str(data.get("_id") or data.get("id") or ""),
        "email_id": str(data.get("email_id") or data.get("emailId") or data.get("_id") or ""),
        "subject": data.get("subject"),
        "from": sender_val,
        "reply_to": reply_to_val,
        "return_path": _pick(sh, "return_path", "returnPath"),
        "spf_result": _extract_auth_result(sh, "spf", "received_spf"),
        "dkim_result": _extract_auth_result(sh, "dkim", "dkim_signature"),
        "dmarc_result": _extract_auth_result(sh, "dmarc", "authentication_results"),
        "message_id": _pick(sh, "message_id", "messageId"),
        "received_chain": normalized_chain,
        "urls": data.get("urls") or data.get("extractedUrls") or [],
    }

    ioc_map = {}
    for ioc in data.get("iocs", []) or []:
        ip_val = ioc.get("value") or ioc.get("ip")
        ioc_id = ioc.get("_id") or ioc.get("id")
        if ip_val and ioc_id:
            ioc_map[ip_val] = str(ioc_id)
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


_STATUS_BY_FLAG = {"Flagged": "blocked", "Suspicious": "watchlisted", "Detected": "monitored"}


def build_ioc_payload(geo: dict, flag_status: str) -> dict:
    """Geolocation dict -> PATCH /api/iocs/:id body."""
    status = _STATUS_BY_FLAG.get(flag_status, "monitored")
    if not geo:
        return {"status": status}
    return {
        "geolocation": {
            "country": geo.get("country") or "",
            "city": geo.get("city") or "",
            "region": geo.get("region") or "",
            "isp": geo.get("isp") or "",
            "asn": _extract_asn(geo) or "",
            "latitude": geo.get("lat"),
            "longitude": geo.get("lon"),
        },
        "status": status,
    }