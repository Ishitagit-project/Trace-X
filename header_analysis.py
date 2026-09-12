"""
header_analysis.py
-------------------
Analyzes the header/protocol fields that Member 3's parser already
extracted from the .eml file: SPF/DKIM/DMARC results, Received chain,
Return-Path / From / Reply-To alignment.

IMPORTANT: this module works ON TOP OF Member 3's parsed output — it is
NOT independent. Input is the parsed email dict as stored by Member 2 in
MongoDB. Output is a list of structured evidence items (see evidence_types.py)
that feed the Evidence tab / "Investigation Evidence" section.
"""

import socket
import ipaddress
from dateutil import parser as dtparser

from evidence_types import make_evidence

DISPOSABLE_LOOKALIKE_TLDS = {"xyz", "top", "click", "gq", "tk", "cf", "ml", "work"}
MIN_PLAUSIBLE_HOP_GAP_SECONDS = 1


def _get(doc, *keys, default=None):
    """Walk a list of possible field-name aliases and return the first hit."""
    for k in keys:
        if k in doc and doc[k] not in (None, ""):
            return doc[k]
    return default


def check_auth_results(parsed_email: dict) -> list:
    """SPF / DKIM / DMARC pass/fail/none from the parsed headers."""
    spf, dkim, dmarc = _auth_raw(parsed_email)

    evidence = []
    if spf != "pass":
        evidence.append(make_evidence(
            "spf_fail", "medium", f"SPF check did not pass (result: {spf})",
            "header_analysis", {"spf_result": spf}))
    if dkim != "pass":
        evidence.append(make_evidence(
            "dkim_fail", "medium", f"DKIM check did not pass (result: {dkim})",
            "header_analysis", {"dkim_result": dkim}))
    if dmarc != "pass":
        evidence.append(make_evidence(
            "dmarc_fail", "high", f"DMARC check did not pass (result: {dmarc})",
            "header_analysis", {"dmarc_result": dmarc}))
    return evidence


def _auth_raw(parsed_email: dict) -> tuple:
    spf = str(_get(parsed_email, "spf_result", "spf", default="none")).lower()
    dkim = str(_get(parsed_email, "dkim_result", "dkim", default="none")).lower()
    dmarc = str(_get(parsed_email, "dmarc_result", "dmarc", default="none")).lower()
    return spf, dkim, dmarc


def check_sender_alignment(parsed_email: dict) -> list:
    """Compares From / Reply-To / Return-Path domains - a mismatch is a classic BEC/phishing indicator."""
    import re

    from_addr = str(_get(parsed_email, "from", "from_address", default=""))
    reply_to = str(_get(parsed_email, "reply_to", default=""))
    return_path = str(_get(parsed_email, "return_path", default=""))

    def domain_of(addr):
        m = re.search(r"@([\w.-]+)", addr)
        return m.group(1).lower() if m else None

    from_domain = domain_of(from_addr)
    reply_domain = domain_of(reply_to)
    return_domain = domain_of(return_path)

    evidence = []
    if reply_domain and from_domain and reply_domain != from_domain:
        evidence.append(make_evidence(
            "reply_to_mismatch", "high",
            f"Reply-To domain '{reply_domain}' differs from From domain '{from_domain}' "
            "(possible impersonation / redirect-reply attack)",
            "header_analysis", {"from_domain": from_domain, "reply_to_domain": reply_domain}))

    if return_domain and from_domain and return_domain != from_domain:
        evidence.append(make_evidence(
            "return_path_mismatch", "medium",
            f"Return-Path domain '{return_domain}' differs from From domain '{from_domain}' "
            "(possible spoofed sender)",
            "header_analysis", {"from_domain": from_domain, "return_path_domain": return_domain}))

    if from_domain and from_domain.split(".")[-1] in DISPOSABLE_LOOKALIKE_TLDS:
        evidence.append(make_evidence(
            "suspicious_sender_tld", "low",
            f"From domain uses a commonly-abused TLD (.{from_domain.split('.')[-1]})",
            "header_analysis", {"from_domain": from_domain}))

    return evidence


def _hostname_matches(claimed_host, resolved_host):
    if not claimed_host or not resolved_host:
        return None
    c, r = claimed_host.lower().rstrip("."), resolved_host.lower().rstrip(".")
    return c == r or c.endswith("." + r) or r.endswith("." + c)


_DNS_CACHE = {}


def _reverse_dns(ip: str):
    if not ip:
        return None
    if ip in _DNS_CACHE:
        return _DNS_CACHE[ip]
    try:
        socket.setdefaulttimeout(2.0)
        res = socket.gethostbyaddr(ip)[0]
        _DNS_CACHE[ip] = res
        return res
    except Exception:
        _DNS_CACHE[ip] = None
        return None


def _is_private_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


def detect_forged_hop(chain: list) -> dict:
    """
    Walks the Received chain to find the specific hop where a middleman
    likely fabricated or rewrote a Received header. See README for the
    chain-of-custody logic. Returns the suspect hop + structured evidence.
    """
    suspects = []

    for i in range(len(chain) - 1):
        hop, next_hop = chain[i], chain[i + 1]
        claimed_from, next_by = hop.get("from"), next_hop.get("by")
        reasons = []

        if _hostname_matches(claimed_from, next_by) is False:
            reasons.append((
                "forged_relay_hop", "high",
                f"Hop claims message came 'from {claimed_from}', but the next hop down the chain "
                f"was logged as received 'by {next_by}' — chain of custody breaks here, indicating "
                "an inserted or rewritten Received header."
            ))

        t1, t2 = hop.get("timestamp"), next_hop.get("timestamp")
        if t1 and t2:
            try:
                delta = (dtparser.parse(t1) - dtparser.parse(t2)).total_seconds()
                if delta < 0:
                    reasons.append((
                        "forged_relay_hop", "high",
                        f"Timestamp for this hop ({t1}) is earlier than the hop before it ({t2}) — "
                        "chronologically impossible, suggests a fabricated hop."
                    ))
                elif 0 <= delta < MIN_PLAUSIBLE_HOP_GAP_SECONDS:
                    reasons.append((
                        "forged_relay_hop", "medium",
                        f"Timestamps between consecutive hops are essentially identical ({t1} vs {t2}) — "
                        "unusual for a genuine multi-relay path, consistent with a synthetically inserted hop."
                    ))
            except (ValueError, OverflowError):
                pass

        ip = hop.get("ip")
        if ip and claimed_from and not _is_private_ip(ip):
            ptr = _reverse_dns(ip)
            if ptr and _hostname_matches(claimed_from, ptr) is False:
                reasons.append((
                    "forged_relay_hop", "high",
                    f"IP {ip} reverse-resolves to '{ptr}', which does not match the hostname this hop "
                    f"claims ('{claimed_from}') — classic sign of a spoofed Received header."
                ))

        if ip and _is_private_ip(ip) and i != len(chain) - 1:
            reasons.append((
                "private_ip_mid_chain", "medium",
                f"Hop reports a private/reserved IP ({ip}) in the middle of the relay path — "
                "a legitimate public-internet relay chain would not contain this."
            ))

        if reasons:
            suspects.append({"hop_index": i, "hop": hop, "next_hop": next_hop, "reasons": reasons})

    if not suspects:
        return {"forged_hop_detected": False, "suspect_hop": None, "all_suspects": [], "evidence": []}

    primary = suspects[0]
    evidence = [
        make_evidence(etype, sev, f"[hop {primary['hop_index']}] {desc}", "header_analysis",
                       {"hop_index": primary["hop_index"], "hop": primary["hop"], "next_hop": primary["next_hop"]})
        for etype, sev, desc in primary["reasons"]
    ]
    for extra in suspects[1:]:
        evidence.append(make_evidence(
            "forged_relay_hop", "low",
            f"Additional inconsistency at hop position {extra['hop_index']} "
            f"(between '{extra['hop'].get('by')}' and '{extra['next_hop'].get('by')}')",
            "header_analysis", {"hop_index": extra["hop_index"]}))

    return {
        "forged_hop_detected": True,
        "suspect_hop": primary["hop"],
        "suspect_hop_index": primary["hop_index"],
        "all_suspects": suspects,
        "evidence": evidence,
    }


def estimate_forged_hop_timeframe(chain: list, suspect_hop_index: int) -> dict:
    """
    Bounds the time window during which a fabricated/middleman hop was most
    likely inserted, using the nearest VERIFIED (non-suspect) neighbors as
    anchors — since the forged hop's own claimed timestamp can be freely
    set by whoever inserted it and isn't trustworthy on its own.

    chain is newest-first (index 0 = closest to recipient). For suspect
    hop[i], the "upper" bound is hop[i-1] (more recent, still on the trusted
    side) and the "lower" bound is hop[i+1] (older, the next verifiable point).
    The insertion must have happened somewhere inside that window.
    """
    i = suspect_hop_index
    upper_hop = chain[i - 1] if i - 1 >= 0 else None   # more recent / closer to recipient
    lower_hop = chain[i + 1] if i + 1 < len(chain) else None  # older / closer to true origin

    upper_ts = upper_hop.get("timestamp") if upper_hop else None
    lower_ts = lower_hop.get("timestamp") if lower_hop else None
    claimed_ts = chain[i].get("timestamp")

    result = {
        "lower_bound": lower_ts,
        "lower_bound_hop": lower_hop.get("by") if lower_hop else None,
        "upper_bound": upper_ts,
        "upper_bound_hop": upper_hop.get("by") if upper_hop else None,
        "claimed_hop_timestamp": claimed_ts,
        "duration_seconds": None,
        "note": None,
    }

    if lower_ts and upper_ts:
        try:
            dt_lower, dt_upper = dtparser.parse(lower_ts), dtparser.parse(upper_ts)
            duration = (dt_upper - dt_lower).total_seconds()
            result["duration_seconds"] = duration
            result["note"] = (
                f"The fabricated hop was most likely inserted between {lower_ts} "
                f"(last verified timestamp, hop '{lower_hop.get('by')}') and {upper_ts} "
                f"(next verified timestamp, hop '{upper_hop.get('by')}') — a window of "
                f"{duration:.0f} seconds. Its own claimed timestamp ({claimed_ts}) is not "
                "trustworthy on its own since the inserter controls that value."
            )
        except (ValueError, OverflowError):
            result["note"] = "Could not parse neighboring timestamps to compute a reliable window."
    elif upper_ts:
        result["note"] = (
            f"No verified hop exists further down the chain to anchor a lower bound. "
            f"The fabricated hop was inserted sometime before {upper_ts} (hop '{upper_hop.get('by')}')."
        )
    elif lower_ts:
        result["note"] = (
            "This is the topmost hop in the chain, so there's no more-recent verified hop to bound "
            f"the window from above. It was inserted sometime after {lower_ts} (hop '{lower_hop.get('by')}')."
        )
    else:
        result["note"] = "Insufficient timestamp data on neighboring hops to estimate an insertion window."

    return result


def trace_full_path(chain: list) -> list:
    """
    Used when NO forged hop is detected — the chain is presumed trustworthy,
    so we can confidently reconstruct the email's full transmission path from
    true origin to final recipient. Returned oldest (origin) -> newest (delivery).
    """
    ordered = list(reversed(chain))
    return [
        {
            "sequence": idx + 1,
            "by": hop.get("by"),
            "from": hop.get("from"),
            "ip": hop.get("ip"),
            "timestamp": hop.get("timestamp"),
        }
        for idx, hop in enumerate(ordered)
    ]


def analyze_relay_chain(parsed_email: dict) -> dict:
    chain = _get(parsed_email, "received_chain", "relay_chain", default=[]) or []
    evidence = []

    if not chain:
        evidence.append(make_evidence(
            "relay_chain_missing", "low", "No Received chain available — cannot verify relay path",
            "header_analysis"))
        return {
            "hop_count": 0, "earliest_hop": None, "forged_hop": None,
            "full_path": None, "evidence": evidence,
        }

    earliest_hop = chain[-1]
    timestamps = [hop.get("timestamp") for hop in chain if hop.get("timestamp")]
    if len(timestamps) >= 2 and timestamps != sorted(timestamps, reverse=True):
        evidence.append(make_evidence(
            "relay_chain_out_of_order", "medium",
            "Received header timestamps are out of chronological order — possible forged/injected hop",
            "header_analysis"))

    forged = detect_forged_hop(chain)
    evidence.extend(forged["evidence"])

    full_path = None
    if forged["forged_hop_detected"]:
        # Attach the insertion-window estimate directly onto the forged_hop result.
        forged["timeframe"] = estimate_forged_hop_timeframe(chain, forged["suspect_hop_index"])
    else:
        # Chain looks clean end-to-end -> safe to reconstruct and trust the full path.
        full_path = trace_full_path(chain)

    return {
        "hop_count": len(chain),
        "earliest_hop": earliest_hop,
        "forged_hop": forged if forged["forged_hop_detected"] else None,
        "full_path": full_path,
        "evidence": evidence,
    }


def run(parsed_email: dict) -> dict:
    """Entry point: runs all header/protocol checks and merges structured evidence."""
    auth_evidence = check_auth_results(parsed_email)
    alignment_evidence = check_sender_alignment(parsed_email)
    relay = analyze_relay_chain(parsed_email)
    spf, dkim, dmarc = _auth_raw(parsed_email)

    all_evidence = auth_evidence + alignment_evidence + relay["evidence"]

    return {
        "relay_chain_summary": {
            "hop_count": relay["hop_count"],
            "earliest_hop": relay["earliest_hop"],
            "forged_hop": relay["forged_hop"],
            "full_path": relay["full_path"],
        },
        # raw SPF/DKIM/DMARC strings — needed verbatim for the
        # POST /api/analyses -> forensicEvidence.authentication payload
        "auth_raw": {"spf_result": spf, "dkim_result": dkim, "dmarc_result": dmarc},
        "evidence": all_evidence,
    }