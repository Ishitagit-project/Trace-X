"""
main.py
-------
Member 1's pipeline entry point.

Flow (production, via the team REST API — see M1_API_HANDOFF.md):
  GET /api/emails/:id  -> (YOU ARE HERE) analyze the cybersecurity evidence
        -> POST /api/analyses        (forensic findings + geolocation)
        -> PATCH /api/iocs/:id       (enrich each extracted IP with geolocation)

Flow (local/offline dev — still supported, e.g. before the API is live):
  MongoDB (EvidenceDB) is used the same way as before.

Run modes:
  python main.py --api EMAIL_ID      -> fetch, analyze, and submit ONE email via the real API
  python main.py --sample            -> print the exact sample JSON, no network needed
  python main.py --demo              -> run the full pipeline on a built-in fake phishing email
  python main.py --demo-clean        -> run on a built-in clean (non-MITM) sample chain
  python main.py --map               -> plot both demo emails on a map
  python main.py --once / (no flag)  -> local MongoDB mode: process pending / poll continuously
"""

import argparse
import time
import traceback
from datetime import datetime, timezone

import config
import header_analysis
import ip_intel
import url_domain
import scoring
import map_generator
import api_client
import adapters
from db import EvidenceDB


def build_origin_trace(header_result: dict, ip_result: dict) -> dict:
    """
    Answers the "find the hop, then either bound the MITM insertion time,
    or trace the full path + geolocate the origin device" requirement.

    - If a forged/MITM hop was found: report which hop, the time window it
      was likely inserted in, AND still geolocate that hop's IP (labeled as
      unverified) so it can be plotted on the map for investigators.
    - If the chain is clean: report the full hop-by-hop path from true origin
      to final delivery, plus the origin device's confirmed IP and geolocation.
    """
    relay = header_result["relay_chain_summary"]
    forged = relay.get("forged_hop")

    if forged:
        suspect_ip = (forged.get("suspect_hop") or {}).get("ip")
        suspect_geo = None
        if suspect_ip:
            suspect_geo = ip_intel.geolocate_ip(suspect_ip)
            if suspect_geo.get("error"):
                suspect_geo = None

        return {
            "mitm_detected": True,
            "suspect_hop_index": forged["suspect_hop_index"],
            "suspect_hop": forged["suspect_hop"],
            "insertion_timeframe": forged["timeframe"],
            "full_path": None,
            "origin_ip": None,
            "origin_geolocation": None,
            "suspect_hop_geolocation": suspect_geo,  # unverified, but still plottable on the map
            "note": "Chain of custody breaks at the hop above — the true origin below this point "
                    "cannot be trusted until the fabricated hop is confirmed and excluded. The "
                    "location shown is of the suspect hop itself, not a confirmed origin device.",
        }

    earliest_hop = relay.get("earliest_hop") or {}
    origin_ip = earliest_hop.get("ip")
    origin_geo = None
    if origin_ip and origin_ip in ip_result.get("ip_reports", {}):
        origin_geo = ip_result["ip_reports"][origin_ip].get("geolocation")

    return {
        "mitm_detected": False,
        "suspect_hop_index": None,
        "suspect_hop": None,
        "insertion_timeframe": None,
        "full_path": relay.get("full_path"),
        "origin_ip": origin_ip,
        "origin_geolocation": origin_geo,
        "suspect_hop_geolocation": None,
        "note": "No chain-of-custody break detected — full path reconstructed and origin device located.",
    }


def analyze_one(parsed_email: dict) -> dict:
    """Runs the full evidence pipeline on a single parsed email doc and
    returns a report matching the agreed schema (see README 'Schema contract')."""
    header_result = header_analysis.run(parsed_email)

    if not parsed_email.get("candidate_ips"):
        earliest = (header_result["relay_chain_summary"].get("earliest_hop") or {})
        if earliest.get("ip"):
            parsed_email["candidate_ips"] = [earliest["ip"]]

    ip_result = ip_intel.run(parsed_email)
    url_result = url_domain.run(parsed_email)
    combined = scoring.combine(header_result, ip_result, url_result)
    origin_trace = build_origin_trace(header_result, ip_result)

    report = {
        "email_id": parsed_email.get("_id") or parsed_email.get("email_id"),
        "subject": parsed_email.get("subject"),
        "from": parsed_email.get("from") or parsed_email.get("from_address"),
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "based_on_parsed_data": True,  # confirms: works on Member 3's parsed data, not independent

        # --- fields M2 asked about directly ---
        "classification": combined["classification"],        # phishing | spam | bec | malware | safe | suspicious
        "threat_score": combined["threat_score"],             # 0-100
        "confidence": combined["confidence"],                 # low | medium | high (dashboard label)
        "confidence_score": combined["confidence_score"],     # 0-1 float (for the REST API payload)
        "flag_status": combined["flag_status"],               # Detected | Suspicious | Flagged (Evidence tab)
        "evidence": combined["evidence"],                     # structured JSON array (not plain strings)

        # --- origin traceability: hop tracking, MITM timeframe OR full path + geolocation ---
        "origin_trace": origin_trace,

        # --- full nested detail, for drill-down / debugging / Member 4's graph correlation ---
        "details": {
            "header_analysis": header_result,
            "ip_analysis": ip_result,
            "url_analysis": url_result,
        },
    }

    # narrative fields for the POST /api/analyses payload (summary, recommendations)
    report["summary"] = scoring.generate_summary(report)
    report["recommendations"] = scoring.generate_recommendations(report)

    return report


def get_evidence_reports(db: EvidenceDB, limit=200) -> list:
    return list(db.evidence.find().sort("analyzed_at", -1).limit(limit))


def process_pending(db: EvidenceDB, limit=20):
    pending = db.get_unanalyzed_emails(limit=limit)
    print(f"[Member1] Found {len(pending)} email(s) pending evidence analysis")

    for parsed_email in pending:
        email_id = parsed_email.get("_id")
        try:
            report = analyze_one(parsed_email)
            db.save_evidence_report(report)
            db.mark_email_status(email_id, "evidence_analyzed")
            print(f"[Member1] Analyzed {email_id} -> {report['classification']} "
                  f"score={report['threat_score']} flag={report['flag_status']}")
        except Exception:
            db.mark_email_status(email_id, "evidence_analysis_failed")
            print(f"[Member1] FAILED analyzing {email_id}")
            traceback.print_exc()


DEMO_EMAIL = {
    "_id": "demo-001",
    "subject": "URGENT: Invoice Payment Overdue - Action Required",
    "from": "billing@paypal-secure-verify.xyz",
    "reply_to": "payments@paypal-secure-verify.top",
    "return_path": "bounce@some-other-domain.ru",
    "spf_result": "fail",
    "dkim_result": "none",
    "dmarc_result": "fail",
    "received_chain": [
        {"by": "mx1.victim-org.com", "from": "mail.trusted-partner.com", "ip": "45.33.32.156", "timestamp": "2026-09-11T10:05:00Z"},
        {"by": "relay.somewhere-else.net", "from": "attacker-host.evil.ru", "ip": "203.0.113.99", "timestamp": "2026-09-11T10:04:58Z"},
    ],
    "urls": [
        "http://paypal-secure-verify.xyz/login",
        "http://bit.ly/3xAmpLe",
        "http://203.0.113.77/wp-invoice.pdf.exe",
    ],
}


CLEAN_DEMO_EMAIL = {
    "_id": "demo-002",
    "subject": "Q3 report attached",
    "from": "alice@partner-corp.com",
    "reply_to": "alice@partner-corp.com",
    "return_path": "alice@partner-corp.com",
    "spf_result": "pass",
    "dkim_result": "pass",
    "dmarc_result": "pass",
    # newest-first: mx1 (recipient's own server) -> mx-out (partner's outbound relay) -> origin device
    "received_chain": [
        {"by": "mx1.victim-org.com", "from": "mx-out.partner-corp.com", "ip": "104.16.132.229", "timestamp": "2026-09-12T09:00:10Z"},
        {"by": "mx-out.partner-corp.com", "from": "desktop-alice.partner-corp.com", "ip": "93.184.216.34", "timestamp": "2026-09-12T09:00:02Z"},
    ],
    "urls": [],
}


def run_via_api(email_id: str):
    """
    Full production round-trip against the real REST API:
      1. GET /api/emails/:id
      2. run the analysis pipeline
      3. POST /api/analyses with the findings
      4. PATCH /api/iocs/:id for each extracted IP we have an IOC record for
    """
    print(f"[Member1] Fetching email {email_id} via API...")
    raw = api_client.get_email(email_id)
    parsed_email = adapters.adapt_email_response(raw)

    report = analyze_one(parsed_email)
    print(f"[Member1] Analyzed -> {report['classification']} "
          f"score={report['threat_score']} flag={report['flag_status']}")

    analysis_payload = adapters.build_analysis_payload(report)
    api_client.submit_analysis(analysis_payload)
    print("[Member1] POST /api/analyses submitted.")

    ioc_map = parsed_email.get("_ioc_map", {})
    trace = report["origin_trace"]
    ips_to_patch = []
    if trace["mitm_detected"]:
        ip = (trace.get("suspect_hop") or {}).get("ip")
        geo = trace.get("suspect_hop_geolocation")
        if ip:
            ips_to_patch.append((ip, geo))
    else:
        ip = trace.get("origin_ip")
        geo = trace.get("origin_geolocation")
        if ip:
            ips_to_patch.append((ip, geo))

    for ip, geo in ips_to_patch:
        ioc_id = ioc_map.get(ip)
        if not ioc_id:
            fetched_ioc = api_client.get_ioc("ip", ip)
            if fetched_ioc:
                ioc_id = fetched_ioc.get("_id") or fetched_ioc.get("id")

        if not ioc_id:
            print(f"[Member1] No IOC record found for IP {ip} — skipping PATCH.")
            continue
        payload = adapters.build_ioc_payload(geo, report["flag_status"])
        api_client.update_ioc_geolocation(ioc_id, payload)
        print(f"[Member1] PATCH /api/iocs/{ioc_id} updated with geolocation for {ip}.")


def main():
    parser = argparse.ArgumentParser(description="Member 1 - Cybersecurity Evidence Analysis")
    parser.add_argument("--api", metavar="EMAIL_ID", help="fetch/analyze/submit ONE email via the real REST API")
    parser.add_argument("--once", action="store_true", help="process pending emails once then exit (local MongoDB mode)")
    parser.add_argument("--demo", action="store_true", help="run against a built-in sample email, no DB/API needed")
    parser.add_argument("--sample", action="store_true", help="print the sample JSON schema to hand to M2")
    parser.add_argument("--demo-clean", action="store_true", help="run against a clean (non-MITM) sample chain")
    parser.add_argument("--map", action="store_true", help="analyze both demo emails and plot them on a map -> email_origin_map.html")
    parser.add_argument("--map-db", action="store_true", help="plot all stored evidence_reports from MongoDB on a map -> email_origin_map.html")
    args = parser.parse_args()

    if args.api:
        run_via_api(args.api)
        return

    if args.map_db:
        db = EvidenceDB()
        try:
            reports = get_evidence_reports(db)
            out_path = map_generator.generate_map(reports)
            print(f"[Member1] Plotted {len(reports)} email(s) -> {out_path}")
        finally:
            db.close()
        return

    if args.map:
        report_mitm = analyze_one(dict(DEMO_EMAIL))
        report_clean = analyze_one(dict(CLEAN_DEMO_EMAIL))
        out_path = map_generator.generate_map([report_mitm, report_clean])
        print(f"[Member1] Map written to {out_path} — open it in a browser.")
        return

    if args.demo_clean:
        import json
        report = analyze_one(dict(CLEAN_DEMO_EMAIL))
        print(json.dumps(report, indent=2, default=str))
        return

    if args.demo or args.sample:
        import json
        report = analyze_one(dict(DEMO_EMAIL))
        print(json.dumps(report, indent=2, default=str))
        return

    db = EvidenceDB()
    try:
        if args.once:
            process_pending(db)
        else:
            print(f"[Member1] Polling every {config.POLL_INTERVAL_SECONDS}s. Ctrl+C to stop.")
            while True:
                process_pending(db)
                time.sleep(config.POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[Member1] Stopped.")
    finally:
        db.close()


if __name__ == "__main__":
    main()