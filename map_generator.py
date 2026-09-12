"""
map_generator.py
-----------------
Plots the geolocation extracted during origin tracing onto an actual
interactive map (Folium/Leaflet) — regardless of whether the email turned
out to be safe or malicious. Every analyzed email gets a marker; the pin
color + popup text always states plainly whether that location is tied to
a suspicious/flagged email or a safe one.

This is meant to feed the dashboard (Member 6) or stand alone as a
downloadable HTML report for an investigator.

Marker color legend:
  green  -> safe / low-risk email, location shown for reference
  orange -> suspicious, or MITM case where the origin is unverifiable
  red    -> flagged / high-risk (phishing, bec, malware) confirmed origin
"""

import folium
from folium.plugins import MarkerCluster

STATUS_COLORS = {
    "safe": "green",
    "suspicious": "orange",
    "unverifiable": "orange",
    "flagged": "red",
}


def _status_for_report(report: dict) -> str:
    """Maps a report's flag_status/classification to a marker status bucket."""
    if report.get("origin_trace", {}).get("mitm_detected"):
        return "unverifiable"  # can't confirm true origin once a hop is forged
    flag = report.get("flag_status", "Detected")
    if flag == "Flagged":
        return "flagged"
    if flag == "Suspicious":
        return "suspicious"
    return "safe"


def _point_for_report(report: dict) -> dict:
    """
    Extracts a single plottable point (lat/lon + metadata) from one evidence
    report, whichever branch of origin_trace produced the location:
      - clean chain -> origin_geolocation from the confirmed origin IP
      - MITM case   -> geolocation of the suspect (fabricated) hop's IP, if resolvable,
                       clearly labeled as unverified since the chain of custody broke there
    """
    trace = report.get("origin_trace", {})
    status = _status_for_report(report)

    if trace.get("mitm_detected"):
        suspect_hop = trace.get("suspect_hop") or {}
        ip = suspect_hop.get("ip")
        geo = trace.get("suspect_hop_geolocation")
        label_prefix = "Unverified (MITM/forged hop) — location of the suspect hop"
    else:
        ip = trace.get("origin_ip")
        geo = trace.get("origin_geolocation")
        label_prefix = "Confirmed email origin device"

    if not geo or geo.get("lat") is None or geo.get("lon") is None:
        return None  # nothing plottable for this email

    return {
        "email_id": report.get("email_id"),
        "subject": report.get("subject"),
        "from": report.get("from"),
        "ip": ip,
        "lat": geo["lat"],
        "lon": geo["lon"],
        "city": geo.get("city"),
        "region": geo.get("region"),
        "country": geo.get("country"),
        "isp": geo.get("isp") or geo.get("org"),
        "status": status,
        "classification": report.get("classification"),
        "threat_score": report.get("threat_score"),
        "flag_status": report.get("flag_status"),
        "label_prefix": label_prefix,
    }


def _popup_html(point: dict) -> str:
    location_str = ", ".join(filter(None, [point.get("city"), point.get("region"), point.get("country")])) or "Unknown location"
    ip = point.get("ip") or "N/A"
    lat = point.get("lat")
    lon = point.get("lon")
    isp = point.get("isp") or "N/A"
    subject = str(point.get("subject") or "N/A").replace("'", "\\'").replace('"', '&quot;')
    sender = str(point.get("from") or "N/A").replace("'", "\\'").replace('"', '&quot;')
    status_upper = point['status'].upper()
    status_color = '#ff0055' if point['status'] == 'flagged' else ('#ffb703' if point['status'] in ('suspicious', 'unverifiable') else '#00e676')

    copy_payload = f"Device IP: {ip}\\nCoordinates: {lat}, {lon}\\nLocation: {location_str}\\nISP: {isp}\\nSubject: {subject}\\nSender: {sender}\\nStatus: {status_upper}"

    return f"""
    <div style="font-family: monospace; font-size: 12px; min-width: 250px; color: #e2f1f8; background: #0a0f18; padding: 12px; border-radius: 8px; border: 1px solid #00f2fe; box-shadow: 0 0 15px rgba(0, 242, 254, 0.3);">
      <b style="color: #00f2fe; text-transform: uppercase;">{point['label_prefix']}</b><br>
      <div style="margin-top: 6px;"><b>Status:</b> <span style="color: {status_color}; font-weight: bold;">{status_upper}</span></div>
      <div><b>Classification:</b> {point.get('classification', 'N/A')} (Score: {point.get('threat_score', 'N/A')})</div>
      <hr style="margin: 8px 0; border-color: rgba(0, 242, 254, 0.25);">
      <div><b>Subject:</b> {subject}</div>
      <div><b>From:</b> {sender}</div>
      <div><b>Device IP:</b> <span style="color: #00f2fe;">{ip}</span></div>
      <div><b>Location:</b> {location_str}</div>
      <div><b>ISP / Infra:</b> {isp}</div>
      <div><b>Coordinates:</b> {lat}, {lon}</div>
      <div style="margin-top: 10px;">
        <button onclick="
          navigator.clipboard.writeText('{copy_payload}');
          alert('Exact Device Address & Location copied to clipboard!');
        " style="width: 100%; background: linear-gradient(135deg, #00f2fe, #0088ff); color: #000; border: none; padding: 8px; border-radius: 4px; font-weight: bold; cursor: pointer; font-family: monospace; text-transform: uppercase;">
          📋 Copy Exact Device Address
        </button>
      </div>
    </div>
    """


def generate_map(reports: list, output_path: str = "email_origin_map.html", cluster: bool = True) -> str:
    """
    Builds an interactive HTML map from a list of evidence reports (the same
    dicts produced by main.analyze_one). Plots every email that has a
    resolvable location, safe or not, colored + labeled per STATUS_COLORS.

    Returns the output file path. Pass a single-item list for one email.
    """
    points = [p for p in (_point_for_report(r) for r in reports) if p]

    if not points:
        m = folium.Map(location=[20, 0], zoom_start=2)
        folium.map.Marker(
            [20, 0],
            icon=folium.DivIcon(html='<div style="font-size:13px; color:#fff; font-family:monospace;">No geolocation data available for these emails.</div>')
        ).add_to(m)
        m.save(output_path)
        return output_path

    avg_lat = sum(p["lat"] for p in points) / len(points)
    avg_lon = sum(p["lon"] for p in points) / len(points)
    m = folium.Map(location=[avg_lat, avg_lon], zoom_start=3, tiles="OpenStreetMap")

    target = MarkerCluster().add_to(m) if cluster and len(points) > 1 else m

    for p in points:
        folium.Marker(
            location=[p["lat"], p["lon"]],
            popup=folium.Popup(_popup_html(p), max_width=340),
            tooltip=f"{p['status'].upper()} — {p.get('city') or p.get('country') or p['ip']}",
            icon=folium.Icon(color=STATUS_COLORS.get(p["status"], "blue"), icon="envelope", prefix="fa"),
        ).add_to(target)

    # Dark Theme & Laser Sweep Animation Overlay Injection
    cyber_style_html = """
    <style>
      .leaflet-tile-pane { filter: invert(100%) hue-rotate(190deg) brightness(85%) contrast(120%); }
      .laser-scan-line {
        position: fixed; top: 0; left: 0; width: 100%; height: 3px;
        background: linear-gradient(90deg, transparent, #00f2fe, transparent);
        box-shadow: 0 0 20px #00f2fe, 0 0 10px #00f2fe; z-index: 99999;
        pointer-events: none; animation: laserSweep 3s ease-in-out infinite alternate;
      }
      @keyframes laserSweep {
        0% { top: 0%; }
        100% { top: 100%; }
      }
    </style>
    <div class="laser-scan-line"></div>
    <div style="position: fixed; bottom: 24px; left: 24px; z-index: 9999;
                background: rgba(10, 15, 24, 0.9); padding: 12px 16px; border: 1px solid #00f2fe;
                border-radius: 8px; font-family: monospace; font-size: 13px; color:#e2f1f8; box-shadow: 0 0 20px rgba(0,242,254,0.3);">
      <b style="color:#00f2fe; text-transform:uppercase;">Trace-X Email Origin Radar</b><br>
      <span style="color:#00e676;">&#9679;</span> Safe &nbsp;
      <span style="color:#ffb703;">&#9679;</span> Suspicious / Unverifiable (MITM) &nbsp;
      <span style="color:#ff0055;">&#9679;</span> Flagged Malicious
    </div>
    """
    m.get_root().html.add_child(folium.Element(cyber_style_html))

    m.save(output_path)
    return output_path