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
    return f"""
    <div style="font-family: sans-serif; font-size: 13px; min-width: 220px;">
      <b>{point['label_prefix']}</b><br>
      <b>Status:</b> {point['status'].upper()} &mdash; {point.get('flag_status', 'N/A')}<br>
      <b>Classification:</b> {point.get('classification', 'N/A')} (score {point.get('threat_score', 'N/A')})<br>
      <hr style="margin:4px 0;">
      <b>Subject:</b> {point.get('subject') or 'N/A'}<br>
      <b>From:</b> {point.get('from') or 'N/A'}<br>
      <b>IP:</b> {point.get('ip') or 'N/A'}<br>
      <b>Location:</b> {location_str}<br>
      <b>ISP/Org:</b> {point.get('isp') or 'N/A'}
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
            icon=folium.DivIcon(html='<div style="font-size:13px;">No geolocation data available for these emails.</div>')
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
            popup=folium.Popup(_popup_html(p), max_width=320),
            tooltip=f"{p['status'].upper()} — {p.get('city') or p.get('country') or p['ip']}",
            icon=folium.Icon(color=STATUS_COLORS.get(p["status"], "blue"), icon="envelope", prefix="fa"),
        ).add_to(target)

    # simple legend, always visible regardless of verdict mix
    legend_html = """
    <div style="position: fixed; bottom: 30px; left: 30px; z-index: 9999;
                background: white; padding: 10px 14px; border: 1px solid #999;
                border-radius: 6px; font-family: sans-serif; font-size: 13px; color:#222;">
      <b>Email origin status</b><br>
      <span style="color:green;">&#9679;</span> Safe &nbsp;
      <span style="color:orange;">&#9679;</span> Suspicious / unverifiable (MITM) &nbsp;
      <span style="color:red;">&#9679;</span> Flagged
    </div>
    """
    m.get_root().html.add_child(folium.Element(legend_html))

    m.save(output_path)
    return output_path