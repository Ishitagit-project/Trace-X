"""
api_client.py
-------------
Thin wrapper around the three endpoints in M1_API_HANDOFF.md. This REPLACES
db.py/EvidenceDB for production use — you now pull email data over HTTP
instead of reading MongoDB directly, and push results back the same way.

Auth: set API_KEY (and API_AUTH_STYLE if needed) via environment variables —
see config.py. Never hard-code the key here.
"""

import requests
import config


def _auth_headers() -> dict:
    if not config.API_KEY:
        return {}
    if config.API_AUTH_STYLE == "x-api-key":
        return {"x-api-key": config.API_KEY}
    return {"Authorization": f"Bearer {config.API_KEY}"}  # default: bearer


def _url(path: str) -> str:
    return config.API_BASE_URL.rstrip("/") + path


def get_email(email_id: str) -> dict:
    """GET /api/emails/:id — fetch the full email + security_headers."""
    resp = requests.get(_url(f"/api/emails/{email_id}"), headers=_auth_headers(), timeout=10)
    resp.raise_for_status()
    return resp.json()


def submit_analysis(payload: dict) -> dict:
    """POST /api/analyses — submit your forensic analysis + geolocation findings."""
    resp = requests.post(
        _url("/api/analyses"),
        json=payload,
        headers={**_auth_headers(), "Content-Type": "application/json"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json() if resp.content else {}


def update_ioc_geolocation(ioc_id: str, payload: dict) -> dict:
    """PATCH /api/iocs/:id — enrich an extracted IP IOC with geolocation."""
    resp = requests.patch(
        _url(f"/api/iocs/{ioc_id}"),
        json=payload,
        headers={**_auth_headers(), "Content-Type": "application/json"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json() if resp.content else {}