"""
config.py
---------
Central configuration for Member 1 - Cybersecurity Evidence Analysis service.

All values are read from environment variables so nothing sensitive
(API keys, DB URIs) is hard-coded in source. Ask Member 2 for the exact
Mongo collection names they're using so these stay in sync.
"""

import os

# ---- MongoDB (shared with Member 2) ----
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "email_threat_platform")

# Collection Member 2 writes parsed .eml data + raw IOCs into
COLLECTION_PARSED_EMAILS = os.getenv("COLLECTION_PARSED_EMAILS", "parsed_emails")

# Collection YOU (Member 1) write evidence/analysis results into.
# Member 4 (IOC relationships) and Member 5 (AI classification/report) read from this.
COLLECTION_EVIDENCE = os.getenv("COLLECTION_EVIDENCE", "evidence_reports")

# ---- Third-party intelligence APIs (all optional - code degrades gracefully) ----
# IP reputation / abuse scoring: https://www.abuseipdb.com/api
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# IP geolocation: https://ip-api.com (free tier, no key needed) is used by default.
# Swap in MaxMind GeoLite2 / ipinfo.io later if you need offline / higher volume lookups.
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")  # optional, only if you switch to ipinfo.io

# VirusTotal for URL / domain / attachment hash reputation
VT_API_KEY = os.getenv("VT_API_KEY", "")

# ---- Polling ----
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "10"))

# ---- Team backend REST API (replaces direct MongoDB access in production) ----
# See M1_API_HANDOFF.md for the full contract.
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:5000")
API_KEY = os.getenv("API_KEY", "")

# How the key gets attached to requests. Confirm with M2 which one their
# backend actually expects — "bearer" sends `Authorization: Bearer <key>`,
# "x-api-key" sends a raw `x-api-key: <key>` header. Change the default once known.
API_AUTH_STYLE = os.getenv("API_AUTH_STYLE", "bearer")  # "bearer" | "x-api-key"