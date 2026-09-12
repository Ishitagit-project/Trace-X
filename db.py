"""
db.py
-----
Thin MongoDB access layer. Reads the parsed-email documents that
Member 2 has already stored, and writes your evidence reports back
so Member 4 / Member 5 can pick them up.

Coordinate the exact schema with Member 2 & Member 3 — this assumes a
reasonably generic shape but you WILL need to tweak field names to match
what their parser actually outputs.
"""

from datetime import datetime, timezone
from pymongo import MongoClient, ReturnDocument

import config


class EvidenceDB:
    def __init__(self):
        self.client = MongoClient(config.MONGO_URI)
        self.db = self.client[config.MONGO_DB_NAME]
        self.parsed_emails = self.db[config.COLLECTION_PARSED_EMAILS]
        self.evidence = self.db[config.COLLECTION_EVIDENCE]

    def get_unanalyzed_emails(self, limit=20):
        """
        Fetch parsed emails that don't yet have an evidence report.
        Assumes Member 2's documents have a unique '_id' or 'email_id' field,
        and (ideally) a status flag like {"analysis_status": "pending"}.
        Adjust the filter to match their actual schema.
        """
        query = {
            "$or": [
                {"analysis_status": {"$exists": False}},
                {"analysis_status": "pending"},
            ]
        }
        return list(self.parsed_emails.find(query).limit(limit))

    def mark_email_status(self, email_id, status):
        self.parsed_emails.update_one(
            {"_id": email_id},
            {"$set": {"analysis_status": status,
                      "analysis_updated_at": datetime.now(timezone.utc)}}
        )

    def save_evidence_report(self, report: dict):
        """
        Upsert the evidence report keyed on the source email id, so
        re-running analysis on the same email doesn't create duplicates.
        """
        report["created_at"] = report.get("created_at", datetime.now(timezone.utc))
        report["updated_at"] = datetime.now(timezone.utc)

        return self.evidence.find_one_and_update(
            {"email_id": report["email_id"]},
            {"$set": report},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )

    def close(self):
        self.client.close()