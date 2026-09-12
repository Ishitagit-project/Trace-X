# 🚀 M2 Backend — Complete Step-by-Step Work Guide

---

## ✅ PHASE 1 — Email API (DONE)
- Built Express server + MongoDB Atlas connection
- Designed `Email.js` schema based on M3's exact output format
- Built `POST /api/emails`, `GET /api/emails`, `GET /api/emails/:id`
- Successfully uploaded all 50 real parsed emails from M3

---

## ✅ PHASE 2 — M3 Integration (DONE)
- Received `parsed_emails_50.json`, `clean_ioc_relationships.json`,
  `ioc_pivot_demo.json`, `graph_data.json` from Kajal (M3)
- Updated schema to match her exact JSON format
- Tested and confirmed all 50 emails saved successfully

---

## 🟢 COMPLETED MODULES & APIS

### 1. Email APIs (`/api/emails`)
- `POST /api/emails` — Ingest parsed email from M3 (50 sample emails already in DB).
- `GET /api/emails` — List all emails with pagination & sorting.
- `GET /api/emails/:id` — Retrieve single email with populated `threatAnalysisId` and `caseId`.
- `GET /api/emails/search/by-email-id?email_id=...` — Lookup by M3's `email_id`.

### 2. IOC APIs (`/api/iocs`)
- `POST /api/iocs` — Save or upsert an IOC with normalization & deduplication.
- `GET /api/iocs` — List/filter IOCs by `?type=domain&status=active&value=...&emailId=...&caseId=...`.
- `GET /api/iocs/:id` — Get one IOC with populated geolocation, related emails, and related cases.
- `PATCH /api/iocs/:id` — M4 enriches geolocation, ASN, ISP, confidence, status, and related links.
- `GET /api/iocs/:id/pivot` — M4 pivot view to find all emails sharing this indicator.
- `GET /api/iocs/:id/relationships` — Edges connected to this indicator.
- `GET /api/iocs/graph` — Full graph (nodes & edges) for M6 visualization.

### 3. Analysis APIs (`/api/analyses`)
- `POST /api/analyses` — Save M5's AI threat classification and M1's forensic evidence (auto-links to Email).
- `GET /api/analyses` — List all analyses with filters (`?classification=phishing&minScore=70`).
- `GET /api/analyses/:emailId` — Get analysis result for an email (supports MongoDB `_id` or M3 `email_id`).
- `PATCH /api/analyses/:emailId` — Update evidence or scores.

### 4. Case Management APIs (`/api/cases`)
- `POST /api/cases` — Create a security case (validates referenced emails/IOCs/analyses and updates references).
- `GET /api/cases` — List cases with filters (`?status=open&priority=high&classification=phishing`).
- `GET /api/cases/:id` — Full Case detail page for M6 (fully populates related emails, IOCs, and analyses).
- `PATCH /api/cases/:id` — Change status, priority, or close case (automatically tracks `closedAt`).

### 5. Dashboard Statistics API (`/api/dashboard-stats`)
- `GET /api/dashboard-stats` — Returns overall metrics for M6 cards and summary charts:
  ```json
  {
    "success": true,
    "data": {
      "totalEmails": 50,
      "totalAnalyzed": 0,
      "totalThreats": 0,
      "totalSafeEmails": 0,
      "totalIOCs": 0,
      "totalCases": 0,
      "openCases": 0,
      "investigatingCases": 0,
      "closedCases": 0,
      "highRiskCases": 0
    }
  }
  ```

---

## 🛡️ Data Integrity, Relationships & Indexes

- **Cross-Referenced Schema Architecture:**
  - `Email` references `Analysis` (`threatAnalysisId`) and `Case` (`caseId`).
  - `IOC` references `Email` (`sourceEmailId`, `investigation.relatedEmails`) and `Case` (`sourceCaseId`, `investigation.relatedCases`).
  - `Case` references `Email` (`emailIds`), `IOC` (`iocIds`), and `Analysis` (`analysisIds`).
  - `Analysis` references `Email` (`emailId`).

- **Consistent API Response Format:**
  - Success: `{ "success": true, "data": { ... } }`
  - Error: `{ "success": false, "message": "..." }`

- **Optimized MongoDB Indexes:**
  - `Email`: `sender`, `receiver`, `domains`, `ips`, `createdAt: -1`
  - `IOC`: `{ type: 1, normalizedValue: 1 }` (unique), `sourceEmailId: 1`, `sourceCaseId: 1`, `occurrenceCount: -1`
  - `Analysis`: `{ emailId: 1 }` (unique), `classification: 1`, `threatScore: -1`
  - `Case`: `status: 1`, `priority: 1`, `createdAt: -1`, `threatScore: -1`

---

## 🟣 PHASE 5: Cloud Deployment (FINAL STEP)

When ready to connect with the full team over the internet:
1. Push code to GitHub repository.
2. Link repo to **Render** or **Railway**.
3. Set environment variables: `PORT=5000` and `MONGODB_URI`.
4. Provide the public URL (e.g., `https://sih-backend.onrender.com`) to M1, M3, M4, M5, and M6!
