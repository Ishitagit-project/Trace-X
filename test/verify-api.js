const mongoose = require("mongoose");
const app = require("../src/app");
const Email = require("../src/models/Email");
const Analysis = require("../src/models/Analysis");
const Case = require("../src/models/Case");
const IOC = require("../src/models/IOC");
require("dotenv").config();

async function runTests() {
  console.log("🧪 Starting End-to-End API verification...");

  await mongoose.connect(process.env.MONGODB_URI);
  console.log(" Connected to MongoDB");

  const server = app.listen(5001);
  const BASE = "http://localhost:5001";

  try {
    // 1. Get an existing email to attach to
    const sampleEmail = await Email.findOne();
    if (!sampleEmail) {
      throw new Error("No sample emails found in database. Run upload-emails.js first.");
    }
    console.log(` Found existing email: ${sampleEmail._id} (${sampleEmail.email_id})`);

    // 2. Test POST /api/analyses
    console.log("\n Testing POST /api/analyses...");
    // Clear old test analysis if present
    await Analysis.deleteOne({ emailId: sampleEmail._id });

    const postAnalysisRes = await fetch(`${BASE}/api/analyses`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        emailId: sampleEmail._id,
        classification: "phishing",
        threatScore: 88,
        confidence: 0.95,
        summary: "Suspicious login prompt with spoofed sender domain.",
        forensicEvidence: { spf: "fail", dkim: "fail", dmarc: "fail" },
        aiEvidence: { urgencyScore: 0.9, detectedBrand: "Microsoft" },
        recommendations: ["Block sender domain", "Quarantine message"],
        modelVersion: "v1.2",
      }),
    });
    const postAnalysisData = await postAnalysisRes.json();
    console.log("POST /api/analyses response:", postAnalysisRes.status, postAnalysisData.success);
    if (!postAnalysisRes.ok) throw new Error(JSON.stringify(postAnalysisData));

    // 3. Test GET /api/analyses/:emailId (test with both MongoDB _id and email_id string)
    console.log("\n Testing GET /api/analyses/:emailId (using MongoDB _id)...");
    const getAnalysisRes1 = await fetch(`${BASE}/api/analyses/${sampleEmail._id}`);
    const getAnalysisData1 = await getAnalysisRes1.json();
    console.log("GET /api/analyses/:id result:", getAnalysisRes1.status, getAnalysisData1.data?.threatScore);

    console.log("\n Testing GET /api/analyses/:emailId (using M3 email_id string)...");
    const getAnalysisRes2 = await fetch(`${BASE}/api/analyses/${sampleEmail.email_id}`);
    const getAnalysisData2 = await getAnalysisRes2.json();
    console.log("GET /api/analyses/:email_id result:", getAnalysisRes2.status, getAnalysisData2.data?.classification);

    // 4. Test IOC and Geolocation update (PATCH /api/iocs/:id)
    console.log("\n Testing IOC & Geolocation PATCH /api/iocs/:id...");
    const sampleIoc = await IOC.create({
      value: "185.220.101.5",
      normalizedValue: "185.220.101.5",
      type: "ip",
      sourceEmailId: sampleEmail._id,
    });

    const patchIocRes = await fetch(`${BASE}/api/iocs/${sampleIoc._id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        geolocation: {
          country: "Russia",
          city: "Moscow",
          region: "Central",
          isp: "DarkHost Networks",
          asn: "AS49505",
          latitude: 55.7558,
          longitude: 37.6173,
        },
        investigation: {
          confidence: 0.92,
        },
        status: "blocked",
      }),
    });
    const patchIocData = await patchIocRes.json();
    console.log("PATCH /api/iocs/:id result:", patchIocRes.status, patchIocData.data?.geolocation?.city);

    // 5. Test POST /api/cases
    console.log("\n Testing POST /api/cases...");
    const postCaseRes = await fetch(`${BASE}/api/cases`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: "CASE-001: Suspicious Phishing Campaign",
        description: "Email contains a suspicious login link and possible spoofing.",
        status: "open",
        priority: "high",
        classification: "phishing",
        threatScore: 88,
        emailIds: [sampleEmail._id],
        iocIds: [sampleIoc._id],
        analysisIds: [postAnalysisData.data._id],
        evidence: { spfFailed: true, maliciousUrl: true },
        aiSummary: "High confidence phishing campaign targeting company credentials.",
        recommendations: ["Change status", "Block domain", "Close case"],
      }),
    });
    const postCaseData = await postCaseRes.json();
    console.log("POST /api/cases result:", postCaseRes.status, postCaseData.data?._id);
    const caseId = postCaseData.data._id;

    // 6. Test GET /api/cases/:id with populate
    console.log("\n Testing GET /api/cases/:id with populate...");
    const getCaseRes = await fetch(`${BASE}/api/cases/${caseId}`);
    const getCaseData = await getCaseRes.json();
    console.log("GET /api/cases/:id result:", getCaseRes.status);
    console.log(" - Populated Email Subject:", getCaseData.data.emailIds[0]?.subject);
    console.log(" - Populated IOC Value:", getCaseData.data.iocIds[0]?.value);
    console.log(" - Populated Analysis Threat Score:", getCaseData.data.analysisIds[0]?.threatScore);

    // 7. Test PATCH /api/cases/:id (Status -> closed)
    console.log("\n Testing PATCH /api/cases/:id (close case)...");
    const patchCaseRes = await fetch(`${BASE}/api/cases/${caseId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: "closed",
        priority: "medium",
      }),
    });
    const patchCaseData = await patchCaseRes.json();
    console.log("PATCH /api/cases/:id result:", patchCaseRes.status, "closedAt:", patchCaseData.data.closedAt);

    // 8. Test GET /api/dashboard-stats
    console.log("\n Testing GET /api/dashboard-stats...");
    const getStatsRes = await fetch(`${BASE}/api/dashboard-stats`);
    const getStatsData = await getStatsRes.json();
    console.log("GET /api/dashboard-stats result:", getStatsRes.status);
    console.log("Dashboard Stats Data:", JSON.stringify(getStatsData.data, null, 2));

    console.log("\n ALL TESTS PASSED SUCCESSFULLY! ✨");
  } finally {
    server.close();
    await mongoose.connection.close();
  }
}

runTests().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
