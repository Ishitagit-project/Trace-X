/**
 * Upload IOCs and Relationships from M3's sample files into the database.
 *
 * Run this ONCE after the server is started:
 *   node upload-iocs.js
 *
 * Uses:
 *   - m3_samples/clean_ioc_relationships.json  → populates /api/iocs
 *   - m3_samples/graph_data.json               → populates graph edges
 */

const fs = require("fs");
const BASE_URL = "http://localhost:5000";

// ── Helper: POST to an endpoint and log result ────────────────────────
async function post(endpoint, body) {
  const response = await fetch(`${BASE_URL}${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: response.status, data: await response.json() };
}

// ── Step 1: Upload IOCs from clean_ioc_relationships.json ─────────────
async function uploadIOCs() {
  console.log("\n📦 Step 1: Uploading IOCs...");

  const raw = fs.readFileSync("./m3_samples/clean_ioc_relationships.json", "utf-8");
  const records = JSON.parse(raw);

  let success = 0;
  let failed = 0;

  for (const record of records) {
    const { status, data } = await post("/api/iocs", {
      ioc: record.ioc,
      ioc_type: record.ioc_type,
      email_id: record.email_id,
    });

    if (status === 201) {
      success++;
    } else {
      failed++;
      console.log(`  ❌ Failed: ${record.ioc} (${record.ioc_type}) →`, data.error);
    }
  }

  console.log(`  ✅ IOCs uploaded: ${success}`);
  console.log(`  ❌ IOCs failed:   ${failed}`);
  console.log(`  ℹ️  Note: Duplicates are merged automatically (same IOC seen in multiple emails = 1 record with higher sightingCount)`);
}

// ── Step 2: Upload Graph edges from graph_data.json ───────────────────
async function uploadGraph() {
  console.log("\n📦 Step 2: Uploading Graph Relationships...");

  const raw = fs.readFileSync("./m3_samples/graph_data.json", "utf-8");
  const graph = JSON.parse(raw);

  // Build a type lookup from nodes
  const nodeTypes = {};
  graph.nodes.forEach((n) => { nodeTypes[n.id] = n.type; });

  let success = 0;
  let failed = 0;

  for (const edge of graph.edges) {
    const { status, data } = await post("/api/iocs/graph-edge", {
      source: edge.source,
      sourceType: nodeTypes[edge.source] || "email",
      target: edge.target,
      targetType: nodeTypes[edge.target] || "domain",
      relationship: edge.relationship,
    });

    if (status === 201) {
      success++;
    } else if (status === 409) {
      // duplicate edge — that is fine
      success++;
    } else {
      failed++;
      console.log(`  ❌ Edge failed: ${edge.source} → ${edge.target}`, data.error || "");
    }
  }

  console.log(`  ✅ Graph edges uploaded: ${success}`);
  console.log(`  ❌ Graph edges failed:   ${failed}`);
}

// ── Main ──────────────────────────────────────────────────────────────
async function main() {
  console.log("🚀 Starting IOC + Graph upload...");
  console.log("   Make sure your server is running on http://localhost:5000\n");

  try {
    await uploadIOCs();
    await uploadGraph();
    console.log("\n✅ All done! Check your MongoDB Atlas to see the iocs and relationships collections.");
  } catch (err) {
    console.error("\n❌ Upload failed:", err.message);
    console.error("   Is your server running? Start it with: npm run dev");
  }
}

main();
