const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const errorHandler = require("./middleware/errorHandler");
const emailRoutes = require("./routes/emailRoutes");

const app = express();

// ── Global Middleware ──────────────────────────────────────────────────
app.use(cors()); // Allow cross-origin requests (M6 frontend)
app.use(express.json({ limit: "10mb" })); // Parse JSON bodies (large emails)
app.use(morgan("dev")); // HTTP request logging

// ── Health Check ───────────────────────────────────────────────────────
app.get("/api/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Email Threat Platform API is running",
    timestamp: new Date().toISOString(),
  });
});

// ── API Routes ─────────────────────────────────────────────────────────
app.use("/api/emails", emailRoutes);

// Future routes (uncomment when ready):
// app.use("/api/iocs", iocRoutes);
// app.use("/api/analyses", threatAnalysisRoutes);
// app.use("/api/cases", caseRoutes);

// ── 404 Handler ────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Route not found",
    message: `Cannot ${req.method} ${req.originalUrl}`,
  });
});

// ── Global Error Handler ───────────────────────────────────────────────
app.use(errorHandler);

module.exports = app;
