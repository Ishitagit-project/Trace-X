const mongoose = require("mongoose");

const analysisSchema = new mongoose.Schema(
  {
    // ── Which email this analysis belongs to ──────────────────────────
    emailId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Email",
      required: [true, "emailId is required"],
    },

    // ── AI classification result ──────────────────────────────────────
    classification: {
      type: String,
      required: [true, "classification is required"],
      enum: ["safe", "phishing", "spam", "malware", "bec", "suspicious", "unknown"],
    },

    // ── Overall threat score (0 = safe, 100 = critical) ───────────────
    threatScore: {
      type: Number,
      required: [true, "threatScore is required"],
      min: [0, "threatScore cannot be below 0"],
      max: [100, "threatScore cannot exceed 100"],
    },

    // ── How confident the AI model is (0.0 to 1.0) ───────────────────
    confidence: {
      type: Number,
      min: 0,
      max: 1,
      default: null,
    },

    // ── Short human-readable summary of the finding ───────────────────
    summary: {
      type: String,
      default: "",
    },

    // ── Raw forensic evidence from M1 (SPF, DKIM, DMARC, headers etc) ─
    // Using Mixed so M1 can send any structure they want
    forensicEvidence: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },

    // ── Raw AI evidence from M5 (model output, feature scores etc) ────
    // Using Mixed so M5 can send any structure they want
    aiEvidence: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },

    // ── What the analyst/AI recommends doing ─────────────────────────
    recommendations: {
      type: [String],
      default: [],
    },

    // ── Which version of M5's model produced this result ─────────────
    modelVersion: {
      type: String,
      default: "v1",
    },

    // ── When the analysis was run ─────────────────────────────────────
    analyzedAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
  },
  {
    timestamps: true, // also adds createdAt, updatedAt
  }
);

// ── Recommended indexes ───────────────────────────────────────────────
analysisSchema.index({ emailId: 1 }, { unique: true });
analysisSchema.index({ classification: 1 });
analysisSchema.index({ threatScore: -1 });
analysisSchema.index({ classification: 1, threatScore: -1 });

module.exports = mongoose.model("Analysis", analysisSchema);
