const mongoose = require("mongoose");

const caseSchema = new mongoose.Schema(
  {
    // ── Case identity ─────────────────────────────────────────────────
    title: {
      type: String,
      required: [true, "title is required"],
    },

    description: {
      type: String,
      default: "",
    },

    // ── Status & Priority ─────────────────────────────────────────────
    status: {
      type: String,
      enum: ["open", "investigating", "closed"],
      default: "open",
    },

    priority: {
      type: String,
      enum: ["low", "medium", "high", "critical"],
      default: "medium",
    },

    // ── Threat classification ─────────────────────────────────────────
    classification: {
      type: String,
      default: "",
      index: true,
    },

    threatScore: {
      type: Number,
      min: 0,
      max: 100,
      default: null,
    },

    // ── Related documents (populated on GET) ──────────────────────────
    emailIds: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Email",
      },
    ],

    iocIds: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "IOC",
      },
    ],

    analysisIds: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Analysis",
      },
    ],

    // ── Evidence and AI output ────────────────────────────────────────
    // Mixed — M1/M5 can send any structure
    evidence: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },

    aiSummary: {
      type: String,
      default: "",
    },

    recommendations: {
      type: [String],
      default: [],
    },

    // ── Timestamps ────────────────────────────────────────────────────
    closedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true, // adds createdAt + updatedAt automatically
  }
);

// ── Indexes for fast filtering on case list page ──────────────────────
caseSchema.index({ status: 1 });
caseSchema.index({ priority: 1 });
caseSchema.index({ createdAt: -1 });
caseSchema.index({ status: 1, priority: 1, createdAt: -1 });
caseSchema.index({ threatScore: -1 });

module.exports = mongoose.model("Case", caseSchema);
