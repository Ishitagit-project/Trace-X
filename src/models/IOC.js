const mongoose = require("mongoose");

const iocSchema = new mongoose.Schema(
  {
    // ── IOC category ──────────────────────────────────────────────────
    type: {
      type: String,
      required: [true, "type is required"],
      enum: ["ip", "domain", "url", "email", "hash"],
      index: true,
    },

    // ── Raw value exactly as M3 sent it ───────────────────────────────
    value: {
      type: String,
      required: [true, "value is required"],
      trim: true,
    },

    // ── Cleaned version used for deduplication & searching ────────────
    // e.g. "HTTP://Fake-Login.com/" → "http://fake-login.com"
    normalizedValue: {
      type: String,
      required: [true, "normalizedValue is required"],
      trim: true,
    },

    // ── Which email first introduced this IOC ─────────────────────────
    sourceEmailId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Email",
      default: null,
    },

    // ── Which case this IOC belongs to (set later by M4) ──────────────
    sourceCaseId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Case",
      default: null,
    },

    // ── When this IOC was first and last observed ─────────────────────
    firstSeen: {
      type: Date,
      default: Date.now,
    },
    lastSeen: {
      type: Date,
      default: Date.now,
    },

    // ── How many times this IOC has been seen across all emails ────────
    occurrenceCount: {
      type: Number,
      default: 1,
    },

    // ── Geolocation (filled in later by M4 enrichment) ────────────────
    geolocation: {
      country: { type: String, default: "" },
      city: { type: String, default: "" },
      region: { type: String, default: "" },
      isp: { type: String, default: "" },
      organization: { type: String, default: "" },
      asn: { type: String, default: "" },
      latitude: { type: Number, default: null },
      longitude: { type: Number, default: null },
    },

    // ── Investigation data (filled in later by M4) ────────────────────
    investigation: {
      confidence: { type: Number, default: null }, // 0.0 to 1.0
      relatedEmails: [{ type: mongoose.Schema.Types.ObjectId, ref: "Email" }],
      relatedCases: [{ type: mongoose.Schema.Types.ObjectId, ref: "Case" }],
    },

    // ── Containment status ────────────────────────────────────────────
    status: {
      type: String,
      enum: ["active", "blocked", "whitelisted"],
      default: "active",
      index: true,
    },
  },
  {
    timestamps: true, // adds createdAt, updatedAt automatically
  }
);

// ── Compound unique index: same type + normalizedValue = same IOC ─────
// Prevents duplicate records for the same indicator under the same type
iocSchema.index({ type: 1, normalizedValue: 1 }, { unique: true });

// ── Extra indexes for fast lookups ────────────────────────────────────
iocSchema.index({ occurrenceCount: -1 });     // sort by most-seen IOCs
iocSchema.index({ firstSeen: -1 });           // sort by newest
iocSchema.index({ sourceEmailId: 1 });        // find IOCs by source email
iocSchema.index({ sourceCaseId: 1 });         // find IOCs by case

module.exports = mongoose.model("IOC", iocSchema);
