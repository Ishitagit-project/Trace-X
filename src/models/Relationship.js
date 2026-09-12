const mongoose = require("mongoose");

const relationshipSchema = new mongoose.Schema(
  {
    // ── Source node (email_id or IOC value) ───────────────────────────
    source: {
      type: String,
      required: [true, "source is required"],
      index: true,
    },

    // ── Source node type ──────────────────────────────────────────────
    sourceType: {
      type: String,
      required: [true, "sourceType is required"],
      enum: ["email", "domain", "url", "ip", "email_address", "hash"],
    },

    // ── Target node (email_id or IOC value) ───────────────────────────
    target: {
      type: String,
      required: [true, "target is required"],
      index: true,
    },

    // ── Target node type ──────────────────────────────────────────────
    targetType: {
      type: String,
      required: [true, "targetType is required"],
      enum: ["email", "domain", "url", "ip", "email_address", "hash"],
    },

    // ── Edge label ────────────────────────────────────────────────────
    // "contains_ioc"  → email → IOC
    // "shared_ioc"    → IOC → other email that shares the same IOC
    relationship: {
      type: String,
      required: [true, "relationship is required"],
      enum: ["contains_ioc", "shared_ioc"],
      index: true,
    },
  },
  {
    timestamps: true,
  }
);

// ── Compound unique index: prevent duplicate edges ────────────────────
relationshipSchema.index(
  { source: 1, target: 1, relationship: 1 },
  { unique: true }
);

module.exports = mongoose.model("Relationship", relationshipSchema);
