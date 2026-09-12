const mongoose = require("mongoose");

const attachmentSchema = new mongoose.Schema(
  {
    filename: String,
    content_type: String,
  },
  { _id: false }
);

const securityHeadersSchema = new mongoose.Schema(
  {
    received: [String],
    authentication_results: [String],
    dkim_signature: [String],
    received_spf: [String],
    return_path: { type: String, default: null },
    message_id: { type: String, default: null },
  },
  { _id: false }
);

const emailSchema = new mongoose.Schema(
  {
    email_id: {
      type: String,
      required: [true, "email_id is required"],
      unique: true,
      index: true,
    },
    sender: {
      type: [String],
      required: [true, "sender is required"],
    },
    receiver: {
      type: [String],
      default: [],
    },
    subject: {
      type: String,
      default: "",
    },
    reply_to: {
      type: [String],
      default: [],
    },
    urls: {
      type: [String],
      default: [],
    },
    domains: {
      type: [String],
      default: [],
    },
    ips: {
      type: [String],
      default: [],
    },
    attachments: {
      type: [attachmentSchema],
      default: [],
    },
    security_headers: {
      type: securityHeadersSchema,
      default: () => ({}),
    },
    suspicious_indicators: {
      type: [String],
      default: [],
    },
    // Future references (for M1/M4/M5/M6)
    threatAnalysisId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Analysis",
      default: null,
    },
    caseId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Case",
      default: null,
    },
  },
  {
    timestamps: true, // adds createdAt, updatedAt
  }
);

// Basic indexing for faster lookups
emailSchema.index({ sender: 1 });
emailSchema.index({ receiver: 1 });
emailSchema.index({ domains: 1 });
emailSchema.index({ ips: 1 });
emailSchema.index({ createdAt: -1 });

module.exports = mongoose.model("Email", emailSchema);
