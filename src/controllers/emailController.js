const Email = require("../models/Email");
const IOC = require("../models/IOC");
const normalizeIOC = require("../utils/normalizeIOC");
const { parseEmlFile } = require("../services/parserService");
const fs = require("fs");

/**
 * Helper to normalize and upsert extracted IOCs from parsed email
 */
async function saveExtractedIOCs(parsedData, sourceEmailId) {
  try {
    const iocEntries = [];

    // URLs
    if (Array.isArray(parsedData.urls)) {
      parsedData.urls.forEach((u) => iocEntries.push({ value: u, type: "url" }));
    }

    // Domains
    if (Array.isArray(parsedData.domains)) {
      parsedData.domains.forEach((d) => iocEntries.push({ value: d, type: "domain" }));
    }

    // IPs
    if (Array.isArray(parsedData.ips)) {
      parsedData.ips.forEach((ip) => iocEntries.push({ value: ip, type: "ip" }));
    }

    // Senders & receivers as email IOCs
    if (Array.isArray(parsedData.sender)) {
      parsedData.sender.forEach((em) => iocEntries.push({ value: em, type: "email" }));
    }
    if (Array.isArray(parsedData.receiver)) {
      parsedData.receiver.forEach((em) => iocEntries.push({ value: em, type: "email" }));
    }

    for (const item of iocEntries) {
      if (!item.value) continue;
      const normalized = normalizeIOC(item.value, item.type);
      if (!normalized) continue;

      await IOC.findOneAndUpdate(
        { normalizedValue: normalized, type: item.type },
        {
          $setOnInsert: {
            value: item.value,
            normalizedValue: normalized,
            type: item.type,
            firstSeen: new Date(),
            sourceEmailId: sourceEmailId,
          },
          $set: { lastSeen: new Date() },
          $inc: { occurrenceCount: 1 },
          $addToSet: { "investigation.relatedEmails": sourceEmailId },
        },
        { upsert: true, setDefaultsOnInsert: true }
      );
    }
  } catch (err) {
    console.error("Warning: Error saving extracted IOCs:", err.message);
  }
}

/**
 * @desc    Store a parsed email from M3 or upload an .eml file
 * @route   POST /api/emails
 */
exports.createEmail = async (req, res, next) => {
  // If an .eml file was uploaded via multipart/form-data
  if (req.file) {
    const filePath = req.file.path;

    try {
      // 1. Run M3's Python parser
      const parsedData = await parseEmlFile(filePath);

      // 2. Ensure unique email_id (if existing email with this ID exists, append timestamp)
      let uniqueEmailId = parsedData.email_id || req.file.originalname.replace(/\.eml$/i, "");
      const existing = await Email.findOne({ email_id: uniqueEmailId });
      if (existing) {
        uniqueEmailId = `${uniqueEmailId}_${Date.now()}`;
      }
      parsedData.email_id = uniqueEmailId;

      // 3. Save parsed email into MongoDB
      const email = await Email.create(parsedData);

      // 4. Save/normalize extracted IOCs in parallel/background
      await saveExtractedIOCs(parsedData, email._id);

      // 5. Respond with frontend-expected structure
      return res.status(201).json({
        success: true,
        message: "Email uploaded and parsed successfully",
        data: {
          emailId: email._id,
          filename: req.file.originalname,
          subject: email.subject || "",
          sender: Array.isArray(email.sender) ? email.sender.join(", ") : email.sender || "",
          createdAt: email.createdAt,
        },
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        error: "EML parsing/upload error",
        message: err.message,
      });
    } finally {
      // Ensure uploaded temp file is always deleted
      if (fs.existsSync(filePath)) {
        try {
          fs.unlinkSync(filePath);
        } catch (cleanupErr) {
          console.error("Failed to delete temp file:", cleanupErr.message);
        }
      }
    }
  }

  // Fallback: Existing raw JSON body handling
  try {
    const email = await Email.create(req.body);

    res.status(201).json({
      success: true,
      message: "Email stored successfully",
      data: email,
    });
  } catch (err) {
    next(err); // handled by errorHandler middleware
  }
};

/**
 * @desc    Retrieve a single email by MongoDB _id
 * @route   GET /api/emails/:id
 */
exports.getEmailById = async (req, res, next) => {
  try {
    const email = await Email.findById(req.params.id)
      .populate("threatAnalysisId")
      .populate("caseId");

    if (!email) {
      return res.status(404).json({
        success: false,
        error: "Email not found",
        message: `No email exists with id "${req.params.id}".`,
      });
    }

    res.status(200).json({
      success: true,
      data: email,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    List all emails with pagination
 * @route   GET /api/emails?page=1&limit=20&sort=-date
 */
exports.getAllEmails = async (req, res, next) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 20, 1), 100);
    const skip = (page - 1) * limit;

    // Sort: default newest first by createdAt
    const sortField = req.query.sort || "-createdAt";

    const [emails, total] = await Promise.all([
      Email.find().sort(sortField).skip(skip).limit(limit).lean(),
      Email.countDocuments(),
    ]);

    res.status(200).json({
      success: true,
      count: emails.length,
      total,
      page,
      totalPages: Math.ceil(total / limit),
      data: emails,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Search emails by email_id
 * @route   GET /api/emails/search/by-email-id?email_id=<value>
 */
exports.getEmailByEmailId = async (req, res, next) => {
  try {
    const { email_id } = req.query;

    if (!email_id) {
      return res.status(400).json({
        success: false,
        error: "Missing query parameter",
        message: 'Provide "email_id" as a query parameter.',
      });
    }

    const email = await Email.findOne({ email_id });

    if (!email) {
      return res.status(404).json({
        success: false,
        error: "Email not found",
        message: `No email exists with email_id "${email_id}".`,
      });
    }

    res.status(200).json({
      success: true,
      data: email,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Get forensic evidence for the frontend Evidence tab
 * @route   GET /api/emails/:id/evidence
 *
 * Supports both MongoDB ObjectId and M3 email_id string
 */
exports.getEmailEvidence = async (req, res, next) => {
  try {
    const { id } = req.params;
    const mongoose = require("mongoose");

    let email = null;
    if (mongoose.Types.ObjectId.isValid(id)) {
      email = await Email.findById(id);
    }
    if (!email) {
      email = await Email.findOne({ email_id: id });
    }

    if (!email) {
      return res.status(404).json({
        success: false,
        message: `No email found with ID "${id}".`,
      });
    }

    const headers = email.security_headers || {};

    const evidenceResponse = {
      emailId: email._id,
      sender: {
        from: email.sender || [],
        replyTo: email.reply_to && email.reply_to.length > 0 ? email.reply_to[0] : "",
        returnPath: headers.return_path || "",
      },
      urls: email.urls || [],
      content: {
        text: "",
        html: "",
      },
      headers: {
        received: headers.received || [],
        authenticationResults: Array.isArray(headers.authentication_results)
          ? headers.authentication_results.join("; ")
          : (headers.authentication_results || ""),
        spf: Array.isArray(headers.received_spf)
          ? headers.received_spf.join("; ")
          : (headers.received_spf || ""),
        dkim: Array.isArray(headers.dkim_signature)
          ? headers.dkim_signature.join("; ")
          : (headers.dkim_signature || ""),
        dmarc: "",
        messageId: headers.message_id || "",
        all: headers,
      },
    };

    res.status(200).json({
      success: true,
      data: evidenceResponse,
    });
  } catch (err) {
    next(err);
  }
};
