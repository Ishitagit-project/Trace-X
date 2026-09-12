const mongoose = require("mongoose");
const Analysis = require("../models/Analysis");
const Email = require("../models/Email");

const VALID_CLASSIFICATIONS = [
  "safe",
  "phishing",
  "spam",
  "malware",
  "bec",
  "suspicious",
  "unknown",
];

/**
 * @desc    Save an analysis result (called by M5 after AI classification)
 * @route   POST /api/analyses
 * @body    { emailId, classification, threatScore, confidence,
 *            summary, forensicEvidence, aiEvidence,
 *            recommendations, modelVersion }
 */
exports.createAnalysis = async (req, res, next) => {
  try {
    const { emailId, classification, threatScore } = req.body;

    if (!emailId) {
      return res.status(400).json({
        success: false,
        message: "Missing required field: emailId",
      });
    }

    // Validate classification enum
    if (classification && !VALID_CLASSIFICATIONS.includes(classification.toLowerCase())) {
      return res.status(400).json({
        success: false,
        message: `Invalid classification "${classification}". Must be one of: ${VALID_CLASSIFICATIONS.join(", ")}`,
      });
    }

    // Validate threat score range
    if (threatScore !== undefined && (typeof threatScore !== "number" || threatScore < 0 || threatScore > 100)) {
      return res.status(400).json({
        success: false,
        message: "Threat score must be a number between 0 and 100",
      });
    }

    // Find the email either by MongoDB ObjectId or M3 email_id string
    let emailDoc = null;
    if (mongoose.Types.ObjectId.isValid(emailId)) {
      emailDoc = await Email.findById(emailId);
    }
    if (!emailDoc) {
      emailDoc = await Email.findOne({ email_id: emailId });
    }

    if (!emailDoc) {
      return res.status(404).json({
        success: false,
        message: `Referenced email not found with id "${emailId}". Save the email first.`,
      });
    }

    // Use actual MongoDB ObjectId for the reference
    const analysisData = {
      ...req.body,
      emailId: emailDoc._id,
      classification: classification ? classification.toLowerCase() : undefined,
    };

    const analysis = await Analysis.create(analysisData);

    // Link the analysis back to the email document
    await Email.findByIdAndUpdate(emailDoc._id, {
      threatAnalysisId: analysis._id,
    });

    res.status(201).json({
      success: true,
      message: "Analysis saved successfully",
      data: analysis,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Get analysis for a specific email (by ObjectId or email_id)
 * @route   GET /api/analyses/:emailId
 */
exports.getAnalysisByEmailId = async (req, res, next) => {
  try {
    let emailTargetId = req.params.emailId;

    // Check if parameter is an email_id string instead of MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(emailTargetId)) {
      const email = await Email.findOne({ email_id: emailTargetId });
      if (!email) {
        return res.status(404).json({
          success: false,
          message: `Email not found with email_id "${emailTargetId}".`,
        });
      }
      emailTargetId = email._id;
    }

    let analysis = await Analysis.findOne({ emailId: emailTargetId })
      .populate("emailId", "email_id sender subject");

    // Fallback: if not found by emailId reference, check if req.params.emailId was the analysis _id directly
    if (!analysis && mongoose.Types.ObjectId.isValid(req.params.emailId)) {
      analysis = await Analysis.findById(req.params.emailId)
        .populate("emailId", "email_id sender subject");
    }

    if (!analysis) {
      return res.status(404).json({
        success: false,
        message: `No analysis exists for email id "${req.params.emailId}".`,
      });
    }

    res.status(200).json({ success: true, data: analysis });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Update an existing analysis (M1 or M5 adds more evidence)
 * @route   PATCH /api/analyses/:emailId
 */
exports.updateAnalysis = async (req, res, next) => {
  try {
    // Prevent emailId from being changed
    delete req.body.emailId;

    const analysis = await Analysis.findOneAndUpdate(
      { emailId: req.params.emailId },
      { $set: req.body },
      { new: true, runValidators: true }
    );

    if (!analysis) {
      return res.status(404).json({
        success: false,
        error: "Analysis not found",
        message: `No analysis exists for email id "${req.params.emailId}".`,
      });
    }

    res.status(200).json({
      success: true,
      message: "Analysis updated successfully",
      data: analysis,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Get all analyses — with filters and pagination
 * @route   GET /api/analyses
 * @query   classification, minScore, maxScore, page, limit
 *
 * Examples:
 *   GET /api/analyses?classification=phishing
 *   GET /api/analyses?minScore=70
 *   GET /api/analyses?classification=phishing&minScore=80
 */
exports.getAllAnalyses = async (req, res, next) => {
  try {
    const { classification, minScore, maxScore, page, limit } = req.query;

    const filter = {};

    if (classification) filter.classification = classification;

    if (minScore || maxScore) {
      filter.threatScore = {};
      if (minScore) filter.threatScore.$gte = Number(minScore);
      if (maxScore) filter.threatScore.$lte = Number(maxScore);
    }

    const pageNum  = Math.max(parseInt(page)  || 1, 1);
    const limitNum = Math.min(Math.max(parseInt(limit) || 20, 1), 100);
    const skip     = (pageNum - 1) * limitNum;

    const [analyses, total] = await Promise.all([
      Analysis.find(filter)
        .sort({ threatScore: -1, analyzedAt: -1 })
        .skip(skip)
        .limit(limitNum)
        .populate("emailId", "email_id sender subject")
        .lean(),
      Analysis.countDocuments(filter),
    ]);

    res.status(200).json({
      success: true,
      count: analyses.length,
      total,
      page: pageNum,
      totalPages: Math.ceil(total / limitNum),
      data: analyses,
    });
  } catch (err) {
    next(err);
  }
};
