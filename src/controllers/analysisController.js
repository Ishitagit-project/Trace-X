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

const VALID_RISK_LEVELS = ["low", "medium", "high", "critical", "unknown"];

/**
 * @desc    Save an analysis result (called by M5 after AI classification)
 * @route   POST /api/analyses
 * @body    { emailId, classification, confidence, riskLevel, threatScore,
 *            evidence, iocs, summary, investigation, recommendations, modelVersion }
 */
exports.createAnalysis = async (req, res, next) => {
  try {
    let emailId = req.body.emailId || req.body.email_id;
    let classification = req.body.classification;
    let threatScore = req.body.threatScore;
    let riskLevel = req.body.riskLevel || req.body.risk_level;
    let confidence = req.body.confidence;
    let summary = req.body.summary;
    let evidence = req.body.evidence;
    let iocs = req.body.iocs || req.body.IOCs;
    let recommendations = req.body.recommendations;
    let investigation = req.body.investigation && typeof req.body.investigation === "object"
      ? { ...req.body.investigation }
      : {};

    // If M5 sent classification as an object containing nested details
    if (classification && typeof classification === "object") {
      if (confidence === undefined && classification.confidence !== undefined) {
        confidence = classification.confidence;
      }
      if (!riskLevel && classification.risk_level) {
        riskLevel = classification.risk_level;
      }
      if (!summary && classification.summary) {
        summary = classification.summary;
      }
      if (!evidence && classification.evidence) {
        evidence = classification.evidence;
      }
      if (!iocs && (classification.IOCs || classification.iocs)) {
        iocs = classification.IOCs || classification.iocs;
      }
      classification = classification.classification; // extract string "phishing"
    }

    if (!emailId) {
      return res.status(400).json({
        success: false,
        message: "Missing required field: emailId (or email_id)",
      });
    }

    if (!classification || typeof classification !== "string") {
      return res.status(400).json({
        success: false,
        message: "Missing required field: classification",
      });
    }

    // Validate classification enum
    if (classification && !VALID_CLASSIFICATIONS.includes(classification.toLowerCase())) {
      return res.status(400).json({
        success: false,
        message: `Invalid classification "${classification}". Must be one of: ${VALID_CLASSIFICATIONS.join(", ")}`,
      });
    }

    // Validate confidence range (0 to 1)
    if (confidence !== undefined && confidence !== null && (typeof confidence !== "number" || confidence < 0 || confidence > 1)) {
      return res.status(400).json({
        success: false,
        message: "Confidence must be a number between 0 and 1",
      });
    }

    // Validate riskLevel enum if provided
    if (riskLevel && !VALID_RISK_LEVELS.includes(riskLevel.toLowerCase())) {
      return res.status(400).json({
        success: false,
        message: `Invalid riskLevel "${riskLevel}". Must be one of: ${VALID_RISK_LEVELS.join(", ")}`,
      });
    }

    // Validate threat score range if provided
    if (threatScore !== undefined && threatScore !== null && (typeof threatScore !== "number" || threatScore < 0 || threatScore > 100)) {
      return res.status(400).json({
        success: false,
        message: "Threat score must be a number between 0 and 100",
      });
    }

    // Bi-directional mapping between threatScore and riskLevel for maximum compatibility
    if (threatScore === undefined || threatScore === null) {
      if (riskLevel) {
        const r = riskLevel.toLowerCase();
        if (r === "critical") threatScore = 95;
        else if (r === "high") threatScore = 85;
        else if (r === "medium") threatScore = 50;
        else if (r === "low") threatScore = 20;
        else threatScore = 0;
      } else {
        threatScore = 0;
      }
    }

    if (!riskLevel) {
      if (threatScore >= 90) riskLevel = "critical";
      else if (threatScore >= 70) riskLevel = "high";
      else if (threatScore >= 40) riskLevel = "medium";
      else riskLevel = "low";
    }

    // Normalize IOCs object structure
    const normalizedIOCs = { emails: [], domains: [], urls: [], ips: [] };
    if (iocs && typeof iocs === "object") {
      normalizedIOCs.emails  = iocs.emails || [];
      normalizedIOCs.domains = iocs.domains || [];
      normalizedIOCs.urls    = iocs.urls || iocs.URLs || [];
      normalizedIOCs.ips     = iocs.ips || iocs.IPs || [];
    }

    // Normalize snake_case keys in investigation
    if (investigation.recommended_investigation_steps && !investigation.recommendedInvestigationSteps) {
      investigation.recommendedInvestigationSteps = investigation.recommended_investigation_steps;
    }
    if (investigation.final_assessment && !investigation.finalAssessment) {
      investigation.finalAssessment = investigation.final_assessment;
    }
    if (investigation.IOCs && !investigation.iocs) {
      investigation.iocs = {
        emails:  investigation.IOCs.emails || [],
        domains: investigation.IOCs.domains || [],
        urls:    investigation.IOCs.urls || investigation.IOCs.URLs || [],
        ips:     investigation.IOCs.ips || investigation.IOCs.IPs || [],
      };
    }

    // Bi-directional mapping for recommendations
    let recs = Array.isArray(recommendations) ? [...recommendations] : [];
    if (Array.isArray(investigation.recommendedInvestigationSteps) && investigation.recommendedInvestigationSteps.length > 0 && recs.length === 0) {
      recs = [...investigation.recommendedInvestigationSteps];
    } else if (recs.length > 0 && (!Array.isArray(investigation.recommendedInvestigationSteps) || investigation.recommendedInvestigationSteps.length === 0)) {
      investigation.recommendedInvestigationSteps = [...recs];
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

    // Prepare complete data
    const analysisData = {
      ...req.body,
      emailId: emailDoc._id,
      classification: classification.toLowerCase(),
      riskLevel: riskLevel.toLowerCase(),
      threatScore,
      confidence,
      summary,
      evidence,
      iocs: normalizedIOCs,
      recommendations: recs,
      investigation,
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
