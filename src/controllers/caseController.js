const mongoose = require("mongoose");
const Case     = require("../models/Case");
const Email    = require("../models/Email");
const IOC      = require("../models/IOC");
const Analysis = require("../models/Analysis");

/**
 * @desc    Create a new case
 * @route   POST /api/cases
 * @body    { title, description, status, priority, classification,
 *            threatScore, emailIds, iocIds, analysisIds,
 *            evidence, aiSummary, recommendations }
 */
exports.createCase = async (req, res, next) => {
  try {
    const { title, threatScore, emailIds, iocIds, analysisIds } = req.body;

    if (!title) {
      return res.status(400).json({
        success: false,
        message: "Missing required field: title",
      });
    }

    if (threatScore !== undefined && (typeof threatScore !== "number" || threatScore < 0 || threatScore > 100)) {
      return res.status(400).json({
        success: false,
        message: "Threat score must be a number between 0 and 100",
      });
    }

    // Validate referenced emails if provided
    if (emailIds && Array.isArray(emailIds) && emailIds.length > 0) {
      for (const id of emailIds) {
        if (!mongoose.Types.ObjectId.isValid(id)) {
          return res.status(400).json({
            success: false,
            message: `Invalid email ID format: "${id}".`,
          });
        }
      }
      const foundEmails = await Email.find({ _id: { $in: emailIds } });
      if (foundEmails.length !== emailIds.length) {
        return res.status(404).json({
          success: false,
          message: "One or more referenced emails do not exist.",
        });
      }
    }

    // Validate referenced IOCs if provided
    if (iocIds && Array.isArray(iocIds) && iocIds.length > 0) {
      for (const id of iocIds) {
        if (!mongoose.Types.ObjectId.isValid(id)) {
          return res.status(400).json({
            success: false,
            message: `Invalid IOC ID format: "${id}".`,
          });
        }
      }
      const foundIOCs = await IOC.find({ _id: { $in: iocIds } });
      if (foundIOCs.length !== iocIds.length) {
        return res.status(404).json({
          success: false,
          message: "One or more referenced IOCs do not exist.",
        });
      }
    }

    // Validate referenced Analyses if provided
    if (analysisIds && Array.isArray(analysisIds) && analysisIds.length > 0) {
      for (const id of analysisIds) {
        if (!mongoose.Types.ObjectId.isValid(id)) {
          return res.status(400).json({
            success: false,
            message: `Invalid Analysis ID format: "${id}".`,
          });
        }
      }
      const foundAnalyses = await Analysis.find({ _id: { $in: analysisIds } });
      if (foundAnalyses.length !== analysisIds.length) {
        return res.status(404).json({
          success: false,
          message: "One or more referenced Analyses do not exist.",
        });
      }
    }

    const newCase = await Case.create(req.body);

    // Update referenced emails with caseId
    if (emailIds && emailIds.length > 0) {
      await Email.updateMany({ _id: { $in: emailIds } }, { $set: { caseId: newCase._id } });
    }

    // Update referenced IOCs with sourceCaseId
    if (iocIds && iocIds.length > 0) {
      await IOC.updateMany({ _id: { $in: iocIds } }, { $set: { sourceCaseId: newCase._id } });
    }

    res.status(201).json({
      success: true,
      message: "Case created successfully",
      data: newCase,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Get all cases with filters and pagination
 * @route   GET /api/cases
 * @query   status, priority, classification, page, limit
 *
 * Examples:
 *   GET /api/cases?status=open
 *   GET /api/cases?priority=high
 *   GET /api/cases?classification=phishing
 *   GET /api/cases?status=open&priority=critical
 */
exports.getAllCases = async (req, res, next) => {
  try {
    const { status, priority, classification, page, limit } = req.query;

    const filter = {};
    if (status)         filter.status         = status;
    if (priority)       filter.priority       = priority;
    if (classification) filter.classification = classification;

    const pageNum  = Math.max(parseInt(page)  || 1, 1);
    const limitNum = Math.min(Math.max(parseInt(limit) || 20, 1), 100);
    const skip     = (pageNum - 1) * limitNum;

    const [cases, total] = await Promise.all([
      Case.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitNum)
        // Lightweight populate — only the fields M6 needs for the list view
        .populate("emailIds",   "email_id sender subject")
        .populate("iocIds",     "value type status")
        .lean(),
      Case.countDocuments(filter),
    ]);

    res.status(200).json({
      success: true,
      count: cases.length,
      total,
      page: pageNum,
      totalPages: Math.ceil(total / limitNum),
      data: cases,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Get one case — full detail view (the Case page in M6)
 * @route   GET /api/cases/:id
 *
 * Returns all sections of the case page:
 *   - Case details (title, status, priority, classification, threatScore)
 *   - Related emails (email_id, sender, subject)
 *   - Related IOCs   (value, type, geolocation, investigation.confidence)
 *   - Analysis       (threatScore, classification, summary, recommendations)
 *   - Evidence + AI summary
 */
exports.getCaseById = async (req, res, next) => {
  try {
    const caseDoc = await Case.findById(req.params.id)
      .populate("emailIds",    "email_id sender subject")
      .populate("iocIds",      "value type status geolocation investigation")
      .populate("analysisIds", "classification threatScore confidence summary recommendations");

    if (!caseDoc) {
      return res.status(404).json({
        success: false,
        error: "Case not found",
        message: `No case exists with id "${req.params.id}".`,
      });
    }

    res.status(200).json({ success: true, data: caseDoc });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Update a case — status, priority, evidence, notes, close
 * @route   PATCH /api/cases/:id
 * @body    { status, priority, description, evidence, aiSummary,
 *            recommendations, emailIds, iocIds, analysisIds }
 *
 * Special rule: if status === "closed" → set closedAt automatically
 */
exports.updateCase = async (req, res, next) => {
  try {
    const updates = { ...req.body };

    // Auto-set closedAt when case is being closed
    if (updates.status === "closed") {
      updates.closedAt = new Date();
    }

    // If reopening a closed case, clear closedAt
    if (updates.status === "open" || updates.status === "investigating") {
      updates.closedAt = null;
    }

    const updatedCase = await Case.findByIdAndUpdate(
      req.params.id,
      { $set: updates },
      { new: true, runValidators: true }
    )
      .populate("emailIds",    "email_id sender subject")
      .populate("iocIds",      "value type status")
      .populate("analysisIds", "classification threatScore summary");

    if (!updatedCase) {
      return res.status(404).json({
        success: false,
        error: "Case not found",
        message: `No case exists with id "${req.params.id}".`,
      });
    }

    res.status(200).json({
      success: true,
      message: "Case updated successfully",
      data: updatedCase,
    });
  } catch (err) {
    next(err);
  }
};
