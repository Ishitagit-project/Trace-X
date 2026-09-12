const IOC = require("../models/IOC");
const Relationship = require("../models/Relationship");
const normalizeIOC = require("../utils/normalizeIOC");

/**
 * @desc    Create or save an IOC (with deduplication)
 * @route   POST /api/iocs
 * @body    { ioc, ioc_type, email_id }
 *
 * If the same normalizedValue + type already exists:
 *   → update lastSeen, increment occurrenceCount, add email to relatedEmails
 * If new:
 *   → create a fresh record
 */
exports.createIOC = async (req, res, next) => {
  try {
    const { ioc, ioc_type, email_id } = req.body;

    if (!ioc || !ioc_type) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields: ioc and ioc_type",
      });
    }

    const normalized = normalizeIOC(ioc, ioc_type);

    const result = await IOC.findOneAndUpdate(
      { normalizedValue: normalized, type: ioc_type },
      {
        $setOnInsert: {
          value: ioc,
          normalizedValue: normalized,
          type: ioc_type,
          firstSeen: new Date(),
        },
        $set:  { lastSeen: new Date() },
        $inc:  { occurrenceCount: 1 },
        ...(email_id && {
          $addToSet: { "investigation.relatedEmails": email_id },
        }),
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    res.status(201).json({
      success: true,
      message: "IOC saved successfully",
      data: result,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Get all IOCs — with filters and pagination
 * @route   GET /api/iocs
 * @query   type, value, emailId, caseId, status, page, limit
 *
 * Examples:
 *   GET /api/iocs?type=ip
 *   GET /api/iocs?type=domain&value=attack.com
 *   GET /api/iocs?emailId=abc123
 *   GET /api/iocs?caseId=abc123
 */
exports.getAllIOCs = async (req, res, next) => {
  try {
    const { type, value, emailId, caseId, status, page, limit } = req.query;

    const filter = {};

    // Filter by IOC type (ip, domain, url, email, hash)
    if (type) filter.type = type;

    // Filter by IOC status (active, blocked, whitelisted, watchlisted, monitored)
    if (status) filter.status = status;

    // Filter by value — partial match (e.g. ?value=attack)
    if (value) {
      filter.$or = [
        { normalizedValue: { $regex: value.toLowerCase(), $options: "i" } },
        { value: { $regex: value, $options: "i" } },
      ];
    }

    // Filter by source email ID
    if (emailId) {
      filter["investigation.relatedEmails"] = emailId;
    }

    // Filter by case ID (supports both sourceCaseId and investigation.relatedCases)
    if (caseId) {
      filter.$or = [
        { sourceCaseId: caseId },
        { "investigation.relatedCases": caseId },
      ];
    }

    const pageNum  = Math.max(parseInt(page)  || 1,  1);
    const limitNum = Math.min(Math.max(parseInt(limit) || 50, 1), 200);
    const skip     = (pageNum - 1) * limitNum;

    const [iocs, total] = await Promise.all([
      IOC.find(filter)
        .sort({ occurrenceCount: -1 })
        .skip(skip)
        .limit(limitNum)
        .lean(),
      IOC.countDocuments(filter),
    ]);

    res.status(200).json({
      success: true,
      count: iocs.length,
      total,
      page: pageNum,
      totalPages: Math.ceil(total / limitNum),
      data: iocs,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Get one IOC by MongoDB _id
 * @route   GET /api/iocs/:id
 *
 * Returns:
 *   - IOC value and type
 *   - Geolocation
 *   - Related emails
 *   - Related cases
 *   - Investigation details
 */
exports.getIOCById = async (req, res, next) => {
  try {
    const ioc = await IOC.findById(req.params.id)
      .populate("sourceEmailId",               "email_id sender subject")
      .populate("sourceCaseId",                "caseId title status")
      .populate("investigation.relatedEmails", "email_id sender subject")
      .populate("investigation.relatedCases",  "caseId title status");

    if (!ioc) {
      return res.status(404).json({
        success: false,
        error: "IOC not found",
        message: `No IOC found with id "${req.params.id}".`,
      });
    }

    res.status(200).json({ success: true, data: ioc });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Update IOC — M4 adds geolocation, ASN, ISP, confidence,
 *          related emails, related cases
 * @route   PATCH /api/iocs/:id
 * @body    { geolocation, investigation, status }
 */
exports.updateIOC = async (req, res, next) => {
  try {
    const { geolocation, investigation, status } = req.body;

    const updateFields = {};
    if (geolocation)  updateFields.geolocation  = geolocation;
    if (status)       updateFields.status        = status;

    // investigation sub-fields (merge, don't overwrite the whole object)
    if (investigation?.confidence !== undefined) {
      updateFields["investigation.confidence"] = investigation.confidence;
    }
    if (investigation?.relatedEmails) {
      // handled separately as $addToSet to avoid duplicates
    }
    if (investigation?.relatedCases) {
      // handled separately as $addToSet to avoid duplicates
    }

    const addToSet = {};
    if (investigation?.relatedEmails?.length) {
      addToSet["investigation.relatedEmails"] = { $each: investigation.relatedEmails };
    }
    if (investigation?.relatedCases?.length) {
      addToSet["investigation.relatedCases"] = { $each: investigation.relatedCases };
    }

    const updateQuery = { $set: updateFields };
    if (Object.keys(addToSet).length) updateQuery.$addToSet = addToSet;

    const ioc = await IOC.findByIdAndUpdate(req.params.id, updateQuery, { new: true });

    if (!ioc) {
      return res.status(404).json({
        success: false,
        error: "IOC not found",
        message: `No IOC found with id "${req.params.id}".`,
      });
    }

    res.status(200).json({ success: true, data: ioc });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Pivot — find all emails sharing the same IOC value (for M4)
 * @route   GET /api/iocs/:id/pivot
 */
exports.pivotIOC = async (req, res, next) => {
  try {
    const ioc = await IOC.findById(req.params.id)
      .populate("investigation.relatedEmails", "email_id sender subject")
      .lean();

    if (!ioc) {
      return res.status(404).json({
        success: false,
        error: "IOC not found",
      });
    }

    res.status(200).json({
      success: true,
      ioc: ioc.normalizedValue,
      type: ioc.type,
      occurrenceCount: ioc.occurrenceCount,
      firstSeen: ioc.firstSeen,
      lastSeen: ioc.lastSeen,
      relatedEmails: ioc.investigation?.relatedEmails || [],
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Get all graph edges for a node (for M4/M6)
 * @route   GET /api/iocs/:id/relationships
 */
exports.getRelationships = async (req, res, next) => {
  try {
    const ioc = await IOC.findById(req.params.id).lean();
    if (!ioc) {
      return res.status(404).json({ success: false, error: "IOC not found" });
    }

    const edges = await Relationship.find({
      $or: [{ source: ioc.normalizedValue }, { target: ioc.normalizedValue }],
    }).lean();

    res.status(200).json({ success: true, count: edges.length, data: edges });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Full graph — nodes + edges for M6 visualization
 * @route   GET /api/iocs/graph
 */
exports.getGraph = async (req, res, next) => {
  try {
    const edges = await Relationship.find().lean();

    const nodeSet = new Map();
    edges.forEach((edge) => {
      if (!nodeSet.has(edge.source))
        nodeSet.set(edge.source, { id: edge.source, type: edge.sourceType });
      if (!nodeSet.has(edge.target))
        nodeSet.set(edge.target, { id: edge.target, type: edge.targetType });
    });

    res.status(200).json({
      success: true,
      data: {
        nodes: Array.from(nodeSet.values()),
        edges: edges.map((e) => ({
          source: e.source,
          target: e.target,
          relationship: e.relationship,
        })),
      },
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Save a graph edge (used by upload-iocs.js)
 * @route   POST /api/iocs/graph-edge
 */
exports.createGraphEdge = async (req, res, next) => {
  try {
    const { source, sourceType, target, targetType, relationship } = req.body;

    if (!source || !target || !relationship) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields: source, target, relationship",
      });
    }

    const edge = await Relationship.findOneAndUpdate(
      { source, target, relationship },
      { source, sourceType, target, targetType, relationship },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    res.status(201).json({ success: true, data: edge });
  } catch (err) {
    next(err);
  }
};
