const Email = require("../models/Email");

/**
 * @desc    Store a parsed email from M3
 * @route   POST /api/emails
 */
exports.createEmail = async (req, res, next) => {
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
    const email = await Email.findById(req.params.id);

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
