const Email = require("../models/Email");
const Analysis = require("../models/Analysis");
const IOC = require("../models/IOC");
const Case = require("../models/Case");

/**
 * @desc    Get dashboard metrics and overall statistics
 * @route   GET /api/dashboard-stats
 *
 * Returns aggregate metrics for M6 dashboard cards and widgets:
 *   - totalEmails
 *   - totalAnalyzed
 *   - totalThreats (phishing, malware, bec, suspicious)
 *   - totalSafeEmails
 *   - totalIOCs
 *   - totalCases
 *   - openCases
 *   - investigatingCases
 *   - closedCases
 *   - highRiskCases (threatScore >= 70)
 */
exports.getDashboardStats = async (req, res, next) => {
  try {
    const [
      totalEmails,
      totalAnalyzed,
      totalThreats,
      totalSafeEmails,
      totalIOCs,
      totalCases,
      openCases,
      investigatingCases,
      closedCases,
      highRiskCases,
    ] = await Promise.all([
      Email.countDocuments(),
      Analysis.countDocuments(),
      Analysis.countDocuments({
        classification: { $in: ["phishing", "malware", "bec", "suspicious"] },
      }),
      Analysis.countDocuments({ classification: "safe" }),
      IOC.countDocuments(),
      Case.countDocuments(),
      Case.countDocuments({ status: "open" }),
      Case.countDocuments({ status: "investigating" }),
      Case.countDocuments({ status: "closed" }),
      Case.countDocuments({ threatScore: { $gte: 70 } }),
    ]);

    res.status(200).json({
      success: true,
      data: {
        totalEmails,
        totalAnalyzed,
        totalThreats,
        totalSafeEmails,
        totalIOCs,
        totalCases,
        openCases,
        investigatingCases,
        closedCases,
        highRiskCases,
      },
    });
  } catch (err) {
    next(err);
  }
};
