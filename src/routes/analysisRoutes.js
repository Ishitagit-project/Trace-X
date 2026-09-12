const express = require("express");
const router = express.Router();
const {
  createAnalysis,
  getAnalysisByEmailId,
  updateAnalysis,
  getAllAnalyses,
} = require("../controllers/analysisController");

router.post("/",               createAnalysis);        // M5 saves analysis
router.get("/",                getAllAnalyses);         // dashboard / threat list
router.get("/:emailId",        getAnalysisByEmailId);  // M6 gets result for one email
router.patch("/:emailId",      updateAnalysis);        // M1/M5 adds more evidence

module.exports = router;
