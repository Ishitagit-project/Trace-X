const express = require("express");
const router  = express.Router();
const {
  createCase,
  getAllCases,
  getCaseById,
  updateCase,
} = require("../controllers/caseController");

router.post("/",    createCase);    // M4/M5 create a case
router.get("/",     getAllCases);   // M6 case list — ?status=open&priority=high
router.get("/:id",  getCaseById);  // M6 full case detail page
router.patch("/:id", updateCase);  // M6 change status / priority / close case

module.exports = router;
