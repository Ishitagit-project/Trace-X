const express = require("express");
const router = express.Router();
const {
  createEmail,
  getEmailById,
  getAllEmails,
  getEmailByEmailId,
  getEmailEvidence,
} = require("../controllers/emailController");

// Search by emailId (Message-ID) — must be BEFORE /:id to avoid conflicts
router.get("/search/by-email-id", getEmailByEmailId);

// Evidence endpoint for Replit / frontend Evidence tab
router.get("/:id/evidence", getEmailEvidence);

// CRUD routes
router.post("/", createEmail);
router.get("/", getAllEmails);
router.get("/:id", getEmailById);

module.exports = router;
