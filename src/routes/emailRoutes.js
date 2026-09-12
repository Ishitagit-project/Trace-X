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
const upload = require("../middleware/upload");

router.post("/", (req, res, next) => {
  // Use multer for multipart/form-data, or pass directly for json
  upload.single("file")(req, res, (err) => {
    if (err) {
      return res.status(400).json({
        success: false,
        error: "Upload error",
        message: err.message,
      });
    }
    next();
  });
}, createEmail);
router.get("/", getAllEmails);
router.get("/:id", getEmailById);

module.exports = router;
