const express = require("express");
const router = express.Router();
const {
  createIOC,
  getAllIOCs,
  getIOCById,
  updateIOC,
  pivotIOC,
  getRelationships,
  getGraph,
  createGraphEdge,
} = require("../controllers/iocController");

// ── Graph routes — must be BEFORE /:id to avoid conflicts ─────────────
router.get("/graph", getGraph);
router.post("/graph-edge", createGraphEdge);

// ── Core IOC routes ───────────────────────────────────────────────────
router.post("/",   createIOC);   // M3/backend saves extracted IOC
router.get("/",    getAllIOCs);   // M6 IOC explorer — with filters

// ── Single IOC by MongoDB _id ─────────────────────────────────────────
router.get("/:id",              getIOCById);       // full details
router.patch("/:id",            updateIOC);        // M4 enriches IOC
router.get("/:id/pivot",        pivotIOC);         // M4 pivots to related emails
router.get("/:id/relationships", getRelationships); // M4/M6 graph edges

module.exports = router;
