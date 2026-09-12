/**
 * Centralized error-handling middleware.
 * Catches all errors thrown or passed via next(err) in routes/controllers.
 */
const errorHandler = (err, req, res, next) => {
  console.error(`❌ [${req.method}] ${req.originalUrl} →`, err.message);

  // Mongoose validation error → 400
  if (err.name === "ValidationError") {
    const fields = Object.values(err.errors).map((e) => ({
      field: e.path,
      message: e.message,
    }));
    return res.status(400).json({
      success: false,
      message: `Validation failed: ${fields.map((f) => f.message).join(", ")}`,
      details: fields,
    });
  }

  // Mongoose duplicate key (code 11000) → 409 Conflict
  if (err.code === 11000) {
    const duplicateField = Object.keys(err.keyPattern || {})[0] || "field";
    const duplicateValue = err.keyValue ? err.keyValue[duplicateField] : "";
    return res.status(409).json({
      success: false,
      message: `Duplicate entry: record with ${duplicateField} "${duplicateValue}" already exists.`,
    });
  }

  // Mongoose bad ObjectId → 400
  if (err.name === "CastError" && err.kind === "ObjectId") {
    return res.status(400).json({
      success: false,
      message: `"${err.value}" is not a valid ID format.`,
    });
  }

  // Fallback → 500
  res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || "Internal Server Error",
  });
};

module.exports = errorHandler;
