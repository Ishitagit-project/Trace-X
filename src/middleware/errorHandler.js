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
      error: "Validation failed",
      details: fields,
    });
  }

  // Mongoose duplicate key (code 11000) → 409 Conflict
  if (err.code === 11000) {
    const duplicateField = Object.keys(err.keyPattern)[0];
    const duplicateValue = err.keyValue[duplicateField];
    return res.status(409).json({
      success: false,
      error: "Duplicate entry",
      message: `An email with ${duplicateField} "${duplicateValue}" already exists.`,
    });
  }

  // Mongoose bad ObjectId → 400
  if (err.name === "CastError" && err.kind === "ObjectId") {
    return res.status(400).json({
      success: false,
      error: "Invalid ID format",
      message: `"${err.value}" is not a valid ID.`,
    });
  }

  // Fallback → 500
  res.status(err.statusCode || 500).json({
    success: false,
    error: err.message || "Internal Server Error",
  });
};

module.exports = errorHandler;
