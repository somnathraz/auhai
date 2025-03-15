module.exports = (requiredRole) => (req, res, next) => {
  if (!req.userId) {
    return res.status(403).json({ error: "Unauthorized" });
  }

  // Get user role from context
  if (req.userRole !== requiredRole) {
    return res
      .status(403)
      .json({ error: "Forbidden: Insufficient permissions" });
  }

  next();
};
