const rateLimit = require("express-rate-limit");

// Limit login attempts (5 per 15 minutes)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 5,
  message: "Too many login attempts. Try again later.",
});

// Limit password reset requests (3 per hour)
const resetPasswordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: "Too many password reset requests. Try again later.",
});

module.exports = { loginLimiter, resetPasswordLimiter };
