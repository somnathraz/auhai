const jwt = require("jsonwebtoken");
const RefreshToken = require("../models/RefreshToken");
const User = require("../models/User");
const { generateAccessToken } = require("../utils/auth");

module.exports = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1]; // Extract the token from "Bearer <token>"

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.userId = decoded.userId; // Attach userId to the request
      return next(); // Continue with request
    } catch (err) {
      if (err.name === "TokenExpiredError") {
        console.log("🔄 Token expired, attempting to refresh...");

        // Extract refresh token from request headers
        const refreshToken = req.headers["x-refresh-token"];
        if (!refreshToken) {
          console.log("❌ No refresh token provided.");
          return res.status(401).json({ error: "Refresh token required." });
        }

        // Check if refresh token exists in database
        const storedToken = await RefreshToken.findOne({ token: refreshToken });
        if (!storedToken || storedToken.expiresAt < new Date()) {
          console.log("❌ Invalid or expired refresh token.");
          return res
            .status(401)
            .json({ error: "Refresh token invalid or expired." });
        }

        // Fetch user associated with refresh token
        const user = await User.findById(storedToken.userId);
        if (!user) {
          console.log("❌ User not found for refresh token.");
          return res.status(401).json({ error: "User not found." });
        }

        // Generate a new access token
        const newAccessToken = generateAccessToken(user);
        console.log("✅ New access token generated!");

        // Attach new token to the response header
        res.setHeader("x-new-access-token", newAccessToken);
        req.userId = user._id; // Attach userId to request
        return next();
      }

      console.log("Invalid token:", err);
      return res.status(401).json({ error: "Invalid token." });
    }
  }

  next();
};
