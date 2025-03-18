// graphql/resolvers.js
const User = require("../models/User");
const {
  hashPassword,
  comparePassword,
  generateTokens,
} = require("../utils/auth");
const { v4: uuidv4 } = require("uuid");
const jwt = require("jsonwebtoken");
const { signupSchema, loginSchema } = require("../utils/validators");
const RefreshToken = require("../models/RefreshToken");
const { sendEmail } = require("../utils/email");
const { checkRole } = require("../utils/authorization");
const { logEvent } = require("../models/logger");
const AuditLog = require("../models/AuditLog");
const { OAuth2Client } = require("google-auth-library");
const GraphQLJSON = require("graphql-type-json");
const crypto = require("crypto");
const ApiKey = require("../models/ApiKey");

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const dummyPassword = "Social_dummy_@123#";

const socialLogin = async (_, { provider, token }) => {
  let payload;
  if (provider === "google") {
    // Verify the token from Google Identity Services
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    payload = ticket.getPayload();
  } else {
    throw new Error("Unsupported provider.");
  }

  // Use the payload to find or create a user in your database.
  const email = payload.email;
  let user = await User.findOne({ email });
  if (!user) {
    // Create new user if they don't exist.
    user = await User.create({
      username: payload.name || email.split("@")[0],
      email: email,
      passwordHash: await hashPassword(dummyPassword), // Social login users don't have a password
      role: "user",
      isVerified: true, // They are verified via Google
    });
  }
  // Generate JWT tokens (access & refresh)
  const { accessToken, refreshToken } = await generateTokens(user);
  return { accessToken, refreshToken, user };
};

module.exports = {
  JSON: GraphQLJSON,
  Query: {
    me: async (_, __, { req }) => {
      if (!req.userId) throw new Error("Not authenticated!");
      return await User.findById(req.userId);
    },
    listUsers: async (_, __, { req }) => {
      if (!req.userId) throw new Error("Not authenticated!");
      const currentUser = await User.findById(req.userId);
      checkRole(currentUser, ["admin"]); // Only admin can list users
      return await User.find({});
    },
    listApiKeys: async (_, __, { req }) => {
      // Ensure the request is authenticated
      if (!req.userId) throw new Error("Not authenticated!");
      // List API keys for the current user (developer)
      return await ApiKey.find({ userId: req.userId });
    },
    auditLogs: async (_, __, { req }) => {
      // Only allow admin to access audit logs
      if (!req.userId) throw new Error("Not authenticated!");
      const currentUser = await User.findById(req.userId);
      checkRole(currentUser, ["admin"]);
      return await AuditLog.find({}).sort({ timestamp: -1 });
    },
  },

  Mutation: {
    signup: async (_, { username, email, password }) => {
      const { error } = signupSchema.validate({ username, email, password });
      if (error) throw new Error(error.details[0].message);

      const existingUser = await User.findOne({ email });
      if (existingUser) throw new Error("User already exists!");

      const passwordHash = await hashPassword(password);

      // Generate verification token
      const verificationToken = uuidv4();

      const user = await User.create({
        username,
        email,
        passwordHash,
        verificationToken,
      });

      // Send verification email
      const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;
      await sendEmail(
        user.email,
        "Verify Your Email",
        `Click here to verify: ${verificationLink}`
      );
      await logEvent("SIGNUP", user._id, { email });
      return {
        message: "Signup successful! Check your email to verify your account.",
      };
    },
    requestPasswordReset: async (_, { email }) => {
      const user = await User.findOne({ email });
      if (!user) throw new Error("User not found!");

      const resetToken = uuidv4();
      user.passwordResetToken = resetToken;
      user.passwordResetExpires = new Date(Date.now() + 15 * 60 * 1000); // Expires in 15 min
      await user.save();

      // Send password reset email
      const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
      await sendEmail(
        user.email,
        "Reset Your Password",
        `Click here: ${resetLink}`
      );
      await logEvent("REQUEST_PASSWORD_RESET", user ? user._id : null, {
        email,
      });
      return "Password reset email sent.";
    },
    login: async (_, { email, password }, { req }) => {
      // 1) Find user
      const user = await User.findOne({ email });
      if (!user) throw new Error("User not found!");

      // Validate request metadata (e.g., IP address)
      const ipAddress =
        req.headers["x-forwarded-for"] || req.connection.remoteAddress;
      const userAgent = req.headers["user-agent"];

      // 2) Validate credentials
      const { error } = loginSchema.validate({ email, password });
      if (error) throw new Error(error.details[0].message);
      const valid = await comparePassword(password, user.passwordHash);
      if (!valid) throw new Error("Invalid password!");

      // 3) Generate tokens
      const { accessToken, refreshToken } = await generateTokens(user);

      // 4) Log the login event with metadata
      await logEvent("LOGIN", user._id, { email, ipAddress, userAgent });

      // 5) Assess risk
      const riskScore = await assessLoginRisk({ user, ipAddress, userAgent });
      if (riskScore > 0.7) {
        // Optionally, trigger additional security (e.g., require MFA)
        // For now, you might log the risk score or set a flag in the user session.
        console.log("High-risk login detected:", riskScore);
      }

      return { accessToken, refreshToken, user };
    },
    resetPassword: async (_, { token, newPassword }) => {
      const user = await User.findOne({
        passwordResetToken: token,
        passwordResetExpires: { $gt: new Date() },
      });
      if (!user) throw new Error("Invalid or expired reset token.");

      user.passwordHash = await hashPassword(newPassword);
      user.passwordResetToken = null;
      user.passwordResetExpires = null;
      await user.save();
      await logEvent("RESET_PASSWORD", user._id);
      return "Password reset successful. You can now log in.";
    },
    // For exchanging refreshToken -> new access token
    refreshToken: async (_, { refreshToken }) => {
      const foundToken = await RefreshToken.findOne({ token: refreshToken });
      if (!foundToken) throw new Error("Invalid refresh token!");

      // Check if expired
      if (foundToken.expiresAt < new Date()) {
        throw new Error("Refresh token expired!");
      }

      // Retrieve user
      const user = await User.findById(foundToken.userId);
      if (!user) throw new Error("User not found!");

      // Generate a fresh access token
      const newAccessToken = jwt.sign(
        { userId: user._id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "15m" }
      );

      return { accessToken: newAccessToken };
    },
    updateUserRole: async (_, { userId, role }, { req }) => {
      //   console.log(userId, "userid here");

      if (!req.userId) throw new Error("Not authenticated!");
      const currentUser = await User.findById(req.userId);
      checkRole(currentUser, ["admin"]); // Only admin can update roles

      const user = await User.findByIdAndUpdate(
        userId,
        { role },
        { new: true }
      );
      if (!user) throw new Error("User not found.");
      await logEvent("UPDATE_USER_ROLE", req.userId, {
        targetUserId: userId,
        newRole: role,
      });
      await logEvent("UPDATE_USER_ROLE", req.userId, {
        targetUserId: userId,
        newRole: role,
      });
      return user;
    },
    // Admin-only: Delete a user
    deleteUser: async (_, { userId }, { req }) => {
      if (!req.userId) throw new Error("Not authenticated!");
      const currentUser = await User.findById(req.userId);
      checkRole(currentUser, ["admin"]); // Only admin can delete users

      await User.findByIdAndDelete(userId);
      await logEvent("DELETE_USER", req.userId, { targetUserId: userId });
      return "User deleted successfully.";
    },
    socialLogin,
    createApiKey: async (_, __, { req }) => {
      if (!req.userId) throw new Error("Not authenticated!");
      // Generate a new random API key
      const key = crypto.randomBytes(32).toString("hex");
      const apiKey = await ApiKey.create({ key, userId: req.userId });
      return apiKey;
    },
    revokeApiKey: async (_, { apiKeyId }, { req }) => {
      if (!req.userId) throw new Error("Not authenticated!");
      // Only allow revoking keys that belong to the current user
      const apiKey = await ApiKey.findOne({
        _id: apiKeyId,
        userId: req.userId,
      });
      if (!apiKey) throw new Error("API Key not found or not owned by you.");
      apiKey.revoked = true;
      await apiKey.save();
      return "API Key revoked successfully.";
    },
  },
};
