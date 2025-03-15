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

module.exports = {
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
    login: async (_, { email, password }) => {
      // 1) Find user
      const user = await User.findOne({ email });
      if (!user) throw new Error("User not found!");

      const { error } = loginSchema.validate({ email, password });
      if (error) throw new Error(error.details[0].message);
      // 2) Check password
      const valid = await comparePassword(password, user.passwordHash);
      if (!valid) throw new Error("Invalid password!");

      // 3) Generate tokens
      const { accessToken, refreshToken } = await generateTokens(user);
      await logEvent("LOGIN", user._id, { email });
      // 4) Return tokens + user
      return {
        accessToken,
        refreshToken,
        user,
      };
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
  },
};
