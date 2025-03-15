const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const RefreshToken = require("../models/RefreshToken");

const hashPassword = async (password) => {
  return await bcrypt.hash(password, 12);
};

const comparePassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

const generateAccessToken = (user) => {
  return jwt.sign(
    { userId: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "15m" } // short-lived access token
  );
};
const generateRefreshToken = async (user) => {
  const tokenString = uuidv4();
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 14); // 14-day refresh token

  await RefreshToken.create({
    token: tokenString,
    userId: user._id,
    expiresAt,
  });

  return tokenString;
};

const generateTokens = async (user) => {
  const accessToken = generateAccessToken(user);
  const refreshToken = await generateRefreshToken(user);
  return { accessToken, refreshToken };
};

const verifyToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET);
};

module.exports = {
  hashPassword,
  comparePassword,
  generateTokens,
  generateAccessToken,
  generateRefreshToken,
  verifyToken,
};
