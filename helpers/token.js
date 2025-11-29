const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const RefreshToken = require("../models/refreshTokens");

const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || "3m";
const REFRESH_TOKEN_EXPIRY_IN_SEC = parseInt(process.env.REFRESH_TOKEN_EXPIRY_IN_SEC, 10) || 60 * 60 * 24 * 7;
const REFRESH_COOKIE_PATH = process.env.REFRESH_COOKIE_PATH || "/";

function hashToken(tokenPayload) {
  return crypto.createHash("sha256").update(tokenPayload).digest("hex");
}

function createJti() {
  return crypto.randomBytes(16).toString("hex");
}

function signAccessToken(user) {
  const tokenPayload = { id: user._id, email: user.email, tokenVersion: user.tokenVersion ?? 0 };
  const accessToken = jwt.sign(tokenPayload, process.env.JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY,
  });
  return accessToken;
}

function signRefreshToken(user, jti) {
  const refreshSecret = process.env.REFRESH_TOKEN_SECRET || process.env.JWT_SECRET;
  const refreshTokenPayload = { id: user._id, jti };
  const refreshToken = jwt.sign(refreshTokenPayload, refreshSecret, {
    expiresIn: REFRESH_TOKEN_EXPIRY_IN_SEC,
  });
  return refreshToken;
}

async function storeRefreshToken(user, refreshToken, jti, ip, userAgent) {
  const tokenHash = hashToken(refreshToken);
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_IN_SEC * 1000);
  await RefreshToken.create({
    user: user._id,
    token: tokenHash,
    jti,
    expiresAt,
    ipAddress: ip,
    userAgent: userAgent,
  });
}

function setRefreshCookie(res, token) {
  res.cookie("refresh_token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Strict",
    path: REFRESH_COOKIE_PATH,
    maxAge: REFRESH_TOKEN_EXPIRY_IN_SEC * 1000,
  });
}

async function revokeRefreshToken(jti) {
  const token = await RefreshToken.findOne({ jti: jti });
  if (token && !token.revokedAt) {
    token.revokedAt = new Date();
    await token.save();
  }
}

async function rotateRefreshToken(oldDoc, user, req, res) {
  oldDoc.revokedAt = new Date();
  const Jti = createJti();

  const newRefreshToken = signRefreshToken(user, Jti);

  oldDoc.replacedByToken = hashToken(newRefreshToken);

  await oldDoc.save();
 
  await storeRefreshToken(
    user,
    newRefreshToken,
    Jti,
    req.ip,
    req.get("User-Agent")
  );

  setRefreshCookie(res, newRefreshToken);

  const newAccessToken = signAccessToken(user);

  return { accessToken: newAccessToken, refreshToken: newRefreshToken };
}

module.exports = {
  signAccessToken,
  signRefreshToken,
  storeRefreshToken,
  revokeRefreshToken,
  setRefreshCookie,
  createJti,
  rotateRefreshToken,
  generateAccessToken: hashToken, 
  hashToken,
};