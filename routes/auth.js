const express = require("express");
const router = express.Router();
const User = require("../models/user");
const jwt = require("jsonwebtoken");
const RefreshToken = require("../models/refreshTokens");
const BlacklistedToken = require("../models/blacklistedToken");
const {
  createJti,
  setRefreshCookie,
  storeRefreshToken,
  signAccessToken,
  signRefreshToken,
  generateAccessToken,
  rotateRefreshToken,
} = require("../helpers/token");

router.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const newUser = new User({ username, email, password });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Invalid email or password" });
    }
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    const accessToken = signAccessToken(user);
    const jti = createJti();
    const refreshToken = signRefreshToken(user, jti);

    await storeRefreshToken(
      user,
      refreshToken,
      jti,
      req.ip,
      req.get("User-Agent")
    );

    setRefreshCookie(res, refreshToken);

    res.cookie("access_token", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 15 * 60 * 1000, 
    });

    return res.json({ message: "Logged in", token: accessToken });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});



router.post("/refresh-token", async (req, res) => {
  try {
    const rawToken = req.cookies?.refresh_token;
    if (!rawToken || typeof rawToken !== "string") {
      return res.status(401).json({ message: "No refresh token" });
    }

    let decoded;
    try {
      decoded = jwt.verify(rawToken, process.env.JWT_SECRET);
    } catch (err) {
      return res
        .status(401)
        .json({ message: "Invalid or expired refresh token" });
    }

    const tokenHash = generateAccessToken(rawToken);

    let doc = await RefreshToken.findOne({
      jti: decoded.jti,
      token: tokenHash,
    }).populate("user");

    if (!doc) {
      const suspect = await RefreshToken.findOne({ jti: decoded.jti });
      if (suspect) {
        await RefreshToken.updateMany(
          { user: suspect.user, revokedAt: null },
          { $set: { revokedAt: new Date() } }
        );
        return res
          .status(401)
          .json({
            message: "Token reuse detected. All refresh tokens revoked.",
          });
      }
      return res.status(401).json({ message: "Refresh token not recognized" });
    }

    if (doc.revokedAt)
      return res.status(401).json({ message: "Refresh token revoked" });
    if (doc.expiresAt < new Date())
      return res.status(401).json({ message: "Refresh token expired" });

    const newJti = createJti();
    const newRefreshToken = signRefreshToken(doc.user, newJti);

    doc.revokedAt = new Date();
    doc.replacedByToken = generateAccessToken(newRefreshToken);
    await doc.save();

    const expiresAt = new Date(
      Date.now() + process.env.REFRESH_TOKEN_EXPIRY_IN_SEC * 1000
    );
    await RefreshToken.create({
      user: doc.user._id,
      token: generateAccessToken(newRefreshToken),
      jti: newJti,
      expiresAt,
      ipAddress: req.ip,
      userAgent: req.get("User-Agent"),
    });

    setRefreshCookie(res, newRefreshToken);
    const newAccessToken = signAccessToken(doc.user);

    return res.json({
      access_Token: newAccessToken,
      refresh_Token: newRefreshToken,
    });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});


router.post("/logout", async (req, res) => {
  try {
    const refresh = req.cookies?.refresh_token;
    if (refresh) {
      const tokenHash = generateAccessToken(refresh);
      const doc = await RefreshToken.findOne({ token: tokenHash });
      if (doc && !doc.revokedAt) {
        doc.revokedAt = new Date();
        await doc.save();
      }
    }

    const accessToken =
      req.header("Authorization")?.replace(/^Bearer\s+/i, "") ||
      req.cookies?.access_token ||
      req.cookies?.token ||
      req.cookies?.jwt;

    if (accessToken && typeof accessToken === "string") {
      const tokenHash = generateAccessToken(accessToken);
      const decoded = jwt.decode(accessToken);
      const expiresAt = decoded?.exp
        ? new Date(decoded.exp * 1000)
        : new Date(Date.now() + 60 * 1000);

      try {
        await BlacklistedToken.create({ token: tokenHash, expiresAt });
      } catch (e) {
      }
    }

    res.clearCookie("refresh_token", {
      path: process.env.REFRESH_COOKIE_PATH || "/",
    });
    res.clearCookie("access_token", {
      path: process.env.ACCESS_COOKIE_PATH || "/",
    });
    res.json({ message: "Logged out" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
