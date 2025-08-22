// server.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");

const { register, login, publicUser } = require("./auth/localAuth");
const { getGoogleAuthUrl, handleGoogleCallback } = require("./auth/googleAuth");

const {
  verifyAccessToken,
  verifyRefreshToken,
  rotateRefreshToken,
  revokeSession,
} = require("./auth/jwt");

const { findUserById } = require("./users");

const app = express();

// ---------- Config ----------
const PORT = process.env.PORT || 5000;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
const REFRESH_COOKIE_NAME = process.env.REFRESH_COOKIE_NAME || "refresh_token";
const COOKIE_SECURE = (process.env.COOKIE_SECURE || "false") === "true"; // true in prod HTTPS
const COOKIE_SAMESITE = process.env.COOKIE_SAMESITE || "Strict"; // "Lax" or "None" (if cross-site + HTTPS)

// ---------- Middleware ----------
app.use(cookieParser());
app.use(bodyParser.json());
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true,
}));

// Helper to set refresh cookie
function setRefreshCookie(res, refreshToken) {
  res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE, // "Strict" | "Lax" | "None"
    path: "/",                 // limit to /auth/refresh if you prefer
    maxAge: 7 * 24 * 60 * 60 * 1000, // align with REFRESH_TTL
  });
}

// ---------- Local Auth ----------
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const { user, accessToken, refreshToken } = await register(email, password, name);
    setRefreshCookie(res, refreshToken);
    res.json({ user, accessToken });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const { user, accessToken, refreshToken } = await login(email, password);
    setRefreshCookie(res, refreshToken);
    res.json({ user, accessToken });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ---------- Google OAuth (Authorization Code) ----------
app.get("/auth/google", (req, res) => {
  const url = getGoogleAuthUrl();
  res.redirect(url);
});

app.get("/auth/google/callback", async (req, res) => {
  try {
    const { code } = req.query;
    const { user, accessToken, refreshToken } = await handleGoogleCallback(code);
    setRefreshCookie(res, refreshToken);
    // After login, redirect back to frontend; frontend will 401 once and then call /auth/refresh to obtain access token if needed
    // We also append access token for immediate use if you want:
    const redirectUrl = new URL(FRONTEND_URL);
    redirectUrl.searchParams.set("accessToken", accessToken);
    res.redirect(redirectUrl.toString());
  } catch (e) {
    console.error("Google callback error:", e);
    res.status(400).send("Google auth failed");
  }
});

// ---------- Refresh (Rotation + Reuse detection) ----------
app.post("/auth/refresh", (req, res) => {
  try {
    const token = req.cookies[REFRESH_COOKIE_NAME];
    if (!token) return res.status(401).json({ error: "No refresh cookie" });

    const payload = verifyRefreshToken(token); // { sub, sid, jti, exp, ... }
    const rotate = rotateRefreshToken({ sid: payload.sid, presentedJti: payload.jti });
    if (!rotate.ok) {
      if (rotate.reason === "reuse_detected") {
        // clear cookie and revoke
        res.clearCookie(REFRESH_COOKIE_NAME, { path: "/" });
        return res.status(401).json({ error: "Refresh reuse detected. Session revoked." });
      }
      res.clearCookie(REFRESH_COOKIE_NAME, { path: "/" });
      return res.status(401).json({ error: "Invalid session" });
    }

    // Set new rotated refresh cookie
    setRefreshCookie(res, rotate.refreshToken);
    return res.json({ accessToken: rotate.accessToken });
  } catch (e) {
    res.clearCookie(REFRESH_COOKIE_NAME, { path: "/" });
    return res.status(401).json({ error: "Invalid refresh token" });
  }
});

// ---------- Protected route ----------
app.get("/users/profile", (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing access token" });

  try {
    const payload = verifyAccessToken(token); // { sub, jti, iat, exp }
    const user = findUserById(payload.sub);
    if (!user) return res.status(404).json({ error: "User not found" });
    return res.json(publicUser(user));
  } catch (e) {
    return res.status(401).json({ error: "Invalid or expired access token" });
  }
});

// ---------- Logout ----------
app.post("/auth/logout", (req, res) => {
  const token = req.cookies[REFRESH_COOKIE_NAME];
  if (token) {
    try {
      const payload = verifyRefreshToken(token);
      revokeSession(payload.sid);
    } catch {}
  }
  res.clearCookie(REFRESH_COOKIE_NAME, { path: "/" });
  res.json({ ok: true });
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
});
