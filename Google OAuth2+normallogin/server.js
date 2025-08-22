// server.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const { OAuth2Client } = require("google-auth-library");

const app = express();

/* -------------------- Config -------------------- */
const PORT = process.env.PORT || 5000;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";

/** JWT secrets & TTLs (use strong secrets in prod) */
const ACCESS_SECRET = process.env.ACCESS_SECRET || "dev-access-secret";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "dev-refresh-secret";
const ACCESS_TTL = process.env.ACCESS_TTL || "15m"; // e.g. 15m in prod
const REFRESH_TTL = process.env.REFRESH_TTL || "7d"; // e.g. 7-30d in prod

/** Cookie settings */
const REFRESH_COOKIE_NAME = process.env.REFRESH_COOKIE_NAME || "refresh_token";
const COOKIE_SECURE = (process.env.COOKIE_SECURE || "false") === "true"; // true behind HTTPS
const COOKIE_SAMESITE = process.env.COOKIE_SAMESITE || "Strict"; // 'Strict' | 'Lax' | 'None'

/** Google OAuth (Authorization Code) */
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_REDIRECT_URI =
  process.env.GOOGLE_REDIRECT_URI || `http://localhost:${PORT}/auth/google/callback`;
const oauth = new OAuth2Client({
  clientId: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  redirectUri: GOOGLE_REDIRECT_URI,
});

/* -------------------- Middleware -------------------- */
app.use(cookieParser());
app.use(bodyParser.json());
app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
  })
);

/* -------------------- In-memory "DB" (demo) -------------------- */
// Users: { id, email, passwordHash?, name, provider: 'local'|'google', providerId? }
let uid = 1;
const users = [];
const byId = (id) => users.find((u) => u.id === id);
const byEmail = (email) => users.find((u) => u.email?.toLowerCase() === String(email).toLowerCase());
const byProvider = (provider, providerId) =>
  users.find((u) => u.provider === provider && u.providerId === providerId);

/* -------------------- Session Store (refresh rotation) -------------------- */
/** Map<sid, { userId, jti }> — use Redis in production for multi-instance */
const sessionStore = new Map();

/* -------------------- Helpers: JWT -------------------- */
function signAccessToken(userId) {
  const jti = uuidv4(); // not for rotation, just to make tokens unique
  return jwt.sign({ sub: userId, jti }, ACCESS_SECRET, { expiresIn: ACCESS_TTL });
}

function createRefreshForUser(userId) {
  const sid = uuidv4();
  const jti = uuidv4();
  sessionStore.set(sid, { userId, jti }); // current JTI for this session
  const token = jwt.sign({ sub: userId, sid, jti }, REFRESH_SECRET, { expiresIn: REFRESH_TTL });
  return token;
}

function verifyAccess(token) {
  return jwt.verify(token, ACCESS_SECRET);
}

function verifyRefresh(token) {
  return jwt.verify(token, REFRESH_SECRET);
}

/** Rotate single-use refresh token. Detect reuse and revoke. */
function rotateRefreshToken({ sid, presentedJti }) {
  const sess = sessionStore.get(sid);
  if (!sess) return { ok: false, reason: "session_not_found" };
  if (sess.jti !== presentedJti) {
    // Reuse detected (old token replayed) -> revoke session
    sessionStore.delete(sid);
    return { ok: false, reason: "reuse_detected" };
  }
  // Valid: rotate to new JTI
  const newJti = uuidv4();
  sessionStore.set(sid, { userId: sess.userId, jti: newJti });
  const refreshToken = jwt.sign({ sub: sess.userId, sid, jti: newJti }, REFRESH_SECRET, {
    expiresIn: REFRESH_TTL,
  });
  const accessToken = signAccessToken(sess.userId);
  return { ok: true, accessToken, refreshToken };
}

function revokeSession(sid) {
  sessionStore.delete(sid);
}

function setRefreshCookie(res, refreshToken) {
  res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000, // align to REFRESH_TTL
  });
}

/* -------------------- Helpers: Users -------------------- */
function publicUser(u) {
  if (!u) return null;
  const { passwordHash, ...pub } = u;
  return pub;
}

/* -------------------- Local Auth -------------------- */

/** Register */
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password, name = "" } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Email & password required" });
    if (byEmail(email)) return res.status(400).json({ error: "User already exists" });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = { id: uid++, email, passwordHash, name, provider: "local" };
    users.push(user);

    const accessToken = signAccessToken(user.id);
    const refreshToken = createRefreshForUser(user.id);
    setRefreshCookie(res, refreshToken);
    res.json({ user: publicUser(user), accessToken });
  } catch (e) {
    res.status(500).json({ error: "Registration failed" });
  }
});

/** Login */
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = byEmail(email);
    if (!user || !user.passwordHash) return res.status(401).json({ error: "Invalid credentials" });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const accessToken = signAccessToken(user.id);
    const refreshToken = createRefreshForUser(user.id);
    setRefreshCookie(res, refreshToken);
    res.json({ user: publicUser(user), accessToken });
  } catch (e) {
    res.status(500).json({ error: "Login failed" });
  }
});

/* -------------------- Google OAuth2 (Authorization Code) -------------------- */

/** Step 1: Redirect user to Google consent */
app.get("/auth/google", (req, res) => {
  const scopes = ["openid", "email", "profile"];
  const url = oauth.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: scopes,
  });
  res.redirect(url);
});

/** Step 2: Handle Google callback, issue our tokens */
app.get("/auth/google/callback", async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).send("Missing code");

    const { tokens } = await oauth.getToken(code);
    // Verify ID token to get identity
    const ticket = await oauth.verifyIdToken({
      idToken: tokens.id_token,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const sub = payload.sub;
    const email = payload.email;
    const name = payload.name || email;

    let user = byProvider("google", sub);
    if (!user) {
      // create or link by email if needed
      const existingByEmail = byEmail(email);
      if (existingByEmail) {
        // upgrade existing local user to also have google?
        // For demo we keep separate; in prod you may link accounts
      }
      user = { id: uid++, email, name, provider: "google", providerId: sub };
      users.push(user);
    }

    const accessToken = signAccessToken(user.id);
    const refreshToken = createRefreshForUser(user.id);
    setRefreshCookie(res, refreshToken);

    // Redirect back to your frontend with accessToken in URL (optional convenience)
    const redirect = new URL(FRONTEND_URL);
    redirect.searchParams.set("accessToken", accessToken);
    res.redirect(redirect.toString());
  } catch (e) {
    console.error("Google callback error:", e);
    res.status(400).send("Google auth failed");
  }
});

/* -------------------- Refresh (rotation + reuse detection) -------------------- */
app.post("/auth/refresh", (req, res) => {
  try {
    const token = req.cookies[REFRESH_COOKIE_NAME];
    if (!token) return res.status(401).json({ error: "No refresh cookie" });

    const payload = verifyRefresh(token); // { sub, sid, jti, iat, exp }
    const rotated = rotateRefreshToken({ sid: payload.sid, presentedJti: payload.jti });
    if (!rotated.ok) {
      res.clearCookie(REFRESH_COOKIE_NAME, { path: "/" });
      if (rotated.reason === "reuse_detected") {
        return res.status(401).json({ error: "Refresh reuse detected. Session revoked." });
      }
      return res.status(401).json({ error: "Invalid session" });
    }

    setRefreshCookie(res, rotated.refreshToken);
    return res.json({ accessToken: rotated.accessToken });
  } catch (e) {
    res.clearCookie(REFRESH_COOKIE_NAME, { path: "/" });
    return res.status(401).json({ error: "Invalid refresh token" });
  }
});

/* -------------------- Protected API -------------------- */
app.get("/users/profile", (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing access token" });

  try {
    const payload = verifyAccess(token); // { sub, jti, iat, exp }
    const user = byId(payload.sub);
    if (!user) return res.status(404).json({ error: "User not found" });
    return res.json(publicUser(user));
  } catch (e) {
    return res.status(401).json({ error: "Invalid or expired access token" });
  }
});

/* -------------------- Logout -------------------- */
app.post("/auth/logout", (req, res) => {
  const token = req.cookies[REFRESH_COOKIE_NAME];
  if (token) {
    try {
      const payload = verifyRefresh(token); // { sid, ... }
      revokeSession(payload.sid);
    } catch {}
  }
  res.clearCookie(REFRESH_COOKIE_NAME, { path: "/" });
  res.json({ ok: true });
});

/* -------------------- Start -------------------- */
app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    console.warn(
      "[warn] Google OAuth vars missing. Set GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET/GOOGLE_REDIRECT_URI."
    );
  }
});
