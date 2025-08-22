// auth/jwt.js
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

// Load secrets from env
const ACCESS_SECRET  = process.env.ACCESS_SECRET  || "dev-access-secret";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "dev-refresh-secret";

// Lifetimes
const ACCESS_TTL  = process.env.ACCESS_TTL  || "15m";   // demo: 15m
const REFRESH_TTL = process.env.REFRESH_TTL || "7d";    // demo: 7d

// In-memory session store (for demo). Use Redis in production.
const sessionStore = new Map(); // sid -> { userId, jti }

function signAccessToken(userId) {
  const jti = uuidv4();
  const token = jwt.sign({ sub: userId, jti }, ACCESS_SECRET, { expiresIn: ACCESS_TTL });
  return token;
}

// Create a refresh token for a session (sid) with a jti and remember it.
function signRefreshToken(userId) {
  const sid = uuidv4();
  const jti = uuidv4();
  sessionStore.set(sid, { userId, jti }); // store current jti
  const token = jwt.sign({ sub: userId, sid, jti }, REFRESH_SECRET, { expiresIn: REFRESH_TTL });
  return { refreshToken: token, sid, jti };
}

function verifyAccessToken(token) {
  return jwt.verify(token, ACCESS_SECRET);
}

function verifyRefreshToken(token) {
  return jwt.verify(token, REFRESH_SECRET);
}

// Rotate refresh token (single-use): check jti matches, then issue new jti & token.
function rotateRefreshToken({ sid, presentedJti }) {
  const sess = sessionStore.get(sid);
  if (!sess) return { ok: false, reason: "session_not_found" };

  if (sess.jti !== presentedJti) {
    // Reuse detected -> revoke session
    sessionStore.delete(sid);
    return { ok: false, reason: "reuse_detected" };
  }

  // Valid: rotate to a new jti
  const newJti = uuidv4();
  sess.jti = newJti;
  sessionStore.set(sid, sess);

  const newRefresh = jwt.sign({ sub: sess.userId, sid, jti: newJti }, REFRESH_SECRET, { expiresIn: REFRESH_TTL });
  const newAccess  = signAccessToken(sess.userId);

  return { ok: true, accessToken: newAccess, refreshToken: newRefresh };
}

function revokeSession(sid) {
  sessionStore.delete(sid);
}

module.exports = {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  rotateRefreshToken,
  revokeSession,
  sessionStore,
};
