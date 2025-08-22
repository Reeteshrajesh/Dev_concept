import express from "express";
import axios from "axios";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";

const app = express();
app.use(cookieParser());

// Replace with your values
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = "https://yourapp.com/auth/google/callback";

// Mock DB functions
async function findUserByEmail(email) {
  return null; // replace with real DB query
}
async function createUser(userData) {
  return { id: "123", ...userData }; // replace with DB insert
}
function generateJwt(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1h" });
}

// 1️⃣ Redirect to Google Auth
app.get("/auth/google", (req, res) => {
  const redirectUri = "https://accounts.google.com/o/oauth2/v2/auth";
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile",
    access_type: "offline",
  });

  res.redirect(`${redirectUri}?${params.toString()}`);
});

// 2️⃣ Handle Google Callback
app.get("/auth/google/callback", async (req, res) => {
  const { code } = req.query;

  // Exchange code for tokens
  const tokenRes = await axios.post(
    "https://oauth2.googleapis.com/token",
    new URLSearchParams({
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      grant_type: "authorization_code",
    })
  );

  const { access_token } = tokenRes.data;

  // Get user profile from Google
  const userInfo = await axios.get(
    "https://www.googleapis.com/oauth2/v2/userinfo",
    { headers: { Authorization: `Bearer ${access_token}` } }
  );

  const profile = userInfo.data;

  // Link user to DB
  let user = await findUserByEmail(profile.email);
  if (!user) {
    user = await createUser({
      email: profile.email,
      name: profile.name,
      googleId: profile.id,
    });
  }

  // Issue app JWT
  const token = generateJwt({ id: user.id });
  res.cookie("auth_token", token, { httpOnly: true, secure: true });

  res.redirect("/dashboard");
});

// Start server
app.listen(3000, () => console.log("Server running on http://localhost:3000"));
