// auth/googleAuth.js
const { OAuth2Client } = require("google-auth-library");
const {
  signAccessToken,
  signRefreshToken,
} = require("./jwt");
const {
  createUser,
  findUserByProviderId,
} = require("../users");

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI,
} = process.env;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_REDIRECT_URI) {
  console.warn("[googleAuth] Missing Google OAuth env vars — set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI");
}

const oauth = new OAuth2Client({
  clientId: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  redirectUri: GOOGLE_REDIRECT_URI,
});

function getGoogleAuthUrl() {
  const scopes = [
    "openid",
    "email",
    "profile",
  ];
  const url = oauth.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: scopes,
  });
  return url;
}

async function handleGoogleCallback(code) {
  const { tokens } = await oauth.getToken(code);
  // tokens.id_token contains the user identity
  const ticket = await oauth.verifyIdToken({
    idToken: tokens.id_token,
    audience: GOOGLE_CLIENT_ID,
  });
  const payload = ticket.getPayload();
  const sub = payload.sub; // Google user id
  const email = payload.email;
  const name = payload.name || email;

  let user = findUserByProviderId("google", sub);
  if (!user) {
    user = createUser({
      email,
      name,
      provider: "google",
      providerId: sub,
    });
  }

  const accessToken = signAccessToken(user.id);
  const { refreshToken } = signRefreshToken(user.id);

  return { user: { id: user.id, email: user.email, name: user.name, provider: user.provider }, accessToken, refreshToken };
}

module.exports = {
  getGoogleAuthUrl,
  handleGoogleCallback,
};
