// auth/localAuth.js
const bcrypt = require("bcrypt");
const {
  signAccessToken,
  signRefreshToken,
} = require("./jwt");
const {
  createUser,
  findUserByEmail,
} = require("../users");

async function register(email, password, name = "") {
  if (findUserByEmail(email)) {
    throw new Error("User already exists");
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const user = createUser({ email, passwordHash, name, provider: "local" });
  return issueTokens(user);
}

async function login(email, password) {
  const user = findUserByEmail(email);
  if (!user || !user.passwordHash) throw new Error("Invalid credentials");
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) throw new Error("Invalid credentials");
  return issueTokens(user);
}

function issueTokens(user) {
  const accessToken = signAccessToken(user.id);
  const { refreshToken } = signRefreshToken(user.id);
  return { user: publicUser(user), accessToken, refreshToken };
}

function publicUser(u) {
  const { passwordHash, ...pub } = u;
  return pub;
}

module.exports = {
  register,
  login,
  publicUser,
};
