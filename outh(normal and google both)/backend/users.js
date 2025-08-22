// users.js
let uid = 1;
const users = []; // { id, email, passwordHash, name, provider, providerId }

function createUser({ email, passwordHash = null, name = "", provider = "local", providerId = null }) {
  const user = { id: uid++, email, passwordHash, name, provider, providerId };
  users.push(user);
  return user;
}

function findUserByEmail(email) {
  return users.find(u => u.email.toLowerCase() === email.toLowerCase());
}

function findUserById(id) {
  return users.find(u => u.id === id);
}

function findUserByProviderId(provider, providerId) {
  return users.find(u => u.provider === provider && u.providerId === providerId);
}

module.exports = {
  users,
  createUser,
  findUserByEmail,
  findUserById,
  findUserByProviderId,
};
