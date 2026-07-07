// src/authDb.js
const bcrypt = require("bcryptjs");
const { db } = require("./db");

const SALT_ROUNDS = 10;

async function createUser(email, plainPassword) {
  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existing) {
    throw new Error("Bu email zaten kayıtlı.");
  }
  const passwordHash = await bcrypt.hash(plainPassword, SALT_ROUNDS);
  const stmt = db.prepare(`
    INSERT INTO users (email, password_hash, tier) VALUES (?, ?, 'free')
  `);
  const info = stmt.run(email, passwordHash);
  return { id: info.lastInsertRowid, email, tier: "free" };
}

async function verifyUser(email, plainPassword) {
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user) return { user: null, reason: "not_found" };
  if (!user.is_active) return { user: null, reason: "inactive" };
  const match = await bcrypt.compare(plainPassword, user.password_hash);
  if (!match) return { user: null, reason: "wrong_password" };
  return { user: { id: user.id, email: user.email, tier: user.tier }, reason: null };
}

function getUserById(id) {
  const user = db
    .prepare("SELECT id, email, tier, rustdesk_id, is_active, created_at FROM users WHERE id = ?")
    .get(id);
  return user || null;
}

function setRustdeskId(userId, rustdeskId) {
  db.prepare("UPDATE users SET rustdesk_id = ? WHERE id = ?").run(rustdeskId, userId);
}

function setTier(userId, tier) {
  db.prepare("UPDATE users SET tier = ? WHERE id = ?").run(tier, userId);
}

function setActive(userId, isActive) {
  db.prepare("UPDATE users SET is_active = ? WHERE id = ?").run(isActive ? 1 : 0, userId);
}

module.exports = {
  createUser,
  verifyUser,
  getUserById,
  setRustdeskId,
  setTier,
  setActive,
};
