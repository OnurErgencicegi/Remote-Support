// src/authDb.js
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { db } = require("./db");
const SALT_ROUNDS = 10;

async function createUser(email, plainPassword, role = "controller") {
  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existing) {
    throw new Error("Bu email zaten kayitli.");
  }
  const normalizedRole = role === "host" ? "host" : "controller";
  const passwordHash = await bcrypt.hash(plainPassword, SALT_ROUNDS);
  const stmt = db.prepare(`
    INSERT INTO users (email, password_hash, tier, role) VALUES (?, ?, 'free', ?)
  `);
  const info = stmt.run(email, passwordHash, normalizedRole);
  return { id: info.lastInsertRowid, email, tier: "free", role: normalizedRole };
}

async function verifyUser(email, plainPassword) {
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user) return { user: null, reason: "not_found" };
  if (!user.is_active) return { user: null, reason: "inactive" };
  const match = await bcrypt.compare(plainPassword, user.password_hash);
  if (!match) return { user: null, reason: "wrong_password" };
  return {
    user: { id: user.id, email: user.email, tier: user.tier, role: user.role },
    reason: null,
  };
}

function getUserById(id) {
  const user = db
    .prepare(
      "SELECT id, email, tier, tier_expires_at, role, rustdesk_id, is_active, created_at FROM users WHERE id = ?"
    )
    .get(id);
  return user || null;
}

function getUserByEmail(email) {
  return db.prepare("SELECT * FROM users WHERE email = ?").get(email) || null;
}

function setRustdeskId(userId, rustdeskId) {
  db.prepare("UPDATE users SET rustdesk_id = ? WHERE id = ?").run(rustdeskId, userId);
}

/**
 * RemoteSupport: tier ayarlar. tier='pro' verilirse ve months belirtilirse
 * tier_expires_at = simdi + months ay olarak hesaplanir. tier='free'
 * verilirse tier_expires_at NULL'a cekilir (pro suresi anlami kalmaz).
 */
function setTier(userId, tier, months = null) {
  if (tier === "pro" && months) {
    const expiresAt = new Date();
    expiresAt.setMonth(expiresAt.getMonth() + Number(months));
    db.prepare("UPDATE users SET tier = ?, tier_expires_at = ? WHERE id = ?").run(
      tier,
      expiresAt.toISOString(),
      userId
    );
  } else if (tier === "free") {
    db.prepare("UPDATE users SET tier = 'free', tier_expires_at = NULL WHERE id = ?").run(
      userId
    );
  } else {
    db.prepare("UPDATE users SET tier = ? WHERE id = ?").run(tier, userId);
  }
}

function setActive(userId, isActive) {
  db.prepare("UPDATE users SET is_active = ? WHERE id = ?").run(isActive ? 1 : 0, userId);
}

// --- Email dogrulama ---
function createEmailVerification(userId) {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  db.prepare(`
    INSERT INTO email_verifications (user_id, code, expires_at) VALUES (?, ?, ?)
  `).run(userId, code, expiresAt);
  return code;
}

function verifyEmailCode(userId, code) {
  const row = db.prepare(`
    SELECT * FROM email_verifications
    WHERE user_id = ? AND code = ? AND used = 0
    ORDER BY id DESC LIMIT 1
  `).get(userId, code);

  if (!row) return { success: false, reason: "invalid_code" };
  if (new Date(row.expires_at) < new Date()) return { success: false, reason: "expired" };

  db.prepare(`UPDATE email_verifications SET used = 1 WHERE id = ?`).run(row.id);
  db.prepare(`UPDATE users SET email_verified = 1 WHERE id = ?`).run(userId);
  return { success: true };
}

function isEmailVerified(userId) {
  const row = db.prepare("SELECT email_verified FROM users WHERE id = ?").get(userId);
  return !!(row && row.email_verified);
}

// --- Sifremi unuttum (kod tabanli) ---
function createPasswordReset(userId) {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
  db.prepare(`
    INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)
  `).run(userId, code, expiresAt);
  return code;
}

async function resetPasswordWithToken(userId, code, newPassword) {
  const row = db.prepare(`
    SELECT * FROM password_resets
    WHERE user_id = ? AND token = ? AND used = 0
    ORDER BY id DESC LIMIT 1
  `).get(userId, code);

  if (!row) return { success: false, reason: "invalid_code" };
  if (new Date(row.expires_at) < new Date()) return { success: false, reason: "expired" };

  const passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
  db.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`).run(passwordHash, userId);
  db.prepare(`UPDATE password_resets SET used = 1 WHERE id = ?`).run(row.id);
  return { success: true };
}

module.exports = {
  createUser,
  verifyUser,
  getUserById,
  getUserByEmail,
  setRustdeskId,
  setTier,
  setActive,
  createEmailVerification,
  verifyEmailCode,
  isEmailVerified,
  createPasswordReset,
  resetPasswordWithToken,
};