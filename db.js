// src/db.js
const path = require("path");
const Database = require("better-sqlite3");
const DB_PATH = path.join(__dirname, "data", "auth.db");
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    tier TEXT NOT NULL DEFAULT 'free',
    role TEXT NOT NULL DEFAULT 'controller',
    rustdesk_id TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER NOT NULL DEFAULT 1
  );
`);
try {
  db.exec(`ALTER TABLE connections ADD COLUMN conn_token TEXT`);
} catch (e) {
  // Sutun zaten varsa sessizce gec.
}
try {
  db.exec(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'controller'`);
} catch (e) {
  // duplicate column bekleniyor, sorun degil.
}
try {
  db.exec(`ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0`);
} catch (e) {
  // duplicate column bekleniyor, sorun degil.
}
db.exec(`
  CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    email TEXT,
    success INTEGER NOT NULL,
    ip_address TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);
function logLoginAttempt(userId, email, success, ipAddress) {
  const stmt = db.prepare(`
    INSERT INTO login_logs (user_id, email, success, ip_address)
    VALUES (?, ?, ?, ?)
  `);
  stmt.run(userId, email, success ? 1 : 0, ipAddress || null);
}
db.exec(`
  CREATE TABLE IF NOT EXISTS host_passwords (
    host_id TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);
function getHostPassword(hostId) {
  const row = db
    .prepare(`SELECT password FROM host_passwords WHERE host_id = ?`)
    .get(hostId);
  return row ? row.password : null;
}
function setHostPassword(hostId, password) {
  db.prepare(
    `
    INSERT INTO host_passwords (host_id, password, updated_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(host_id) DO UPDATE SET
      password = excluded.password,
      updated_at = CURRENT_TIMESTAMP
  `
  ).run(hostId, password);
}
db.exec(`
  CREATE TABLE IF NOT EXISTS email_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
  );
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
  );
`);
module.exports = { db, logLoginAttempt, getHostPassword, setHostPassword };
