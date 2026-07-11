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

// Var olan (eski) veritabanlarında 'role' kolonu yoksa ekle.
// Zaten varsa SQLite hata fırlatır, onu görmezden geliyoruz.
try {
  db.exec(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'controller'`);
} catch (e) {
  // "duplicate column name" bekleniyor, sorun değil.
}

// Basit oturum/giriş logu - ileride denetim için faydalı
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

// RemoteSupport: controller <-> host bağlantı kullanım kaydı.
// Amaç: (a) bir controller bir host'a en fazla bir kez bağlanabilsin
// (aynı ikili tekrar eşleşemez), (b) her bağlantının 30 dakikalık bir
// süre sınırı olsun (expires_at). UNIQUE(controller_user_id, host_peer_id)
// sayesinde aynı ikili için ikinci bir satır oluşturulamaz - bu, "tekrar
// bağlanamama" kuralını veritabanı seviyesinde garanti eder.
db.exec(`
  CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    controller_user_id INTEGER NOT NULL,
    host_peer_id TEXT NOT NULL,
    started_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    UNIQUE(controller_user_id, host_peer_id)
  );
`);

module.exports = { db, logLoginAttempt };