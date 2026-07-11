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
// RemoteSupport: conn_token sütunu, hbbs'in doğrudan (Node.js'e sorarak)
// doğruladığı, tek bağlantıya özel kısa ömürlü bir tokendır.
try {
  db.exec(`ALTER TABLE connections ADD COLUMN conn_token TEXT`);
} catch (e) {
  // Sütun zaten varsa (SQLITE_ERROR: duplicate column) sessizce geç.
}
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

module.exports = { db, logLoginAttempt };