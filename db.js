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

// RemoteSupport: connections tablosu daha once elle/migration ile
// olusturulmustu, repoda hic CREATE TABLE'i yoktu - guvenlik icin burada
// da tanimliyoruz (IF NOT EXISTS, mevcut VPS verisine dokunmaz).
db.exec(`
  CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    controller_user_id INTEGER NOT NULL,
    host_peer_id TEXT NOT NULL,
    started_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    conn_token TEXT,
    UNIQUE(controller_user_id, host_peer_id)
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
try {
  // RemoteSupport: pro tier'in ne zaman bitecegini tutar. NULL = pro
  // degil / suresiz degil. tier='pro' VE tier_expires_at gelecekte ise
  // kullanici gercekten aktif pro sayilir (bkz. connectionsDb.js
  // isProActive()).
  db.exec(`ALTER TABLE users ADD COLUMN tier_expires_at TEXT`);
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

// RemoteSupport: free tier'in aylik 4 saat (240dk) kullanim tavanini takip
// etmek icin. connections tablosu ayni (user,host) ciftinde UPDATE ile
// uzerine yazildigi icin gecmis kullanim orada kaybolur - bu yuzden ayri,
// sadece INSERT edilen (hic UPDATE edilmeyen) bir log tablosu gerekiyor.
// Her yeni 30dk'lik oturum bloğu basladiginda (ilk baglanti ya da suresi
// dolup yenilenen baglanti) buraya bir satir eklenir.
db.exec(`
  CREATE TABLE IF NOT EXISTS usage_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    controller_user_id INTEGER NOT NULL,
    host_peer_id TEXT NOT NULL,
    minutes INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

module.exports = { db, logLoginAttempt, getHostPassword, setHostPassword };