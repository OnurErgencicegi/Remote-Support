// src/connectionsDb.js
//
// RemoteSupport: bir controller'ın bir host'a (RustDesk peer ID'sine)
// bağlanma hakkını yönetir.
//
// Kural 1 (tekrar bağlanamama): connections tablosundaki
// UNIQUE(controller_user_id, host_peer_id) kısıtı sayesinde, bir controller
// aynı host'a ikinci kez "başlangıç" kaydı oluşturamaz - INSERT ikinci
// denemede çakışma hatası verir, biz bunu "zaten bağlanılmış" olarak
// yorumluyoruz.
//
// Kural 2 (30 dakika süre sınırı): İlk bağlanma anında expires_at
// (now + 30dk) yazılır. Client, bağlantı süresince periyodik olarak
// getConnectionStatus() sonucunu (status endpoint üzerinden) kontrol eder;
// expires_at geçtiyse bağlantıyı kendi tarafında kapatır.

const { db } = require("./db");

const SESSION_DURATION_MS = 30 * 60 * 1000; // 30 dakika

/**
 * Bir controller'ın bir host'a bağlanma isteğini değerlendirir.
 * - Daha önce hiç bağlanılmamışsa: yeni kayıt oluşturur, expires_at now+30dk.
 * - Daha önce bağlanılmışsa: reddeder (allowed:false), sebep olarak
 *   "already_used" döner - süresi dolmuş olsun olmasın fark etmez, kural
 *   "bir kez ve bir daha asla" şeklindedir.
 */
function startConnection(controllerUserId, hostPeerId) {
  const existing = db
    .prepare(
      `SELECT * FROM connections WHERE controller_user_id = ? AND host_peer_id = ?`
    )
    .get(controllerUserId, hostPeerId);

  if (existing) {
    return {
      allowed: false,
      reason: "already_used",
      expiresAt: existing.expires_at,
    };
  }

  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS).toISOString();
  db.prepare(
    `INSERT INTO connections (controller_user_id, host_peer_id, expires_at)
     VALUES (?, ?, ?)`
  ).run(controllerUserId, hostPeerId, expiresAt);

  return { allowed: true, expiresAt };
}

/**
 * Devam eden bir bağlantının süresi dolmuş mu diye kontrol için kullanılır
 * (client periyodik olarak sorar).
 */
function getConnectionStatus(controllerUserId, hostPeerId) {
  const row = db
    .prepare(
      `SELECT * FROM connections WHERE controller_user_id = ? AND host_peer_id = ?`
    )
    .get(controllerUserId, hostPeerId);

  if (!row) {
    return { found: false };
  }

  const expired = new Date(row.expires_at).getTime() < Date.now();
  return { found: true, expiresAt: row.expires_at, expired };
}

module.exports = { startConnection, getConnectionStatus, SESSION_DURATION_MS };