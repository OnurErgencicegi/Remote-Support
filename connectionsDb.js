// src/connectionsDb.js
//
// RemoteSupport: bir controller'ın bir host'a (RustDesk peer ID'sine)
// bağlanma hakkını yönetir.
//
// GÜNCEL KURAL: "bir kez bağlan, bir daha asla" YOK artık.
// Bunun yerine: her bağlantı 30 dakikalık bir oturumdur. Süre dolunca
// client bağlantıyı otomatik kapatır ve kullanıcıya "free tier limitine
// ulaştınız, tier yükseltin veya tekrar bağlanın" mesajı gösterir.
//
// GÜVENLİK GÜNCELLEMESİ: artık her oturum için rastgele bir conn_token
// üretiliyor. Bu token, hbbs (rendezvous_server.rs, patch'lenmiş sürüm)
// tarafından, gerçek bağlantı (punch hole) isteği geldiğinde bu sunucuya
// (POST /connections/verify-token) sorulup doğrulanıyor. Böylece
// ConnectionGuard client-side kontrolü bypass edilse bile (örn. orijinal
// RustDesk client'ı ile bağlanmaya çalışılırsa), hbbs bu token'ı bilmeyen
// isteği en baştan reddeder.

const crypto = require("crypto");
const { db } = require("./db");

const SESSION_DURATION_MS = 30 * 60 * 1000; // 30 dakika

function generateToken() {
  return crypto.randomBytes(24).toString("hex");
}

/**
 * Bir controller'ın bir host'a bağlanma isteğini değerlendirir.
 * Her zaman allowed:true döner (free tier için kalıcı engelleme yok);
 * ileride tier bazlı kısıtlama eklenirse burada allowed:false dönebilecek
 * ek kontroller eklenebilir.
 */
function startConnection(controllerUserId, hostPeerId) {
  const existing = db
    .prepare(
      `SELECT * FROM connections WHERE controller_user_id = ? AND host_peer_id = ?`
    )
    .get(controllerUserId, hostPeerId);

  const now = Date.now();

  if (existing) {
    const stillActive = new Date(existing.expires_at).getTime() > now;

    if (stillActive) {
      // Mevcut oturum hâlâ geçerli - aynı token/expiresAt'i döndür.
      return {
        allowed: true,
        expiresAt: existing.expires_at,
        connToken: existing.conn_token,
        renewed: false,
      };
    }

    // Süresi dolmuş - yeni bir 30dk'lık oturum + yeni token.
    const newExpiresAt = new Date(now + SESSION_DURATION_MS).toISOString();
    const newToken = generateToken();
    db.prepare(
      `UPDATE connections SET expires_at = ?, conn_token = ?, started_at = CURRENT_TIMESTAMP WHERE id = ?`
    ).run(newExpiresAt, newToken, existing.id);
    return {
      allowed: true,
      expiresAt: newExpiresAt,
      connToken: newToken,
      renewed: true,
    };
  }

  // Hiç kayıt yok - ilk oturumu oluştur.
  const expiresAt = new Date(now + SESSION_DURATION_MS).toISOString();
  const token = generateToken();
  db.prepare(
    `INSERT INTO connections (controller_user_id, host_peer_id, expires_at, conn_token)
     VALUES (?, ?, ?, ?)`
  ).run(controllerUserId, hostPeerId, expiresAt, token);

  return { allowed: true, expiresAt, connToken: token, renewed: false };
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

/**
 * RemoteSupport: hbbs'in doğrudan çağırdığı doğrulama fonksiyonu.
 * Token, ilgili host_peer_id için kayıtlı olmalı VE süresi dolmamış olmalı.
 */
function verifyConnToken(token, hostPeerId) {
  if (!token || !hostPeerId) return false;

  const row = db
    .prepare(
      `SELECT * FROM connections WHERE conn_token = ? AND host_peer_id = ?`
    )
    .get(token, hostPeerId);

  if (!row) return false;

  const stillActive = new Date(row.expires_at).getTime() > Date.now();
  return stillActive;
}

module.exports = {
  startConnection,
  getConnectionStatus,
  verifyConnToken,
  SESSION_DURATION_MS,
};