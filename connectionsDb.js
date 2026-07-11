// src/connectionsDb.js
//
// RemoteSupport: bir controller'ın bir host'a (RustDesk peer ID'sine)
// bağlanma hakkını yönetir.
//
// GÜNCEL KURAL: "bir kez bağlan, bir daha asla" YOK artık.
// Bunun yerine: her bağlantı 30 dakikalık bir oturumdur. Süre dolunca
// client bağlantıyı otomatik kapatır ve kullanıcıya "free tier limitine
// ulaştınız, tier yükseltin veya tekrar bağlanın" mesajı gösterir.
// Kullanıcı istediği zaman tekrar "Bağlan"a basıp yeni bir 30dk'lık
// oturum başlatabilir - kalıcı bir engelleme yok (free tier için).
//
// - Kayıt yoksa: yeni satır oluşturulur, expires_at = now + 30dk.
// - Kayıt var ve süresi DOLMAMIŞSA: aynı expires_at aynen döner
//   (idempotent - örn. client bağlantı koptuktan hemen sonra tekrar
//   "Bağlan"a bastıysa, aynı oturumun kalan süresini kullanır).
// - Kayıt var ve süresi DOLMUŞSA: satır güncellenir (yenilenir),
//   expires_at = now + 30dk yeni bir oturum olarak başlar.

const { db } = require("./db");

const SESSION_DURATION_MS = 30 * 60 * 1000; // 30 dakika

/**
 * Bir controller'ın bir host'a bağlanma isteğini değerlendirir.
 * Her zaman allowed:true döner (free tier için kalıcı engelleme yok);
 * ileride tier bazlı kısıtlama eklenirse (örn. eş zamanlı bağlantı
 * limiti, aylık bağlantı sayısı) burada allowed:false dönebilecek
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
      // Mevcut oturum hâlâ geçerli - aynen döndür (yeni süre başlatma).
      return { allowed: true, expiresAt: existing.expires_at, renewed: false };
    }

    // Süresi dolmuş - yeni bir 30dk'lık oturum olarak yenile.
    const newExpiresAt = new Date(now + SESSION_DURATION_MS).toISOString();
    db.prepare(
      `UPDATE connections SET expires_at = ?, started_at = CURRENT_TIMESTAMP WHERE id = ?`
    ).run(newExpiresAt, existing.id);
    return { allowed: true, expiresAt: newExpiresAt, renewed: true };
  }

  // Hiç kayıt yok - ilk oturumu oluştur.
  const expiresAt = new Date(now + SESSION_DURATION_MS).toISOString();
  db.prepare(
    `INSERT INTO connections (controller_user_id, host_peer_id, expires_at)
     VALUES (?, ?, ?)`
  ).run(controllerUserId, hostPeerId, expiresAt);

  return { allowed: true, expiresAt, renewed: false };
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