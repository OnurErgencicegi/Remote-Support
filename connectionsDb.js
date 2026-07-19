// src/connectionsDb.js
//
// RemoteSupport: bir controller'ın bir host'a (RustDesk peer ID'sine)
// bağlanma hakkını yönetir.
//
// GÜNCEL KURAL: "bir kez bağlan, bir daha asla" YOK artık.
// Bunun yerine: her bağlantı 30 dakikalık bir oturumdur.
//
// GÜVENLİK GÜNCELLEMESİ: her oturum için rastgele bir conn_token üretiliyor,
// hbbs (patch'lenmiş) bu token'ı POST /connections/verify-token ile
// doğruluyor.
//
// TIER GÜNCELLEMESİ (bu değişiklik):
// - free tier: aynı anda sadece 1 host'a bağlı olabilir + aylık toplam
//   240 dakika (4 saat) kullanım tavanı var. İkisinden biri aşılırsa
//   yeni bağlantı reddedilir (allowed:false, reason ile).
// - pro tier (tier='pro' VE tier_expires_at gelecekte): bu kısıtlamalardan
//   muaf, sınırsız bağlantı/süre.
// - Kullanım, usage_log tablosuna SADECE yeni bir 30dk'lık blok
//   başladığında (ilk bağlantı ya da süresi dolup yenilenen bağlantı)
//   loglanıyor - aynı aktif oturuma tekrar "start" çağrısı yapılırsa
//   (renewed:false, halihazırda aktif) tekrar loglanmıyor. Bu, blok
//   bazlı bir muhasebe (kullanıcı 30dk'nın tamamını kullanmasa bile o
//   blok "harcanmış" sayılır) - ürün kararına uygun basit bir model.

const crypto = require("crypto");
const { db } = require("./db");

const SESSION_DURATION_MS = 30 * 60 * 1000; // 30 dakika
const FREE_MONTHLY_CAP_MINUTES = 240; // 4 saat

function generateToken() {
  return crypto.randomBytes(24).toString("hex");
}

/**
 * tier='pro' VE tier_expires_at gelecekte ise true. tier_expires_at
 * geçmişse (süresi dolmuşsa) ya da NULL ise false döner - bu durumda
 * kullanıcı free kısıtlamalarına tabi olur (etikette hâlâ "pro" yazsa
 * bile, admin panelde "süresi doldu" olarak gösterilir).
 */
function isProActive(user) {
  if (!user || user.tier !== "pro") return false;
  if (!user.tier_expires_at) return false;
  return new Date(user.tier_expires_at).getTime() > Date.now();
}

/**
 * Bu ay (takvim ayı, UTC) şu ana kadar loglanan toplam dakikayı döner.
 */
function getMonthlyUsageMinutes(controllerUserId) {
  const row = db
    .prepare(
      `SELECT COALESCE(SUM(minutes), 0) as total
       FROM usage_log
       WHERE controller_user_id = ?
         AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')`
    )
    .get(controllerUserId);
  return row.total;
}

function logUsage(controllerUserId, hostPeerId, minutes) {
  db.prepare(
    `INSERT INTO usage_log (controller_user_id, host_peer_id, minutes) VALUES (?, ?, ?)`
  ).run(controllerUserId, hostPeerId, minutes);
}

/**
 * Bir controller'ın bir host'a bağlanma isteğini değerlendirir.
 */
function startConnection(controllerUserId, hostPeerId) {
  const user = db
    .prepare(`SELECT tier, tier_expires_at FROM users WHERE id = ?`)
    .get(controllerUserId);
  const proActive = isProActive(user);

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
      // YENİ KULLANIM LOGLANMAZ (aynı blok devam ediyor).
      return {
        allowed: true,
        expiresAt: existing.expires_at,
        connToken: existing.conn_token,
        renewed: false,
      };
    }

    // Süresi dolmuş - yeni bir blok başlatılacak, önce tier kontrolleri.
    if (!proActive) {
      const denyReason = checkFreeLimits(controllerUserId, hostPeerId, now);
      if (denyReason) return denyReason;
    }

    const newExpiresAt = new Date(now + SESSION_DURATION_MS).toISOString();
    const newToken = generateToken();
    db.prepare(
      `UPDATE connections SET expires_at = ?, conn_token = ?, started_at = CURRENT_TIMESTAMP WHERE id = ?`
    ).run(newExpiresAt, newToken, existing.id);
    logUsage(controllerUserId, hostPeerId, SESSION_DURATION_MS / 60000);
    return {
      allowed: true,
      expiresAt: newExpiresAt,
      connToken: newToken,
      renewed: true,
    };
  }

  // Hiç kayıt yok - ilk oturum, yeni bir blok. Önce tier kontrolleri.
  if (!proActive) {
    const denyReason = checkFreeLimits(controllerUserId, hostPeerId, now);
    if (denyReason) return denyReason;
  }

  const expiresAt = new Date(now + SESSION_DURATION_MS).toISOString();
  const token = generateToken();
  db.prepare(
    `INSERT INTO connections (controller_user_id, host_peer_id, expires_at, conn_token)
     VALUES (?, ?, ?, ?)`
  ).run(controllerUserId, hostPeerId, expiresAt, token);
  logUsage(controllerUserId, hostPeerId, SESSION_DURATION_MS / 60000);

  return { allowed: true, expiresAt, connToken: token, renewed: false };
}

/**
 * Free tier kısıtlamalarını kontrol eder. Sorun yoksa null, sorun varsa
 * startConnection'ın dönebileceği formatta bir "denied" objesi döner.
 */
function checkFreeLimits(controllerUserId, hostPeerId, nowMs) {
  // 1) Eş zamanlı tek host kısıtı: BAŞKA bir host'a aktif bağlantısı var mı?
  const otherActive = db
    .prepare(
      `SELECT host_peer_id, expires_at FROM connections
       WHERE controller_user_id = ? AND host_peer_id != ? AND expires_at > ?`
    )
    .get(controllerUserId, hostPeerId, new Date(nowMs).toISOString());

  if (otherActive) {
    return {
      allowed: false,
      reason: "concurrent_limit",
      activeHostPeerId: otherActive.host_peer_id,
      expiresAt: otherActive.expires_at,
    };
  }

  // 2) Aylık 240dk tavanı
  const usedMinutes = getMonthlyUsageMinutes(controllerUserId);
  if (usedMinutes >= FREE_MONTHLY_CAP_MINUTES) {
    return {
      allowed: false,
      reason: "monthly_limit",
      usedMinutes,
      capMinutes: FREE_MONTHLY_CAP_MINUTES,
    };
  }

  return null;
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
  getMonthlyUsageMinutes,
  isProActive,
  SESSION_DURATION_MS,
  FREE_MONTHLY_CAP_MINUTES,
};