// adminRoutes.js
//
// RemoteSupport - admin panel API'leri. /admin altında mount edilir
// (server.js'de app.use("/admin", adminRouter)).
//
// NOT: tier sistemi henüz implement edilmedi (bkz. YAMALAR_README.md açık
// TODO'su). users tablosunda tier kolonu yoksa otomatik eklenir (db.js
// patch'i, bkz. 0-db-tier-migration.md) ve her kullanıcı için 'free'
// varsayılan değeri gösterilir - eksik kolon yüzünden hata FIRLATILMAZ.

const express = require("express");
const os = require("os");
const { db } = require("./db");
const { createSession, checkPassword, requireAdmin } = require("./adminAuth");
const { setTier } = require("./authDb");
const { getMonthlyUsageMinutes, isProActive, FREE_MONTHLY_CAP_MINUTES } = require("./connectionsDb");

const router = express.Router();

// --- Login (auth gerektirmez) ---
router.post("/login", (req, res) => {
  const { password } = req.body || {};
  if (!checkPassword(password)) {
    return res.status(401).json({ error: "Şifre hatalı." });
  }
  const token = createSession();
  return res.json({ token });
});

// --- Aşağıdaki tüm route'lar admin oturumu gerektirir ---
router.use(requireAdmin);

// GET /admin/users?search=email_veya_id_parcasi
router.get("/users", (req, res) => {
  try {
    const search = (req.query.search || "").trim();
    let rows;
    if (search) {
      rows = db
        .prepare(
          `SELECT id, email, role, email_verified, created_at,
                  COALESCE(tier, 'free') as tier, tier_expires_at
           FROM users
           WHERE email LIKE ?
           ORDER BY created_at DESC`
        )
        .all(`%${search}%`);
    } else {
      rows = db
        .prepare(
          `SELECT id, email, role, email_verified, created_at,
                  COALESCE(tier, 'free') as tier, tier_expires_at
           FROM users
           ORDER BY created_at DESC`
        )
        .all();
    }
    // RemoteSupport: her kullanıcı için gerçekten aktif pro mu (süresi
    // dolmamış mı) bilgisini ekliyoruz - client tarafında "Pro" etiketi
    // gösterip gösterilmeyeceğine bunun üzerinden karar veriliyor.
    const enriched = rows.map((u) => ({
      ...u,
      proActive: isProActive(u),
    }));
    return res.json({ users: enriched });
  } catch (err) {
    console.error("admin/users hata:", err.message);
    return res.status(500).json({ error: "Sunucu hatası." });
  }
});

// POST /admin/users/:id/set-tier { tier: 'free'|'pro', months?: number }
// tier='pro' ise months zorunlu (kaç ay pro verileceği). tier='free' ise
// months yok sayılır, pro süresi hemen temizlenir.
router.post("/users/:id/set-tier", (req, res) => {
  try {
    const userId = req.params.id;
    const { tier, months } = req.body || {};

    if (tier !== "free" && tier !== "pro") {
      return res.status(400).json({ error: "tier 'free' veya 'pro' olmalı." });
    }
    if (tier === "pro" && (!months || Number(months) <= 0)) {
      return res.status(400).json({ error: "Pro için months (1 veya üzeri) gerekli." });
    }

    setTier(userId, tier, tier === "pro" ? Number(months) : null);
    return res.json({ success: true });
  } catch (err) {
    console.error("admin/users/:id/set-tier hata:", err.message);
    return res.status(500).json({ error: "Sunucu hatası." });
  }
});

// GET /admin/users/:id - tek kullanıcının tier + kullanım özeti
router.get("/users/:id", (req, res) => {
  try {
    const userId = req.params.id;
    const user = db
      .prepare(
        `SELECT id, email, role, email_verified, created_at,
                COALESCE(tier, 'free') as tier, tier_expires_at
         FROM users WHERE id = ?`
      )
      .get(userId);

    if (!user) {
      return res.status(404).json({ error: "Kullanıcı bulunamadı." });
    }

    const usedMinutesThisMonth = getMonthlyUsageMinutes(userId);

    return res.json({
      ...user,
      proActive: isProActive(user),
      usedMinutesThisMonth,
      capMinutes: FREE_MONTHLY_CAP_MINUTES,
    });
  } catch (err) {
    console.error("admin/users/:id hata:", err.message);
    return res.status(500).json({ error: "Sunucu hatası." });
  }
});

// GET /admin/connections?user=&host=&from=&to=&page=1&pageSize=50
// user: email parçası (LIKE), host: host_peer_id parçası (LIKE)
// from/to: ISO tarih (started_at aralığı)
router.get("/connections", (req, res) => {
  try {
    const { user, host, from, to, activeOnly } = req.query;
    const page = Math.max(1, parseInt(req.query.page || "1", 10));
    const pageSize = Math.min(
      200,
      Math.max(1, parseInt(req.query.pageSize || "50", 10))
    );
    const offset = (page - 1) * pageSize;

    const conditions = [];
    const params = [];

    if (user) {
      conditions.push("u.email LIKE ?");
      params.push(`%${user}%`);
    }
    if (host) {
      conditions.push("c.host_peer_id LIKE ?");
      params.push(`%${host}%`);
    }
    if (from) {
      conditions.push("c.started_at >= ?");
      params.push(from);
    }
    if (to) {
      conditions.push("c.started_at <= ?");
      params.push(to);
    }
    if (activeOnly === "1" || activeOnly === "true") {
      // RemoteSupport: datetime() ile normalize - expires_at ISO 8601,
      // datetime('now') SQLite format, dogrudan karsilastirma hatali olur.
      conditions.push("datetime(c.expires_at) > datetime('now')");
    }

    const whereClause = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

    const rows = db
      .prepare(
        `SELECT c.id, c.host_peer_id, c.started_at, c.expires_at,
                u.email as controller_email,
                COALESCE(u.tier, 'free') as controller_tier
         FROM connections c
         JOIN users u ON u.id = c.controller_user_id
         ${whereClause}
         ORDER BY c.started_at DESC
         LIMIT ? OFFSET ?`
      )
      .all(...params, pageSize, offset);

    const totalRow = db
      .prepare(
        `SELECT COUNT(*) as cnt
         FROM connections c
         JOIN users u ON u.id = c.controller_user_id
         ${whereClause}`
      )
      .get(...params);

    const now = Date.now();
    const enriched = rows.map((r) => {
      const startedMs = new Date(r.started_at).getTime();
      const expiresMs = new Date(r.expires_at).getTime();
      return {
        ...r,
        active: expiresMs > now,
        // dakika cinsinden planlanan oturum süresi (started -> expires)
        durationMinutes: Math.round((expiresMs - startedMs) / 60000),
      };
    });

    return res.json({
      connections: enriched,
      total: totalRow.cnt,
      page,
      pageSize,
    });
  } catch (err) {
    console.error("admin/connections hata:", err.message);
    return res.status(500).json({ error: "Sunucu hatası." });
  }
});

// GET /admin/users/:id/connections - belirli bir kullanıcının tüm bağlantı geçmişi
router.get("/users/:id/connections", (req, res) => {
  try {
    const userId = req.params.id;
    const rows = db
      .prepare(
        `SELECT c.id, c.host_peer_id, c.started_at, c.expires_at
         FROM connections c
         WHERE c.controller_user_id = ?
         ORDER BY c.started_at DESC`
      )
      .all(userId);

    const now = Date.now();
    const enriched = rows.map((r) => {
      const startedMs = new Date(r.started_at).getTime();
      const expiresMs = new Date(r.expires_at).getTime();
      return {
        ...r,
        active: expiresMs > now,
        durationMinutes: Math.round((expiresMs - startedMs) / 60000),
      };
    });

    return res.json({ connections: enriched });
  } catch (err) {
    console.error("admin/users/:id/connections hata:", err.message);
    return res.status(500).json({ error: "Sunucu hatası." });
  }
});

// GET /admin/stats - üstte özet kutucuklar için (toplam kullanıcı, aktif bağlantı sayısı)
router.get("/stats", (req, res) => {
  try {
    const totalUsers = db.prepare(`SELECT COUNT(*) as cnt FROM users`).get().cnt;
    const verifiedUsers = db
      .prepare(`SELECT COUNT(*) as cnt FROM users WHERE email_verified = 1`)
      .get().cnt;
    // RemoteSupport: expires_at ISO 8601 formatinda tutuluyor
    // (2026-07-19T10:15:00.000Z), datetime('now') ise "2026-07-19 10:15:00"
    // formatinda - duz metin karsilastirmasi 'T' vs bosluk yuzunden yanlis
    // sonuc verebiliyor. datetime(expires_at) ile normalize edip karsilastir.
    const activeConnections = db
      .prepare(`SELECT COUNT(*) as cnt FROM connections WHERE datetime(expires_at) > datetime('now')`)
      .get().cnt;
    const totalConnections = db.prepare(`SELECT COUNT(*) as cnt FROM connections`).get().cnt;

    return res.json({
      totalUsers,
      verifiedUsers,
      activeConnections,
      totalConnections,
    });
  } catch (err) {
    console.error("admin/stats hata:", err.message);
    return res.status(500).json({ error: "Sunucu hatası." });
  }
});

// GET /admin/system-stats - VPS'in anlık CPU/RAM kullanımı (Node'un
// yerleşik 'os' modülü, ek paket gerekmez).
router.get("/system-stats", (req, res) => {
  try {
    const totalMemBytes = os.totalmem();
    const freeMemBytes = os.freemem();
    const usedMemBytes = totalMemBytes - freeMemBytes;
    const memUsedPercent = Math.round((usedMemBytes / totalMemBytes) * 100);

    // RemoteSupport: os.loadavg() Linux'a özgü anlamlı deger dondurur
    // (1/5/15 dakikalik ortalama yuk), Windows'ta hep [0,0,0] doner -
    // VPS Linux oldugu icin sorun yok. cpuCount'a bolerek yuzdeye
    // yakin bir gosterge uretiyoruz (tam dogru CPU% degil, kaba bir
    // tahmin - kesin deger icin ornekleme arasi delta gerekir, panelin
    // amacina gore bu yeterli).
    const cpuCount = os.cpus().length;
    const load1 = os.loadavg()[0];
    const cpuLoadPercent = Math.min(100, Math.round((load1 / cpuCount) * 100));

    return res.json({
      cpuCount,
      cpuLoadPercent,
      memTotalMB: Math.round(totalMemBytes / 1024 / 1024),
      memUsedMB: Math.round(usedMemBytes / 1024 / 1024),
      memUsedPercent,
      uptimeSeconds: Math.round(os.uptime()),
    });
  } catch (err) {
    console.error("admin/system-stats hata:", err.message);
    return res.status(500).json({ error: "Sunucu hatası." });
  }
});

module.exports = { router };