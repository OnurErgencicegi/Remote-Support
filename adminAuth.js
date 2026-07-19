// adminAuth.js
//
// RemoteSupport - basit admin oturum katmanı. Kalıcı kullanıcı sistemi
// eklemeden (henüz "admin" rolü yok), tek bir sabit şifre + rastgele
// oturum token'ı ile çalışır. Token'lar bellekte (Map) tutulur - sunucu
// yeniden başlarsa herkes tekrar login olmalı, bu kabul edilebilir bir
// trade-off (admin panel, kritik olmayan bir iç araç).

const crypto = require("crypto");

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme123";
const SESSION_DURATION_MS = 12 * 60 * 60 * 1000; // 12 saat

// token -> { createdAt }
const sessions = new Map();

function createSession() {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { createdAt: Date.now() });
  return token;
}

function isValidSession(token) {
  if (!token) return false;
  const session = sessions.get(token);
  if (!session) return false;
  if (Date.now() - session.createdAt > SESSION_DURATION_MS) {
    sessions.delete(token);
    return false;
  }
  return true;
}

function checkPassword(password) {
  return password === ADMIN_PASSWORD;
}

// Express middleware - "Authorization: Bearer <token>" header'ını kontrol eder.
function requireAdmin(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : null;

  if (!isValidSession(token)) {
    return res.status(401).json({ error: "Yetkisiz. Lütfen tekrar giriş yapın." });
  }
  next();
}

module.exports = { createSession, checkPassword, requireAdmin };