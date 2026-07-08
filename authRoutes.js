// src/authRoutes.js
const express = require("express");
const jwt = require("jsonwebtoken");
const { createUser, verifyUser, getUserById, setRustdeskId } = require("./authDb");
const { logLoginAttempt } = require("./db");
const logger = require("./logger");

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  logger.warn(
    "JWT_SECRET ortam değişkeni tanımlı değil! Geçici/güvensiz bir anahtar kullanılıyor. " +
      "Production'da mutlaka JWT_SECRET set edin."
  );
}
const SECRET = JWT_SECRET || "GELISTIRME-ICIN-GECICI-ANAHTAR-degistir";
const TOKEN_EXPIRY = "30d";

function signToken(user) {
  return jwt.sign(
    { userId: user.id, email: user.email, tier: user.tier, role: user.role },
    SECRET,
    { expiresIn: TOKEN_EXPIRY }
  );
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// --- Kayıt ol ---
router.post("/register", async (req, res) => {
  try {
    const { email, password, role } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: "Email ve parola gerekli." });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Geçerli bir email girin." });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Parola en az 6 karakter olmalı." });
    }
    if (role && role !== "host" && role !== "controller") {
      return res.status(400).json({ error: "Geçersiz rol." });
    }

    const user = await createUser(email.toLowerCase().trim(), password, role);
    const token = signToken(user);

    logger.info(`Yeni kullanıcı kaydoldu: ${user.email} (${user.role})`);
    res.json({ token, user: { email: user.email, tier: user.tier, role: user.role } });
  } catch (err) {
    logger.error("Register hatası:", err.message);
    res.status(400).json({ error: err.message });
  }
});

// --- Giriş yap ---
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: "Email ve parola gerekli." });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const { user, reason } = await verifyUser(normalizedEmail, password);

    logLoginAttempt(user ? user.id : null, normalizedEmail, !!user, req.ip);

    if (!user) {
      // Hangi sebeple başarısız olduğunu detaylandırmıyoruz (email var mı yok mu
      // sızdırmamak için) - kullanıcıya tek tip mesaj dönüyoruz.
      return res.status(401).json({ error: "Email veya parola hatalı." });
    }

    const token = signToken(user);
    logger.info(`Giriş yapıldı: ${user.email} (${user.role})`);
    res.json({ token, user: { email: user.email, tier: user.tier, role: user.role } });
  } catch (err) {
    logger.error("Login hatası:", err.message);
    res.status(500).json({ error: "Sunucu hatası." });
  }
});

// --- Token doğrulama middleware'i ---
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token gerekli." });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token geçersiz veya süresi dolmuş." });
  }
}

// --- Giriş yapmış kullanıcının kendi bilgisini görmesi ---
router.get("/me", requireAuth, (req, res) => {
  const user = getUserById(req.user.userId);
  if (!user) return res.status(404).json({ error: "Kullanıcı bulunamadı." });
  res.json({
    email: user.email,
    tier: user.tier,
    role: user.role,
    rustdeskId: user.rustdesk_id,
    isActive: !!user.is_active,
    createdAt: user.created_at,
  });
});

// --- Kullanıcının kendi RustDesk ID'sini kaydetmesi (launcher tarafından çağrılacak) ---
router.post("/me/rustdesk-id", requireAuth, (req, res) => {
  const { rustdeskId } = req.body || {};
  if (!rustdeskId) {
    return res.status(400).json({ error: "rustdeskId gerekli." });
  }
  setRustdeskId(req.user.userId, rustdeskId);
  res.json({ success: true });
});

module.exports = { router, requireAuth };
