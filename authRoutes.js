// src/authRoutes.js
const express = require("express");
const jwt = require("jsonwebtoken");
const { db, logLoginAttempt, getHostPassword, setHostPassword } = require("./db");
const {
  createUser,
  verifyUser,
  getUserById,
  setRustdeskId,
  createEmailVerification,
  verifyEmailCode,
  isEmailVerified,
  createPasswordReset,
  resetPasswordWithToken,
  getUserByEmail,
} = require("./authDb");
const { startConnection, getConnectionStatus, verifyConnToken } = require("./connectionsDb");
const { sendVerificationEmail, sendPasswordResetEmail } = require("./mail");
const logger = require("./logger");

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  logger.warn(
    "JWT_SECRET ortam degiskeni tanimli degil! Gecici/guvensiz bir anahtar kullaniliyor. " +
      "Production'da mutlaka JWT_SECRET set edin."
  );
}
const SECRET = JWT_SECRET || "GELISTIRME-ICIN-GECICI-ANAHTAR-degistir";
const TOKEN_EXPIRY = "30d";

const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY;
if (!INTERNAL_API_KEY) {
  logger.warn(
    "INTERNAL_API_KEY ortam degiskeni tanimli degil! /host/password endpoint'leri korumasiz kalacak."
  );
}

function internalKeyGuard(req, res, next) {
  const key = req.header("X-Internal-Key");
  if (!INTERNAL_API_KEY || key !== INTERNAL_API_KEY) {
    return res.status(401).json({ error: "Yetkisiz." });
  }
  next();
}

const _hostPwHits = new Map();
function hostPasswordLimiter(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  const windowMs = 60 * 1000;
  const maxHits = 20;
  const entry = _hostPwHits.get(ip);
  if (!entry || now - entry.windowStart > windowMs) {
    _hostPwHits.set(ip, { count: 1, windowStart: now });
    return next();
  }
  entry.count += 1;
  if (entry.count > maxHits) {
    return res.status(429).json({ error: "Cok fazla istek, lutfen bekleyin." });
  }
  next();
}

const _codeAttemptHits = new Map();
function codeAttemptLimiter(req, res, next) {
  const key = (req.body && (req.body.email || (req.user && req.user.email))) || req.ip;
  const now = Date.now();
  const windowMs = 60 * 1000;
  const maxHits = 10;
  const entry = _codeAttemptHits.get(key);
  if (!entry || now - entry.windowStart > windowMs) {
    _codeAttemptHits.set(key, { count: 1, windowStart: now });
    return next();
  }
  entry.count += 1;
  if (entry.count > maxHits) {
    return res.status(429).json({ error: "Cok fazla deneme, lutfen bekleyin." });
  }
  next();
}

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

router.post("/register", async (req, res) => {
  try {
    const { email, password, role } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: "Email ve parola gerekli." });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Gecerli bir email girin." });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Parola en az 6 karakter olmali." });
    }
    if (role && role !== "host" && role !== "controller") {
      return res.status(400).json({ error: "Gecersiz rol." });
    }

    const user = await createUser(email.toLowerCase().trim(), password, role);
    const token = signToken(user);

    const code = createEmailVerification(user.id);
    sendVerificationEmail(user.email, code).then((sent) => {
      if (!sent) logger.error("Dogrulama maili gonderilemedi: " + user.email);
    });

    logger.info("Yeni kullanici kaydoldu: " + user.email + " (" + user.role + ")");
    res.json({ token, user: { email: user.email, tier: user.tier, role: user.role } });
  } catch (err) {
    logger.error("Register hatasi:", err.message);
    res.status(400).json({ error: err.message });
  }
});

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
      return res.status(401).json({ error: "Email veya parola hatali." });
    }

    const token = signToken(user);
    logger.info("Giris yapildi: " + user.email + " (" + user.role + ")");
    res.json({ token, user: { email: user.email, tier: user.tier, role: user.role } });
  } catch (err) {
    logger.error("Login hatasi:", err.message);
    res.status(500).json({ error: "Sunucu hatasi." });
  }
});

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
    return res.status(401).json({ error: "Token gecersiz veya suresi dolmus." });
  }
}

router.get("/me", requireAuth, (req, res) => {
  const user = getUserById(req.user.userId);
  if (!user) return res.status(404).json({ error: "Kullanici bulunamadi." });
  res.json({
    email: user.email,
    tier: user.tier,
    role: user.role,
    rustdeskId: user.rustdesk_id,
    isActive: !!user.is_active,
    createdAt: user.created_at,
  });
});

router.post("/me/rustdesk-id", requireAuth, (req, res) => {
  const { rustdeskId } = req.body || {};
  if (!rustdeskId) {
    return res.status(400).json({ error: "rustdeskId gerekli." });
  }
  setRustdeskId(req.user.userId, rustdeskId);
  res.json({ success: true });
});

router.post("/verify-email", requireAuth, codeAttemptLimiter, (req, res) => {
  try {
    const { code } = req.body || {};
    if (!code) {
      return res.status(400).json({ error: "Kod gerekli." });
    }
    const result = verifyEmailCode(req.user.userId, String(code).trim());
    if (!result.success) {
      const messages = {
        invalid_code: "Kod hatali.",
        expired: "Kodun suresi dolmus, yeni kod isteyin.",
      };
      return res.status(400).json({ error: messages[result.reason] || "Dogrulama basarisiz." });
    }
    logger.info("Email dogrulandi: user=" + req.user.email);
    res.json({ success: true });
  } catch (err) {
    logger.error("verify-email hatasi:", err.message);
    res.status(500).json({ error: "Sunucu hatasi." });
  }
});

router.post("/resend-verification", requireAuth, codeAttemptLimiter, async (req, res) => {
  try {
    if (isEmailVerified(req.user.userId)) {
      return res.status(400).json({ error: "Email zaten dogrulanmis." });
    }
    const code = createEmailVerification(req.user.userId);
    const sent = await sendVerificationEmail(req.user.email, code);
    if (!sent) {
      return res.status(500).json({ error: "Mail gonderilemedi." });
    }
    res.json({ success: true });
  } catch (err) {
    logger.error("resend-verification hatasi:", err.message);
    res.status(500).json({ error: "Sunucu hatasi." });
  }
});

router.post("/forgot-password", codeAttemptLimiter, async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) {
      return res.status(400).json({ error: "Email gerekli." });
    }
    const user = getUserByEmail(email.toLowerCase().trim());
    if (user) {
      const code = createPasswordReset(user.id);
      await sendPasswordResetEmail(user.email, code);
      logger.info("Sifre sifirlama kodu gonderildi: user=" + user.email);
    }
    res.json({ success: true, message: "Eger bu email kayitliysa, sifirlama kodu gonderildi." });
  } catch (err) {
    logger.error("forgot-password hatasi:", err.message);
    res.status(500).json({ error: "Sunucu hatasi." });
  }
});

router.post("/reset-password", codeAttemptLimiter, async (req, res) => {
  try {
    const { email, code, newPassword } = req.body || {};
    if (!email || !code || !newPassword) {
      return res.status(400).json({ error: "email, code ve newPassword gerekli." });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: "Parola en az 6 karakter olmali." });
    }
    const user = getUserByEmail(email.toLowerCase().trim());
    if (!user) {
      return res.status(400).json({ error: "Kod hatali." });
    }
    const result = await resetPasswordWithToken(user.id, String(code).trim(), newPassword);
    if (!result.success) {
      const messages = {
        invalid_code: "Kod hatali.",
        expired: "Kodun suresi dolmus, yeni kod isteyin.",
      };
      return res.status(400).json({ error: messages[result.reason] || "Sifirlama basarisiz." });
    }
    logger.info("Sifre basariyla sifirlandi: user=" + user.email);
    res.json({ success: true });
  } catch (err) {
    logger.error("reset-password hatasi:", err.message);
    res.status(500).json({ error: "Sunucu hatasi." });
  }
});

router.post("/connections/start", requireAuth, (req, res) => {
  try {
    const { hostPeerId } = req.body || {};
    if (!hostPeerId) {
      return res.status(400).json({ error: "hostPeerId gerekli." });
    }

    const result = startConnection(req.user.userId, String(hostPeerId).trim());

    if (!result.allowed) {
      logger.info(
        "Baglanti reddedildi (tekrar kullanim): user=" + req.user.email + " host=" + hostPeerId
      );
      return res.status(403).json({
        error: "Bu bilgisayara daha once baglandiniz, tekrar baglanamazsiniz.",
        reason: result.reason,
        expiresAt: result.expiresAt,
      });
    }

    logger.info(
      "Yeni baglanti baslatildi: user=" + req.user.email + " host=" + hostPeerId + " expiresAt=" + result.expiresAt
    );
    res.json({ allowed: true, expiresAt: result.expiresAt, connToken: result.connToken });
  } catch (err) {
    logger.error("Connection start hatasi:", err.message);
    res.status(500).json({ error: "Sunucu hatasi." });
  }
});

router.post("/connections/verify-token", (req, res) => {
  try {
    const { token, hostPeerId } = req.body || {};
    const valid = verifyConnToken(token, hostPeerId);
    return res.json({ valid });
  } catch (err) {
    logger.error("verify-token hatasi:", err.message);
    return res.json({ valid: false });
  }
});

router.get("/connections/status", requireAuth, (req, res) => {
  try {
    const { hostPeerId } = req.query || {};
    if (!hostPeerId) {
      return res.status(400).json({ error: "hostPeerId gerekli." });
    }

    const status = getConnectionStatus(req.user.userId, String(hostPeerId).trim());
    if (!status.found) {
      return res.status(404).json({ error: "Bu host icin bir baglanti kaydi yok." });
    }

    res.json(status);
  } catch (err) {
    logger.error("Connection status hatasi:", err.message);
    res.status(500).json({ error: "Sunucu hatasi." });
  }
});

router.get("/host/password", internalKeyGuard, hostPasswordLimiter, (req, res) => {
  try {
    const { hostId } = req.query || {};
    if (!hostId) {
      return res.status(400).json({ error: "hostId gerekli." });
    }
    const password = getHostPassword(String(hostId).trim());
    res.json({ password });
  } catch (err) {
    logger.error("GET /host/password hatasi:", err.message);
    res.status(500).json({ error: "Sunucu hatasi." });
  }
});

router.post("/host/password", internalKeyGuard, hostPasswordLimiter, (req, res) => {
  try {
    const { hostId, password } = req.body || {};
    if (!hostId || !password) {
      return res.status(400).json({ error: "hostId ve password gerekli." });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Parola en az 6 karakter olmali." });
    }
    setHostPassword(String(hostId).trim(), password);
    res.json({ ok: true });
  } catch (err) {
    logger.error("POST /host/password hatasi:", err.message);
    res.status(500).json({ error: "Sunucu hatasi." });
  }
});

module.exports = { router, requireAuth };
