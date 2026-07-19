// server.js
// Sade auth API - kullanıcı kayıt/giriş, RustDesk launcher için.
// Eski WebRTC signal-server'ın yerine geçer (o özellikler artık RustDesk'in
// kendi hbbs/hbbr sunucusu tarafından karşılanıyor, bu sunucu sadece
// kullanıcı hesabı yönetimini yapıyor).

const express = require("express");
const cors = require("cors");
const path = require("path");
const logger = require("./logger");
const { router: authRouter } = require("./authRoutes");
const { router: adminRouter } = require("./adminRoutes");

const PORT = process.env.PORT || 4000;

const app = express();
app.use(cors());
app.use(express.json());

app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed" || err instanceof SyntaxError) {
    logger.info("Gecersiz JSON istegi reddedildi: " + req.method + " " + req.path);
    return res.status(400).json({ error: "Invalid JSON" });
  }
  next(err);
});

app.use("/auth", authRouter);
app.use("/admin", adminRouter);

// RemoteSupport: admin.html (dashboard) ve ileride eklenecek diğer statik
// dosyalar için. http://<vps-ip>:4000/admin.html şeklinde erişilir.
app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "auth-server" });
});

app.listen(PORT, () => {
  logger.info(`Auth server ${PORT} portunda çalışıyor.`);
});