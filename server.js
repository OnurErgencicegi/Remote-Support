// server.js
// Sade auth API - kullanıcı kayıt/giriş, RustDesk launcher için.
// Eski WebRTC signal-server'ın yerine geçer (o özellikler artık RustDesk'in
// kendi hbbs/hbbr sunucusu tarafından karşılanıyor, bu sunucu sadece
// kullanıcı hesabı yönetimini yapıyor).

const express = require("express");
const cors = require("cors");
const logger = require("./src/logger");
const { router: authRouter } = require("./src/authRoutes");

const PORT = process.env.PORT || 4000;

const app = express();
app.use(cors());
app.use(express.json());

app.use("/auth", authRouter);

app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "auth-server" });
});

app.listen(PORT, () => {
  logger.info(`Auth server ${PORT} portunda çalışıyor.`);
});
