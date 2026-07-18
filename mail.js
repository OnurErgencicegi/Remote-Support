// src/mail.js
const axios = require("axios");
const logger = require("./logger");

const BREVO_API_KEY = process.env.BREVO_API_KEY;
const BREVO_SEND_URL = "https://api.brevo.com/v3/smtp/email";

async function sendMail(to, subject, html) {
  if (!BREVO_API_KEY) {
    logger.error("BREVO_API_KEY tanimli degil, mail gonderilemiyor.");
    return false;
  }
  try {
    await axios.post(
      BREVO_SEND_URL,
      {
        sender: { name: "RemoteSupport", email: process.env.SMTP_FROM_EMAIL || "b27283001@smtp-brevo.com" },
        to: [{ email: to }],
        subject,
        htmlContent: html,
      },
      {
        headers: {
          "api-key": BREVO_API_KEY,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        timeout: 10000,
      }
    );
    return true;
  } catch (e) {
    const detail = e.response ? JSON.stringify(e.response.data) : e.message;
    logger.error("Mail gonderim hatasi: " + detail);
    return false;
  }
}

function sendVerificationEmail(to, code) {
  return sendMail(
    to,
    "RemoteSupport - Email Dogrulama",
    `<p>Dogrulama kodunuz: <b>${code}</b></p><p>Bu kod 15 dakika gecerlidir.</p>`
  );
}

function sendPasswordResetEmail(to, code) {
  return sendMail(
    to,
    "RemoteSupport - Sifre Sifirlama",
    `<p>Sifre sifirlama kodunuz: <b>${code}</b></p><p>Bu kod 30 dakika gecerlidir.</p>`
  );
}

module.exports = { sendVerificationEmail, sendPasswordResetEmail };
