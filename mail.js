const nodemailer = require("nodemailer");
const logger = require("./logger");

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp-relay.brevo.com",
  port: Number(process.env.SMTP_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sendMail(to, subject, html) {
  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || `"RemoteSupport" <no-reply@remotesupport.local>`,
      to,
      subject,
      html,
    });
    return true;
  } catch (e) {
    logger.error("Mail gonderim hatasi: " + e.message);
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
