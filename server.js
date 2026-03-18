import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import { ImapFlow } from "imapflow";
import nodemailer from "nodemailer";
import { webcrypto } from "node:crypto";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
);

// Base64 helper
function fromBase64(base64) {
  return Uint8Array.from(Buffer.from(base64, "base64"));
}

// Decrypt password
async function decryptPassword(encrypted, secret) {
  const enc = new TextEncoder();

  const secretHash = await webcrypto.subtle.digest(
    "SHA-256",
    enc.encode(secret)
  );

  const key = await webcrypto.subtle.importKey(
    "raw",
    secretHash,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const payload = JSON.parse(encrypted);
  const iv = fromBase64(payload.iv);
  const data = fromBase64(payload.data);

  const plainBuffer = await webcrypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  return new TextDecoder().decode(plainBuffer);
}

// Health check
app.get("/", (_req, res) => {
  res.json({ ok: true, service: "mail-service" });
});

// Main endpoint
app.post("/test-mail-account", async (req, res) => {
  try {
    const { jwt, mail_account_id } = req.body || {};

    if (!jwt || !mail_account_id) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Validate user via Supabase
    const supabaseUser = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY,
      {
        global: { headers: { Authorization: `Bearer ${jwt}` } },
      }
    );

    const { data: userData, error: userErr } =
      await supabaseUser.auth.getUser();

    if (userErr || !userData?.user) {
      return res.status(401).json({
        error: "Invalid user",
        detail: userErr?.message ?? null,
      });
    }

    const userId = userData.user.id;

    // Load mail account
    const { data: account, error: accountErr } = await supabaseAdmin
      .from("mail_accounts")
      .select("*")
      .eq("id", mail_account_id)
      .single();

    if (accountErr || !account || account.user_id !== userId) {
      return res.status(404).json({ error: "Account not found" });
    }

    // Decrypt password
    let password;
    try {
      password = await decryptPassword(
        account.password_encrypted,
        process.env.MAIL_CREDENTIALS_SECRET
      );
    } catch (e) {
      return res.status(500).json({
        error: "decrypt_failed",
        detail: e?.message ?? String(e),
      });
    }

    let imapOk = false;
    let smtpOk = false;
    let imapError = null;
    let smtpError = null;

    // IMAP test
    try {
      const client = new ImapFlow({
        host: account.imap_host,
        port: account.imap_port,
        secure: account.imap_secure,
        auth: {
          user: account.username,
          pass: password,
        },
        logger: false,
      });

      await client.connect();
      await client.logout();
      imapOk = true;
    } catch (e) {
      imapError = e?.message ?? String(e);
    }

    // SMTP test
    try {
      const transporter = nodemailer.createTransport({
        host: account.smtp_host,
        port: account.smtp_port,
        secure: account.smtp_secure,
        auth: {
          user: account.username,
          pass: password,
        },
      });

      await transporter.verify();
      smtpOk = true;
    } catch (e) {
      smtpError = e?.message ?? String(e);
    }

    return res.json({
      ok: imapOk && smtpOk,
      imap: imapOk,
      smtp: smtpOk,
      imapError,
      smtpError,
    });

  } catch (e) {
    return res.status(500).json({
      error: e?.message ?? String(e),
    });
  }
});

app.listen(PORT, () => {
  console.log(`Mail Service läuft auf Port ${PORT}`);
});