import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import { ImapFlow } from "imapflow";
import nodemailer from "nodemailer";
import { webcrypto } from "node:crypto";
import { simpleParser } from 'mailparser';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({
  strict: false,
  verify: (req, res, buf) => {
    try {
      JSON.parse(buf);
    } catch(e) {
      console.log("Raw body that failed:", buf.toString().slice(0, 200));
      throw e;
    }
  }
}));
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    console.log("JSON parse error on:", req.path, err.message);
    return res.status(400).json({ error: "Invalid JSON body" });
  }
  next(err);
});

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
async function encryptPassword(plainText, secret) {
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
    ["encrypt"]
  );

  const iv = webcrypto.getRandomValues(new Uint8Array(12));

  const cipherBuffer = await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plainText)
  );

  const cipherBytes = new Uint8Array(cipherBuffer);

  return JSON.stringify({
    alg: "AES-GCM",
    iv: Buffer.from(iv).toString("base64"),
    data: Buffer.from(cipherBytes).toString("base64"),
  });
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
app.post("/list-mails", async (req, res) => {
  try {
    const { jwt, mail_account_id } = req.body || {};

    if (!jwt || !mail_account_id) {
      return res.status(400).json({ error: "Missing required fields" });
    }

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

    const { data: account, error: accountErr } = await supabaseAdmin
      .from("mail_accounts")
      .select("*")
      .eq("id", mail_account_id)
      .single();

    if (accountErr || !account || account.user_id !== userId) {
      return res.status(404).json({ error: "Account not found" });
    }

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

    const lock = await client.getMailboxLock("INBOX");

    try {
      const mailbox = await client.mailboxOpen("INBOX");
      const exists = mailbox.exists || 0;

      if (exists === 0) {
        return res.json({
          ok: true,
          emails: [],
        });
      }

      const start = Math.max(1, exists - 9);
      const range = `${start}:${exists}`;

      const emails = [];

      for await (const msg of client.fetch(range, {
        uid: true,
        envelope: true,
        flags: true,
        bodyStructure: true,
      })) {
        emails.push({
          uid: msg.uid,
          subject: msg.envelope?.subject ?? "",
          from:
            msg.envelope?.from?.map((f) =>
              f.name ? `${f.name} <${f.address}>` : f.address
            ).join(", ") ?? "",
          date: msg.envelope?.date ?? null,
          seen: msg.flags?.has("\\Seen") ?? false,
        });
      }

      emails.reverse();

      return res.json({
        ok: true,
        emails,
      });
    } finally {
      lock.release();
      await client.logout();
    }
  } catch (e) {
    return res.status(500).json({
      error: e?.message ?? String(e),
    });
  }
});
app.post("/sync-all-inboxes", async (req, res) => {
  const secret = req.headers["x-cron-secret"];
  if (!secret || secret !== process.env.CRON_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const { data: accounts, error: accountsErr } = await supabaseAdmin
      .from("mail_accounts")
      .select("*")
      .eq("is_active", true);

    if (accountsErr || !accounts?.length) {
      return res.json({ ok: true, synced: 0, message: "No active accounts" });
    }

    let totalSynced = 0;

    for (const account of accounts) {
      let password;
      try {
        password = await decryptPassword(
          account.password_encrypted,
          process.env.MAIL_CREDENTIALS_SECRET
        );
      } catch (e) {
        console.error(`decrypt failed for account ${account.id}:`, e.message);
        continue;
      }

      const { data: existing } = await supabaseAdmin
        .from("mail_messages")
        .select("provider_message_id")
        .eq("mail_account_id", account.id)
        .eq("direction", "incoming");

      const existingIds = new Set(
        (existing ?? []).map((m) => m.provider_message_id).filter(Boolean)
      );

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

      try {
        await client.connect();
        const lock = await client.getMailboxLock("INBOX");

        try {
          const mailbox = await client.mailboxOpen("INBOX");
          const exists = mailbox.exists || 0;

          if (exists === 0) continue;

          const start = Math.max(1, exists - 49);
          const range = `${start}:${exists}`;
          const newMails = [];

          for await (const msg of client.fetch(range, {
            uid: true,
            envelope: true,
            flags: true,
            bodyStructure: true,
            source: true,
          })) {
            try {
              const uid = String(msg.uid);
              if (existingIds.has(uid)) continue;

              const receivedAt = msg.envelope?.date
                ? new Date(msg.envelope.date)
                : null;

              if (receivedAt && receivedAt < new Date(account.created_at)) continue;

              const inReplyTo = msg.envelope?.inReplyTo ?? null;
              let bodyText = "";
              let bodyHtml = "";
              let bodyPreview = "";

              try {
                const parsed = await simpleParser(msg.source);
                if (parsed.html) {
                  bodyHtml = `<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body {
    font-family: -apple-system, sans-serif;
    font-size: 14px;
    word-wrap: break-word;
    overflow-wrap: break-word;
    padding: 8px;
    margin: 0;
  }
  img { max-width: 100%; height: auto; }
  * { max-width: 100%; box-sizing: border-box; }
</style>
</head>
<body>
${parsed.html}
</body>
</html>`;
                } else {
                  bodyHtml = "";
                }

                if (parsed.text && parsed.text.trim().length > 0) {
                  bodyText = parsed.text.trim();
                } else if (bodyHtml) {
                  bodyText = bodyHtml
                    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
                    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
                    .replace(/<br\s*\/?>/gi, '\n')
                    .replace(/<\/p>/gi, '\n\n')
                    .replace(/<[^>]+>/g, ' ')
                    .replace(/&nbsp;/g, ' ')
                    .replace(/&amp;/g, '&')
                    .replace(/&lt;/g, '<')
                    .replace(/&gt;/g, '>')
                    .replace(/&quot;/g, '"')
                    .replace(/\s+/g, ' ')
                    .trim();
                }
                bodyPreview = bodyText.slice(0, 200);
              } catch (e) {
                console.error(`body parse error for uid ${uid}:`, e.message);
              }

              const fromEmail = msg.envelope?.from?.[0]?.address ?? "";
              const toEmail = msg.envelope?.to?.[0]?.address ?? "";

              newMails.push({
                user_id: account.user_id,
                mail_account_id: account.id,
                direction: "incoming",
                provider_message_id: uid,
                from_email: fromEmail,
                to_email: toEmail,
                subject: msg.envelope?.subject ?? "",
                body_text: bodyText,
                body_html: bodyHtml,
                body_preview: bodyPreview,
                in_reply_to_message_id: inReplyTo ?? null,
                received_at: receivedAt
                  ? receivedAt.toISOString()
                  : new Date().toISOString(),
              });
            } catch (e) {
              console.error(`Error processing message:`, e.message);
            }
          }

          if (newMails.length > 0) {
            const { data: insertedMails, error: insertErr } = await supabaseAdmin
              .from("mail_messages")
              .insert(newMails)
              .select("id, from_email, subject, body_text, body_preview, received_at, in_reply_to_message_id, user_id");

            if (insertErr) {
              console.error("insert error:", insertErr.message);
            } else {
              totalSynced += insertedMails.length;

              // Nullter Loop — Client-ID für bekannte Absender setzen
              for (const mail of insertedMails) {
                if (!mail.from_email) continue;

                const { data: matchingClient } = await supabaseAdmin
                  .from("clients")
                  .select("id")
                  .eq("user_id", mail.user_id)
                  .eq('email', mail.from_email)
                  .limit(1)
                  .maybeSingle();

                if (!matchingClient) continue;

                await supabaseAdmin
                  .from("mail_messages")
                  .update({ client_id: matchingClient.id })
                  .eq("id", mail.id);
              }

              // Zweiter Loop — body_clean per KI extrahieren
              for (const mail of insertedMails) {
                const rawText = mail.body_text ?? "";
                if (!rawText.trim()) continue;

                const cleanInput = rawText
                  .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
                  .replace(/\r\n/g, "\n")
                  .replace(/\r/g, "\n");

                try {
                  let cleanResponse;
                  for (let attempt = 0; attempt < 3; attempt++) {
                    cleanResponse = await fetch("https://api.anthropic.com/v1/messages", {
                      method: "POST",
                      headers: {
                        "Content-Type": "application/json",
                        "x-api-key": process.env.ANTHROPIC_API_KEY,
                        "anthropic-version": "2023-06-01",
                      },
                      body: JSON.stringify({
                        model: "claude-haiku-4-5-20251001",
                        max_tokens: 1024,
                        messages: [{
                          role: "user",
                          content: `Extrahiere aus dieser E-Mail nur den eigentlichen neuen Text der aktuellen Nachricht. Entferne vollständig: zitierte Vorgänger-Mails (Zeilen die mit > beginnen), automatische Signaturen, "Von:", "Gesendet:", "An:", "Betreff:" Header-Blöcke von zitierten Mails, und typische Trennlinien wie "---" oder "___" die Zitate einleiten. Gib nur den bereinigten Text zurück, ohne Erklärung, ohne Anführungszeichen, ohne Markdown.

E-Mail:
${cleanInput.slice(0, 3000)}`
                        }],
                      }),
                    });
                    if (cleanResponse.status !== 529) break;
                    await new Promise(r => setTimeout(r, 2000));
                  }

                  const cleanData = await cleanResponse.json();
                  const bodyClean = cleanData.content?.[0]?.text?.trim() ?? null;

                  if (bodyClean) {
                    await supabaseAdmin
                      .from("mail_messages")
                      .update({ body_clean: bodyClean })
                      .eq("id", mail.id);
                    console.log(`body_clean set for mail ${mail.id}`);
                  }
                } catch (e) {
                  console.error(`body_clean error for mail ${mail.id}:`, e.message);
                }
              }

              // Dritter Loop — KI-Analyse für unbekannte Absender
              for (const mail of insertedMails) {
                if (mail.in_reply_to_message_id) continue;

                const { data: existingClient } = await supabaseAdmin
                  .from("clients")
                  .select("id")
                  .eq("user_id", mail.user_id)
                  .eq('email', mail.from_email)
                  .limit(1)
                  .maybeSingle();

                if (existingClient) continue;

                const { data: existingAction } = await supabaseAdmin
                  .from("system_actions")
                  .select("id")
                  .eq("mail_message_id", mail.id)
                  .maybeSingle();

                if (existingAction) continue;

                await new Promise(r => setTimeout(r, 1000));

                const cleanBodyText = (mail.body_text ?? "")
                  .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
                  .replace(/\r\n/g, "\n")
                  .replace(/\r/g, "\n");

                let aiPayload = {
                  from_email: mail.from_email,
                  subject: mail.subject,
                  body_preview: mail.body_preview,
                  received_at: mail.received_at,
                  confidence: 0,
                };

                try {
                  let aiResponse;
                  for (let attempt = 0; attempt < 3; attempt++) {
                    aiResponse = await fetch("https://api.anthropic.com/v1/messages", {
                      method: "POST",
                      headers: {
                        "Content-Type": "application/json",
                        "x-api-key": process.env.ANTHROPIC_API_KEY,
                        "anthropic-version": "2023-06-01",
                      },
                      body: JSON.stringify({
                        model: "claude-haiku-4-5-20251001",
                        max_tokens: 1024,
                        messages: [
                          {
                            role: "user",
                            content: `Du bist ein Assistent für einen Fotografen. Analysiere diese eingehende E-Mail und extrahiere die relevanten Informationen. Antworte NUR mit einem JSON-Objekt, ohne Einleitung oder Erklärung.

Erlaubte Werte für job_event_type: hochzeit, standesamt, meeting, call, other, shooting, travel, editing, deadline, revision, buffer

Bewerte außerdem mit confidence (0-100) wie wahrscheinlich es ist, dass diese E-Mail eine echte Kundenanfrage für einen Fotografen ist:
- 90-100: Eindeutige Anfrage mit konkreten Details (Datum, Event, Namen)
- 70-89: Wahrscheinliche Anfrage, einige Details vorhanden
- 40-69: Unklar, könnte eine Anfrage sein
- 0-39: Kein Auftrag (Spam, Newsletter, System-Mail, interne Benachrichtigung)

Wichtig: Lasse Felder komplett weg wenn sie nicht vorhanden sind. Schreibe niemals null oder leere Strings.

Betreff: ${mail.subject}
Nachricht:
${cleanBodyText}

Antworte mit exakt diesem JSON-Format (nur Felder die tatsächlich vorhanden sind):
{
  "confidence": 85,
  "first_name": "Vorname des Anfragenden", wenn nur 2 Vornamen erkennbar sind, dann verwende nur den erstgenannten,
  "last_name": "Nachname des Anfragenden" nur wenn eindeutig erkennbar, wenn nur 2 Vornamen erkennbar sind, dann lasse dieses Feld frei. wenn 2 vor- und nachnamen erkennbar sind, dann trage hier den erstgenannten nachnamen ein",
  "email": "E-Mail-Adresse des Kunden",
  "phone": "Telefonnummer des Kunden",
  "job_event_type": "hochzeit",
  "event_title": "Art des Events + Vornamen, z.B. Hochzeit, Jana & Oliver. wenn nur ein Name gefunden wurde, dann soll hier vorname und nachname stehen oder nur der vorname, wenn es keinen nachnamen gibt. Falls kein Vorname gefunden wurde, verwende stattdessen das Event-Datum, also Hochzeit, Event-Datum",
  "event_date": "YYYY-MM-DD",
  "location": "Ort des Events",
  "source": "Wo hat der Kunde mich gefunden, z.B. Instagram, Google",
  "message": "alle nicht genannten Informationen als Stichpunkte, einer pro Zeile, mit Bindestrich zu Beginn jeder Zeile"
}`,
                          },
                        ],
                      }),
                    });
                    if (aiResponse.status !== 529) break;
                    console.log(`Anthropic overloaded, retry ${attempt + 1}...`);
                    await new Promise(r => setTimeout(r, 2000));
                  }

                  const aiData = await aiResponse.json();
                  const rawText = aiData.content?.[0]?.text ?? "";
                  console.log("AI raw response:", rawText);
                  console.log("AI status:", aiResponse.status);

                  let aiResult = {};
                  try {
                    const jsonMatch = rawText.match(/\{[\s\S]*\}/);
                    if (jsonMatch) {
                      aiResult = JSON.parse(jsonMatch[0]);
                    }
                  } catch (e) {
                    console.error("AI JSON parse error:", e.message);
                  }

                  aiResult = Object.fromEntries(
                    Object.entries(aiResult).filter(
                      ([_, v]) => v !== null && v !== undefined && v !== ""
                    )
                  );

                  aiPayload = { ...aiPayload, ...aiResult };
                } catch (e) {
                  console.error("AI analysis error:", e.message);
                }

                const confidence = aiPayload.confidence ?? 0;
                const title = confidence >= 70
                  ? `Anfrage: ${aiPayload.event_title ?? mail.subject ?? mail.from_email}`
                  : `Mail: ${mail.subject ?? mail.from_email}`;
                const status = confidence === 0 ? "pending" : (confidence >= 40 ? "active" : "dismissed");

                await supabaseAdmin
                  .from("system_actions")
                  .insert({
                    user_id: mail.user_id,
                    title,
                    description: mail.subject ?? "",
                    action_type: "unknown_sender",
                    status,
                    page_key: "unknown_sender",
                    payload: aiPayload,
                    mail_message_id: mail.id,
                  });
              }

              // Zweiter Loop — Waiting-Actions prüfen
              for (const mail of insertedMails) {
                if (!mail.from_email) continue;

                const { data: waitingActions } = await supabaseAdmin
                  .from("job_actions")
                  .select("id, job_id, client_id, job_routine_id, routine_action_id, routine_actions(action_key, title, description, page_key, action_type, default_job_status, sort_hint)")
                  .eq("user_id", mail.user_id)
                  .eq("status", "waiting");

                const filtered = (waitingActions ?? []).filter(
                  a => a.routine_actions?.action_key === "wait_for_reply"
                );

                if (!filtered.length) continue;

                for (const action of filtered) {
                  if (!action.client_id) continue;

                  const { data: clientData } = await supabaseAdmin
                    .from("clients")
                    .select("email, first_name, name")
                    .eq("id", action.client_id)
                    .single();

                  if (!clientData?.email) continue;
                  if (clientData.email.toLowerCase() !== mail.from_email.toLowerCase()) continue;

                  const clientName = clientData.first_name
                    ? `${clientData.first_name}${clientData.name ? ' ' + clientData.name : ''}`
                    : clientData.email;

                  await supabaseAdmin
                    .from("job_actions")
                    .update({
                      status: "done",
                      completed_at: new Date().toISOString(),
                      payload: { mail_message_id: mail.id },
                    })
                    .eq("id", action.id);

                  const { data: connection } = await supabaseAdmin
                    .from("routine_connections")
                    .select("to_action_id, routine_actions!to_action_id(id, title, description, page_key, action_type, default_job_status, sort_hint)")
                    .eq("from_action_id", action.routine_action_id)
                    .eq("condition_key", "default")
                    .single();

                  if (!connection?.to_action_id) {
                    console.log(`No next action found for wait_for_reply ${action.id}`);
                    continue;
                  }

                  const nextAction = connection.routine_actions;

                  // KI-Analyse: Welche Tools braucht der Nutzer für diese Antwort?
                  let detectedTools = [];
                  try {
                    const cleanReplyText = (mail.body_text ?? "")
                      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
                      .replace(/\r\n/g, "\n")
                      .replace(/\r/g, "\n");

                    let toolAiResponse;
                    for (let attempt = 0; attempt < 3; attempt++) {
                      toolAiResponse = await fetch("https://api.anthropic.com/v1/messages", {
                        method: "POST",
                        headers: {
                          "Content-Type": "application/json",
                          "x-api-key": process.env.ANTHROPIC_API_KEY,
                          "anthropic-version": "2023-06-01",
                        },
                        body: JSON.stringify({
                          model: "claude-haiku-4-5-20251001",
                          max_tokens: 256,
                          messages: [
                            {
                              role: "user",
                              content: `Du bist ein Assistent für einen Fotografen. Analysiere diese Kunden-Antwort-Mail und entscheide, welche der folgenden Tools der Fotograf für seine Antwort benötigt.

Verfügbare Tools:
- price_list: Kunde fragt nach Preisen, Paketen, Kosten oder einer Preisliste
- appointment_suggestion: Kunde fragt nach Terminen, Verfügbarkeit oder möchte ein Kennenlernen/Meeting vereinbaren
- offer: Kunde ist interessiert und möchte ein konkretes Angebot oder hat grundsätzlich zugesagt

Antworte NUR mit einem JSON-Array der relevanten Tool-Keys. Wenn kein Tool passt, antworte mit einem leeren Array.
Beispiele: ["price_list"] oder ["appointment_suggestion","offer"] oder []

Betreff: ${mail.subject}
Nachricht:
${cleanReplyText}`,
                            },
                          ],
                        }),
                      });
                      if (toolAiResponse.status !== 529) break;
                      console.log(`Tool detection: Anthropic overloaded, retry ${attempt + 1}...`);
                      await new Promise(r => setTimeout(r, 2000));
                    }

                    const toolAiData = await toolAiResponse.json();
                    const rawToolText = (toolAiData.content?.[0]?.text ?? "").trim();
                    console.log("Tool detection raw response:", rawToolText);

                    const arrayMatch = rawToolText.match(/\[[\s\S]*\]/);
                    if (arrayMatch) {
                      const parsed = JSON.parse(arrayMatch[0]);
                      if (Array.isArray(parsed)) {
                        const validTools = ["price_list", "appointment_suggestion", "offer"];
                        detectedTools = parsed.filter(t => validTools.includes(t));
                      }
                    }
                  } catch (e) {
                    console.error("Tool detection error:", e.message);
                    // detectedTools bleibt [], Action wird trotzdem erstellt
                  }

                  await supabaseAdmin
                    .from("job_actions")
                    .insert({
                      user_id: mail.user_id,
                      job_routine_id: action.job_routine_id,
                      routine_action_id: connection.to_action_id,
                      job_id: action.job_id,
                      client_id: action.client_id,
                      title: `Mail von ${clientName} beantworten`,
                      description: nextAction?.description ?? "",
                      page_key: nextAction?.page_key ?? "answer_reply",
                      action_type: nextAction?.action_type ?? "standard",
                      status: nextAction?.default_job_status ?? "active",
                      sort_order: nextAction?.sort_hint ?? 2,
                      activated_at: new Date().toISOString(),
                      payload: {
                        mail_message_id: mail.id,
                        detected_tools: detectedTools,
                      },
                    });

                  console.log(`wait_for_reply ${action.id} completed, answer_reply created for ${clientName}, detected_tools: ${JSON.stringify(detectedTools)}`);
                }
              }
            }
          }
        } finally {
          lock.release();
          await client.logout();
        }
      } catch (e) {
        console.error(`IMAP error for account ${account.id}:`, e.message);
        continue;
      }
    }

    return res.json({ ok: true, synced: totalSynced });
  } catch (e) {
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
});

app.post("/analyze-mail", async (req, res) => {
  try {
    const { jwt, mail_message_id } = req.body || {};

    if (!jwt || !mail_message_id) {
      return res.status(400).json({ error: "Missing required fields" });
    }

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
      return res.status(401).json({ error: "Invalid user" });
    }

    const { data: mail, error: mailErr } = await supabaseAdmin
      .from("mail_messages")
      .select("body_text, subject, from_email")
      .eq("id", mail_message_id)
      .single();

    if (mailErr || !mail) {
      return res.status(404).json({ error: "Mail not found" });
    }

    const bodyText = mail.body_text ?? "";

    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": process.env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-haiku-4-5-20251001",
        max_tokens: 1024,
        messages: [
          {
            role: "user",
            content: `Du bist ein Assistent für einen Fotografen. Analysiere diese eingehende E-Mail und extrahiere die relevanten Informationen. Antworte NUR mit einem JSON-Objekt, ohne Einleitung oder Erklärung.

Erlaubte Werte für job_event_type: hochzeit, standesamt, meeting, call, other, shooting, travel, editing, deadline, revision, buffer

Bewerte außerdem mit confidence (0-100) wie wahrscheinlich es ist, dass diese E-Mail eine echte Kundenanfrage für einen Fotografen ist:
- 90-100: Eindeutige Anfrage mit konkreten Details (Datum, Event, Namen)
- 70-89: Wahrscheinliche Anfrage, einige Details vorhanden
- 40-69: Unklar, könnte eine Anfrage sein
- 0-39: Kein Auftrag (Spam, Newsletter, System-Mail, interne Benachrichtigung)

Wichtig: Lasse Felder komplett weg wenn sie nicht vorhanden sind. Schreibe niemals null oder leere Strings.

Betreff: ${mail.subject}
Nachricht:
${bodyText}

Antworte mit exakt diesem JSON-Format (nur Felder die tatsächlich vorhanden sind):
{
  "confidence": 85,
  "first_name": "Vorname des Anfragenden", wenn nur 2 Vornamen erkennbar sind, dann verwende nur den erstgenannten,
  "last_name": "Nachname des Anfragenden" nur wenn eindeutig erkennbar, wenn nur 2 Vornamen erkennbar sind, dann lasse dieses Feld frei. wenn 2 vor- und nachnamen erkennbar sind, dann trage hier den erstgenannten nachnamen ein",
  "email": "E-Mail-Adresse des Kunden",
  "phone": "Telefonnummer des Kunden",
  "job_event_type": "hochzeit",
  "event_title": "Art des Events + Vornamen, z.B. Hochzeit, Jana & Oliver. wenn nur ein Name gefunden wurde, dann soll hier vorname und nachname stehen oder nur der vorname, wenn es keinen nachnamen gibt. Falls kein Vorname gefunden wurde, verwende stattdessen das Event-Datum, also Hochzeit, Event-Datum",
  "event_date": "DD.MM.YYYY",
  "location": "Ort des Events",
  "source": "Wo hat der Kunde mich gefunden, z.B. Instagram, Google",
  "message": "alle nicht genannten Informationen als Stichpunkte, einer pro Zeile, mit Bindestrich zu Beginn jeder Zeile"
}`,
          },
        ],
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(500).json({ error: "AI analysis failed", detail: data });
    }

    let aiResult = {};
    const rawText = data.content?.[0]?.text ?? "";
    try {
      const jsonMatch = rawText.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        aiResult = JSON.parse(jsonMatch[0]);
      }
    } catch (e) {
      aiResult = { message: rawText, confidence: 0 };
    }

    // Alle null/undefined/leere Werte entfernen
    const summary = Object.fromEntries(
      Object.entries(aiResult).filter(
        ([_, v]) => v !== null && v !== undefined && v !== ""
      )
    );

    return res.json({ ok: true, summary });
  } catch (e) {
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
});
app.post("/save-mail-account", async (req, res) => {
  try {
    const { jwt, mail_account_id, field, value } = req.body || {};

    if (!jwt || !field) {
      return res.status(400).json({
        error: "Missing required fields",
      });
    }

    const allowedFields = [
      "name",
      "email",
      "imap_host",
      "imap_port",
      "imap_secure",
      "smtp_host",
      "smtp_port",
      "smtp_secure",
      "username",
      "password",
    ];

    if (!allowedFields.includes(field)) {
      return res.status(400).json({
        error: "Invalid field",
      });
    }

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

    // Schritt 1: erstmal nur normales Feld speichern, Passwort kommt danach
let dbField = field;
let dbValue = value;

if (field === "name") {
  dbField = "display_name";
}

if (field === "imap_port" || field === "smtp_port") {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return res.status(400).json({
      error: `Invalid numeric value for ${field}`,
    });
  }
  dbValue = parsed;
}

if (field === "imap_secure" || field === "smtp_secure") {
  if (typeof value === "boolean") {
    dbValue = value;
  } else if (value === "true" || value === "1" || value === 1) {
    dbValue = true;
  } else if (value === "false" || value === "0" || value === 0) {
    dbValue = false;
  } else {
    return res.status(400).json({
      error: `Invalid boolean value for ${field}`,
    });
  }
}

if (field === "password") {
  dbField = "password_encrypted";
  dbValue = await encryptPassword(
    String(value ?? ""),
    process.env.MAIL_CREDENTIALS_SECRET
  );
}

    if (!mail_account_id) {
      const insertData = {
        user_id: userId,
        [dbField]: dbValue,
        test_status: "idle",
      };

      const { data, error } = await supabaseAdmin
        .from("mail_accounts")
        .insert(insertData)
        .select("id")
        .single();

      if (error) {
        return res.status(500).json({
          error: error.message,
        });
      }

      return res.json({
        ok: true,
        created: true,
        mail_account_id: data.id,
      });
    }

    const { data: existing, error: existingErr } = await supabaseAdmin
      .from("mail_accounts")
      .select("id, user_id")
      .eq("id", mail_account_id)
      .single();

    if (existingErr || !existing || existing.user_id !== userId) {
      return res.status(404).json({
        error: "Account not found",
      });
    }
    // 🔥 Default-Account Logik
if (field === "is_default" && dbValue === true) {
  await supabaseAdmin
    .from("mail_accounts")
    .update({ is_default: false })
    .eq("user_id", userId);
}

    const { error: updateErr } = await supabaseAdmin
      .from("mail_accounts")
      .update({
        [dbField]: dbValue,
      })
      .eq("id", mail_account_id)
      .eq("user_id", userId);

    if (updateErr) {
      return res.status(500).json({
        error: updateErr.message,
      });
    }

    return res.json({
      ok: true,
      created: false,
      mail_account_id,
    });
  } catch (e) {
    return res.status(500).json({
      error: e?.message ?? String(e),
    });
  }
});
app.post("/delete-mail-account", async (req, res) => {
  try {
    const { jwt, mail_account_id } = req.body || {};

    if (!jwt || !mail_account_id) {
      return res.status(400).json({
        error: "Missing required fields",
      });
    }

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

    const { data: existing, error: existingErr } = await supabaseAdmin
      .from("mail_accounts")
      .select("id, user_id")
      .eq("id", mail_account_id)
      .single();

    if (existingErr || !existing || existing.user_id !== userId) {
      return res.status(404).json({
        error: "Account not found",
      });
    }

    const { error: deleteErr } = await supabaseAdmin
      .from("mail_accounts")
      .delete()
      .eq("id", mail_account_id)
      .eq("user_id", userId);

    if (deleteErr) {
      return res.status(500).json({
        error: deleteErr.message,
      });
    }

    return res.json({
      ok: true,
      mail_account_id,
    });
  } catch (e) {
    return res.status(500).json({
      error: e?.message ?? String(e),
    });
  }
});
app.post("/send-mail", async (req, res) => {
  try {
    const { jwt, mail_account_id, to, subject, body } = req.body || {};

    if (!jwt || !mail_account_id || !to || !subject || !body) {
      return res.status(400).json({
        error: "Missing required fields",
      });
    }

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

    const { data: account, error: accountErr } = await supabaseAdmin
      .from("mail_accounts")
      .select("*")
      .eq("id", mail_account_id)
      .single();

    if (accountErr || !account || account.user_id !== userId) {
      return res.status(404).json({
        error: "Account not found",
      });
    }

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

    const transporter = nodemailer.createTransport({
      host: account.smtp_host,
      port: account.smtp_port,
      secure: account.smtp_secure,
      auth: {
        user: account.username,
        pass: password,
      },
    });

    const info = await transporter.sendMail({
      from: account.email
        ? `${account.display_name || ""} <${account.email}>`
        : account.username,
      to,
      subject,
      text: body,
    });

    return res.json({
      ok: true,
      messageId: info.messageId,
    });
  } catch (e) {
    return res.status(500).json({
      error: e?.message ?? String(e),
    });
  }
});
app.post("/retry-ai-analysis", async (req, res) => {
  const secret = req.headers["x-cron-secret"];
  if (!secret || secret !== process.env.CRON_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const { data: pendingActions, error } = await supabaseAdmin
      .from("system_actions")
      .select("id, mail_message_id, user_id")
      .eq("status", "pending")
      .eq("action_type", "unknown_sender");

    if (error || !pendingActions?.length) {
      return res.json({ ok: true, retried: 0 });
    }

    let retried = 0;

    for (const action of pendingActions) {
      const { data: mail } = await supabaseAdmin
        .from("mail_messages")
        .select("body_text, subject, from_email, body_preview, received_at")
        .eq("id", action.mail_message_id)
        .single();

      if (!mail) continue;

      const cleanBodyText = (mail.body_text ?? "")
        .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
        .replace(/\r\n/g, "\n")
        .replace(/\r/g, "\n");

      let aiResult = {};
      try {
        let aiResponse;
        for (let attempt = 0; attempt < 3; attempt++) {
          aiResponse = await fetch("https://api.anthropic.com/v1/messages", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "x-api-key": process.env.ANTHROPIC_API_KEY,
              "anthropic-version": "2023-06-01",
            },
            body: JSON.stringify({
              model: "claude-haiku-4-5-20251001",
              max_tokens: 1024,
              messages: [
                {
                  role: "user",
                  content: `Du bist ein Assistent für einen Fotografen. Analysiere diese eingehende E-Mail und extrahiere die relevanten Informationen. Antworte NUR mit einem JSON-Objekt, ohne Einleitung oder Erklärung.

Erlaubte Werte für job_event_type: hochzeit, standesamt, meeting, call, other, shooting, travel, editing, deadline, revision, buffer

Bewerte außerdem mit confidence (0-100) wie wahrscheinlich es ist, dass diese E-Mail eine echte Kundenanfrage für einen Fotografen ist:
- 90-100: Eindeutige Anfrage mit konkreten Details (Datum, Event, Namen)
- 70-89: Wahrscheinliche Anfrage, einige Details vorhanden
- 40-69: Unklar, könnte eine Anfrage sein
- 0-39: Kein Auftrag (Spam, Newsletter, System-Mail, interne Benachrichtigung)

Wichtig: Lasse Felder komplett weg wenn sie nicht vorhanden sind. Schreibe niemals null oder leere Strings.

Betreff: ${mail.subject}
Nachricht:
${cleanBodyText}

Antworte mit exakt diesem JSON-Format (nur Felder die tatsächlich vorhanden sind):
{
  "confidence": 85,
  "first_name": "Vorname des Anfragenden", wenn nur 2 Vornamen erkennbar sind, dann verwende nur den erstgenannten,
  "last_name": "Nachname des Anfragenden" nur wenn eindeutig erkennbar, wenn nur 2 Vornamen erkennbar sind, dann lasse dieses Feld frei. wenn 2 vor- und nachnamen erkennbar sind, dann trage hier den erstgenannten nachnamen ein",
  "email": "E-Mail-Adresse des Kunden",
  "phone": "Telefonnummer des Kunden",
  "job_event_type": "hochzeit",
  "event_title": "Art des Events + Name, z.B. Hochzeit, Jana & Oliver",
  "event_date": "YYYY-MM-DD",
  "location": "Ort des Events",
  "source": "Wo hat der Kunde mich gefunden, z.B. Instagram, Google",
  "message": "alle nicht genannten Informationen als Stichpunkte, einer pro Zeile, mit Bindestrich zu Beginn jeder Zeile"
}`,
                },
              ],
            }),
          });
          if (aiResponse.status !== 529) break;
          console.log(`Retry endpoint: Anthropic overloaded, attempt ${attempt + 1}...`);
          await new Promise(r => setTimeout(r, 2000));
        }

        const aiData = await aiResponse.json();
        const rawText = aiData.content?.[0]?.text ?? "";

        try {
          const jsonMatch = rawText.match(/\{[\s\S]*\}/);
          if (jsonMatch) {
            aiResult = JSON.parse(jsonMatch[0]);
          }
        } catch (e) {
          console.error("AI JSON parse error in retry:", e.message);
        }

        aiResult = Object.fromEntries(
          Object.entries(aiResult).filter(
            ([_, v]) => v !== null && v !== undefined && v !== ""
          )
        );
      } catch (e) {
        console.error("AI analysis error in retry:", e.message);
        continue;
      }

      const confidence = aiResult.confidence ?? 0;
      if (confidence === 0) continue; // Noch nicht erfolgreich — beim nächsten Cron nochmal

      const newStatus = confidence >= 40 ? "active" : "dismissed";
      const title = confidence >= 70
        ? `Anfrage: ${aiResult.event_title ?? mail.subject ?? mail.from_email}`
        : `Mail: ${mail.subject ?? mail.from_email}`;

      const aiPayload = {
        from_email: mail.from_email,
        subject: mail.subject,
        body_preview: mail.body_preview,
        received_at: mail.received_at,
        ...aiResult,
      };

      await supabaseAdmin
        .from("system_actions")
        .update({
          status: newStatus,
          title,
          payload: aiPayload,
        })
        .eq("id", action.id);

      retried++;
      await new Promise(r => setTimeout(r, 1000));
    }

    return res.json({ ok: true, retried });
  } catch (e) {
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
});

// ── /ai-compose ─────────────────────────────────────────────────────────────
// Schreibt eine Mail-Antwort mit Hilfe der KI und Tool Use.
// Body: { user_id, job_id, client_id, task, mail_history }
app.post("/ai-compose", async (req, res) => {
  try {
    const { user_id, job_id, client_id, task, mail_history } = req.body;
    if (!user_id) return res.status(400).json({ error: "user_id required" });

    // ── Tool-Definitionen ────────────────────────────────────────────────────
    const tools = [
      {
        name: "get_office_hours",
        description: "Gibt die Bürozeiten des Nutzers zurück (Wochentage + Von/Bis-Zeiten).",
        input_schema: {
          type: "object",
          properties: {},
          required: [],
        },
      },
      {
        name: "get_calendar_events",
        description: "Gibt Kalender-Termine des Nutzers zurück die Verfügbarkeit blockieren. Nutze from/to im ISO-Format (YYYY-MM-DD).",
        input_schema: {
          type: "object",
          properties: {
            from: { type: "string", description: "Startdatum YYYY-MM-DD" },
            to:   { type: "string", description: "Enddatum YYYY-MM-DD" },
          },
          required: ["from", "to"],
        },
      },
      {
        name: "get_client_info",
        description: "Gibt Name, E-Mail und Notizen zum Kunden zurück.",
        input_schema: {
          type: "object",
          properties: {},
          required: [],
        },
      },
      {
        name: "get_job_info",
        description: "Gibt Details zum aktuellen Job zurück (Titel, Datum, Notizen).",
        input_schema: {
          type: "object",
          properties: {},
          required: [],
        },
      },
    ];

    // ── Tool-Implementierungen ───────────────────────────────────────────────
    async function executeTool(name, input) {
      if (name === "get_office_hours") {
        const { data } = await supabaseAdmin
          .from("user_settings")
          .select("office_hours")
          .eq("user_id", user_id)
          .maybeSingle();
        return data?.office_hours ?? [];
      }

      if (name === "get_calendar_events") {
        const { data } = await supabaseAdmin
          .from("calendar_events")
          .select("title, start_at, end_at, all_day, all_day_start_date, all_day_end_date, status")
          .eq("user_id", user_id)
          .in("status", ["confirmed", "tentative"])
          .gte("start_at", input.from)
          .lte("start_at", input.to + "T23:59:59Z")
          .order("start_at");
        return data ?? [];
      }

      if (name === "get_client_info") {
        const { data } = await supabaseAdmin
          .from("clients")
          .select("first_name, last_name, email, notes")
          .eq("id", client_id)
          .maybeSingle();
        return data ?? {};
      }

      if (name === "get_job_info") {
        const { data } = await supabaseAdmin
          .from("jobs")
          .select("title, event_date, notes")
          .eq("id", job_id)
          .maybeSingle();
        return data ?? {};
      }

      return { error: "unknown tool" };
    }

    // ── Agentic Loop ─────────────────────────────────────────────────────────
    const now = new Date();
    const today = now.toISOString().split("T")[0];
    const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString().split("T")[0];
    const messages = [
      {
        role: "user",
        content: `Heute ist der ${today}, aktuelle Uhrzeit: ${now.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit", timeZone: "Europe/Berlin" })} Uhr (Europe/Berlin).

WICHTIG: Schlage NUR Termine vor die in der Zukunft liegen. Der früheste mögliche Tag ist morgen (${tomorrow}). Heute (${today}) darf NICHT vorgeschlagen werden, auch wenn noch Bürozeit übrig ist.

Aufgabe: ${task || "Schreibe eine freundliche, professionelle E-Mail-Antwort auf Deutsch."}

${mail_history ? `Bisheriger Mailverkehr:\n${mail_history}` : ""}

Nutze die verfügbaren Tools um alle nötigen Informationen zu sammeln. Gib am Ende NUR das Ergebnis zurück, ohne Erklärungen, ohne Einleitung, ohne Markdown-Formatierung.`,
      },
    ];

    let finalText = "";
    let iterations = 0;

    while (iterations < 10) {
      iterations++;

      let aiResp;
      for (let attempt = 0; attempt < 3; attempt++) {
        aiResp = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": process.env.ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
          },
          body: JSON.stringify({
            model: "claude-haiku-4-5-20251001",
            max_tokens: 1024,
            tools,
            messages,
            system: "Du bist ein Assistent für einen Fotografen. Du schreibst professionelle, freundliche E-Mails auf Deutsch. Sammle zuerst alle nötigen Informationen über die Tools, dann schreibe die E-Mail.",
          }),
        });
        if (aiResp.status !== 529) break;
        await new Promise(r => setTimeout(r, 2000));
      }

      const aiData = await aiResp.json();
      // Wenn stop_reason end_turn → Text extrahieren
      const stopReason = aiData.stop_reason;
      const content = aiData.content ?? [];

      // Antwort zur Message-History hinzufügen
      messages.push({ role: "assistant", content });

      if (stopReason === "end_turn") {
        const rawText = content
          .filter(b => b.type === "text")
          .map(b => b.text)
          .join("\n")
          .trim();
        // Bei Terminvorschlägen: nur Datum-Zeilen extrahieren (DD.MM.YYYY HH:MM)
        if (task && task.includes("Termine")) {
          const dateLines = rawText
            .split("\n")
            .map(l => l.trim())
            .filter(l => /^\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}/.test(l))
            .slice(0, 3);
          finalText = dateLines.join("\n");
        } else {
          finalText = rawText;
        }
        break;
      }

      if (stopReason === "tool_use") {
        // Tools ausführen
        const toolResults = [];
        for (const block of content) {
          if (block.type !== "tool_use") continue;
          console.log(`ai-compose: calling tool ${block.name}`, block.input);
          const result = await executeTool(block.name, block.input);
          toolResults.push({
            type: "tool_result",
            tool_use_id: block.id,
            content: JSON.stringify(result),
          });
        }
        messages.push({ role: "user", content: toolResults });
        continue;
      }

      // Unerwarteter stop_reason
      break;
    }

    return res.json({ ok: true, text: finalText });
  } catch (e) {
    console.error("ai-compose error:", e);
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
});

app.listen(PORT, () => {
  console.log(`Mail Service läuft auf Port ${PORT}`);
});