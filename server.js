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
// ── Shared Tool-Detection Helper ─────────────────────────────────────────────
async function runToolDetection(mail) {
  let detectedTools = [];
  let openTopics = '';
  let detectedDates = [];
  try {
    const cleanText = (mail.body_text ?? '')
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
      .replace(/\r\n/g, '\n')
      .replace(/\r/g, '\n');
    let aiResponse;
    for (let attempt = 0; attempt < 3; attempt++) {
      aiResponse = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 500, messages: [{ role: 'user', content: `Du bist ein Assistent fuer einen Fotografen. Analysiere diese Kunden-Mail und entscheide, welche Tools benoetigt werden.\n\nEingang der Mail: ${new Date(mail.received_at || mail.created_at || Date.now()).toLocaleDateString('de-DE', { weekday: 'long', year: 'numeric', month: '2-digit', day: '2-digit' })} (${new Date(mail.received_at || mail.created_at || Date.now()).toISOString().slice(0,10)})\n\nVerfuegbare Tools:\n- price_list: Kunde fragt explizit nach Preisen oder Kosten\n- appointment_suggestion: Kunde moechte einen Termin vereinbaren, nennt aber kein konkretes Datum\n- offer: Kunde fragt explizit nach einem Angebot oder Kostenvoranschlag\n- availability: Kunde nennt ein konkretes, relatives oder beschreibendes Datum (z.B. Hochzeitsdatum, Veranstaltungsdatum, naechsten Samstag, in zwei Tagen, uebernaechste Woche) ODER fragt ob du an einem Datum verfuegbar bist\n\nVerfuegbare Label-Keys fuer Termine: hochzeit, standesamt, meeting, call, other, shooting, travel, editing, deadline, revision, buffer\n\nWichtig:\n- Nur Tools auswaehlen die klar aus dem Text hervorgehen\n- offer NUR wenn explizit nach einem Angebot gefragt wird\n- availability wenn ein Datum genannt wird - auch relative Angaben wie 'diesen Samstag', 'naechste Woche Freitag', 'in drei Tagen' zaehlen\n- Bei relativen Datumsangaben: berechne das genaue Datum basierend auf dem Eingangsdatum der Mail\n- Falls availability: alle Daten als Array in detected_dates mit {date: YYYY-MM-DD, title: string, label: key}, sonst leeres Array\n- title ist eine kurze Beschreibung des Termins (z.B. Hochzeit, Standesamt, Shooting)\n- label ist der passende Label-Key aus der Liste oben\n- open_topics NUR wenn der Kunde eine explizite Frage stellt oder einen Punkt anspricht der vom Fotografen beantwortet werden muss und nicht durch die anderen Tools abgedeckt ist. Reine Hintergrundinformationen (Locations, Gaestezahl, Stil etc.) gehoeren NICHT in open_topics. Wenn keine echte offene Frage vorhanden: open_topics leer lassen\n\nAntworte NUR mit JSON:\n{tools: [availability], open_topics: , detected_dates: [{date: 2026-08-15, title: Hochzeit, label: hochzeit}]}\n\nBetreff: ${mail.subject}\nNachricht:\n${cleanText}` }] }),
      });
      if (aiResponse.status !== 529) break;
      await new Promise(r => setTimeout(r, 2000));
    }
    const aiData = await aiResponse.json();
    const rawText = (aiData.content?.[0]?.text ?? '').trim();
    console.log('Tool detection raw response:', rawText);
    const objectMatch = rawText.match(/\{[\s\S]*\}/);
    if (objectMatch) {
      const parsed = JSON.parse(objectMatch[0]);
      const validTools = ['price_list', 'appointment_suggestion', 'offer', 'availability'];
      if (Array.isArray(parsed.tools)) detectedTools = parsed.tools.filter(t => validTools.includes(t));
      if (parsed.open_topics) { if (Array.isArray(parsed.open_topics) && parsed.open_topics.length > 0) { openTopics = parsed.open_topics.join(', '); detectedTools.push('sonstiges'); } else if (typeof parsed.open_topics === 'string' && parsed.open_topics.trim()) { openTopics = parsed.open_topics.trim(); detectedTools.push('sonstiges'); } }
      if (Array.isArray(parsed.detected_dates)) {
        detectedDates = parsed.detected_dates.filter(d => d.date).map(d => {
        const dt = d.date.toString().trim();
        // YYYY-MM-DD
        if (/^\d{4}-\d{2}-\d{2}$/.test(dt)) return {...d, date: dt};
        // DD.MM.YYYY
        const m = dt.match(/^(\d{2})\.(\d{2})\.(\d{4})$/);
        if (m) return {...d, date: `${m[3]}-${m[2]}-${m[1]}`};
        return null;
      }).filter(Boolean);
      }
    }
  } catch (e) { console.error('Tool detection error:', e.message); }
  return { detectedTools, openTopics, detectedDates };
}
// ─────────────────────────────────────────────────────────────────────────────

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
              .select("id, from_email, subject, body_text, body_html, body_preview, received_at, in_reply_to_message_id, user_id");

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
                const rawText = mail.body_text ?? '';
                if (!rawText.trim()) continue;

                const cleanInput = rawText
                  .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
                  .replace(/\r\n/g, '\n')
                  .replace(/\r/g, '\n');

                const isHtmlMail = !!(mail.body_html && mail.body_html.trim());

                const prompt = isHtmlMail
                  ? `Diese E-Mail wurde aus HTML in Text konvertiert. Fasse die wichtigsten Informationen übersichtlich auf Deutsch zusammen. Verwende kurze Absätze oder Stichpunkte wo sinnvoll. Entferne technische Artefakte und unwichtige Details. Gib nur die aufbereitete Version zurück, ohne Erklärung, ohne Anführungszeichen, ohne Markdown.

E-Mail:
${cleanInput.slice(0, 3000)}`
                  : `Extrahiere aus dieser E-Mail nur den eigentlichen neuen Text der aktuellen Nachricht. Entferne vollständig: zitierte Vorgänger-Mails (Zeilen die mit > beginnen), automatische Signaturen, "Von:", "Gesendet:", "An:", "Betreff:" Header-Blöcke von zitierten Mails, und typische Trennlinien wie "---" oder "___" die Zitate einleiten. Gib nur den bereinigten Text zurück, ohne Erklärung, ohne Anführungszeichen, ohne Markdown.

E-Mail:
${cleanInput.slice(0, 3000)}`;

                try {
                  let cleanResponse;
                  for (let attempt = 0; attempt < 3; attempt++) {
                    cleanResponse = await fetch('https://api.anthropic.com/v1/messages', {
                      method: 'POST',
                      headers: {
                        'Content-Type': 'application/json',
                        'x-api-key': process.env.ANTHROPIC_API_KEY,
                        'anthropic-version': '2023-06-01',
                      },
                      body: JSON.stringify({
                        model: 'claude-haiku-4-5-20251001',
                        max_tokens: 1024,
                        messages: [{
                          role: 'user',
                          content: prompt
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
                      .from('mail_messages')
                      .update({ body_clean: bodyClean })
                      .eq('id', mail.id);
                    console.log(`body_clean set for mail ${mail.id} (${isHtmlMail ? 'html-mail' : 'text-mail'})`);
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

                // Tool Detection für diese Mail
                try {
                  const toolResult = await runToolDetection(mail);
                  aiPayload.detected_tools = toolResult.detectedTools;
                  aiPayload.open_topics = toolResult.openTopics;
                  aiPayload.detected_dates = toolResult.detectedDates;
                  console.log(`Dritter Loop: tool detection für ${mail.from_email}: ${JSON.stringify(toolResult.detectedTools)}`);
                } catch (e) {
                  console.error(`Dritter Loop: tool detection error:`, e.message);
                }

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

                  // KI-Analyse via shared helper
                  const toolResult = await runToolDetection(mail);
                  const detectedTools = toolResult.detectedTools;
                  const openTopics = toolResult.openTopics;
                  const detectedDates = toolResult.detectedDates;

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
                        open_topics: openTopics,
                        detected_dates: detectedDates,
                      },
                    });

                  console.log(`wait_for_reply ${action.id} completed, answer_reply created for ${clientName}, detected_tools: ${JSON.stringify(detectedTools)}`);
                }
              }

              // Vierter Loop — Bekannte Kunden ohne wait_for_reply
              console.log(`Vierter Loop: checking ${insertedMails.length} mails for known clients`);
              for (const mail of insertedMails) {
                console.log(`Vierter Loop: checking mail from ${mail.from_email}`);
                if (!mail.from_email) continue;

                const { data: matchedClients } = await supabaseAdmin
                  .from('clients')
                  .select('id, email, first_name, name')
                  .eq('user_id', mail.user_id)
                  .ilike('email', mail.from_email);

                if (!matchedClients?.length) continue;

                const matchedClient = matchedClients[0];
                const clientName4 = matchedClient.first_name
                  ? `${matchedClient.first_name}${matchedClient.name ? ' ' + matchedClient.name : ''}`
                  : matchedClient.email;

                const { data: openJobs } = await supabaseAdmin
                  .from('jobs')
                  .select('id')
                  .eq('user_id', mail.user_id)
                  .eq('client_id', matchedClient.id)
                  .in('status', ['active', 'open', 'in_progress'])
                  .order('created_at', { ascending: false })
                  .limit(1);

                const jobId4 = openJobs?.[0]?.id ?? null;

                // Bereits eine action für genau diese Mail?
                const { data: existingByMail } = await supabaseAdmin
                  .from('job_actions')
                  .select('id')
                  .eq('user_id', mail.user_id)
                  .filter('payload->>mail_message_id', 'eq', mail.id);

                if (existingByMail?.length) {
                  console.log(`Known client ${clientName4}: mail ${mail.id} already has a job_action, skipping`);
                  continue;
                }

                const toolResult = await runToolDetection(mail);

                await supabaseAdmin
                  .from('job_actions')
                  .insert({
                    user_id: mail.user_id,
                    job_id: jobId4,
                    client_id: matchedClient.id,
                    title: `Mail von ${clientName4} beantworten`,
                    description: '',
                    page_key: 'answer_reply',
                    action_type: 'standard',
                    status: 'active',
                    sort_order: 2,
                    activated_at: new Date().toISOString(),
                    payload: {
                      mail_message_id: mail.id,
                      detected_tools: toolResult.detectedTools,
                      open_topics: toolResult.openTopics,
                      detected_dates: toolResult.detectedDates,
                    },
                  });

                console.log(`Known client ${clientName4}: answer_reply created, tools: ${JSON.stringify(toolResult.detectedTools)}, dates: ${JSON.stringify(toolResult.detectedDates)}`);
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
    const { user_id, job_id, client_id, task, active_tools } = req.body;
    // active_tools aus Body oder aus task-Inhalt ableiten
    let activeTools = Array.isArray(active_tools) && active_tools.length > 0
      ? active_tools
      : [];
    // Fallback: Tools aus task-Inhalt erkennen
    if (activeTools.length === 0 && task) {
      if (task.includes('Verfügbarkeitsprüfung')) activeTools.push('availability');
      if (task.includes('Terminvorschläge')) activeTools.push('appointment_suggestion');
      if (task.includes('Preisliste')) activeTools.push('price_list');
      if (task.includes('Angebotspositionen')) activeTools.push('offer');
    }
    console.log('ai-compose: active_tools resolved:', JSON.stringify(activeTools));
    let { mail_history } = req.body;
    if (!user_id) return res.status(400).json({ error: "user_id required" });

    // ── Mailverlauf serverseitig laden (falls vom Client nicht mitgegeben) ──
    if ((!mail_history || !mail_history.trim()) && client_id) {
      const { data: msgs } = await supabaseAdmin
        .from("mail_messages")
        .select("direction, from_email, to_email, subject, body_clean, body_text, created_at")
        .eq("client_id", client_id)
        .order("created_at", { ascending: true })
        .limit(20);

      if (msgs && msgs.length > 0) {
        mail_history = msgs
          .map((m) => {
            const sender = m.direction === "incoming" ? "Kunde" : "Ich";
            const body = (m.body_clean || m.body_text || "").trim();
            return `${sender} (${m.subject || "ohne Betreff"}):\n${body}`;
          })
          .join("\n\n---\n\n");
      }
    }

    // ── Tool-Definitionen (gefiltert nach activeTools) ──────────────────────
    const allTools = [
      {
        name: "get_office_hours",
        onlyFor: ["appointment_suggestion"],
        description: "Gibt die Bürozeiten des Nutzers zurück (Wochentage + Von/Bis-Zeiten).",
        input_schema: { type: "object", properties: {}, required: [] },
      },
      {
        name: "get_calendar_events",
        onlyFor: ["availability"],
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
        onlyFor: null, // immer verfügbar
        description: "Gibt Name, E-Mail und Notizen zum Kunden zurück.",
        input_schema: { type: "object", properties: {}, required: [] },
      },
      {
        name: "get_job_info",
        onlyFor: null, // immer verfügbar
        description: "Gibt Details zum aktuellen Job zurück (Titel, Datum, Notizen).",
        input_schema: { type: "object", properties: {}, required: [] },
      },
    ];
    const tools = allTools.filter(t => !t.onlyFor || t.onlyFor.some(k => activeTools.includes(k))).map(({ onlyFor, ...rest }) => rest);

    // ── Freie Slots serverseitig berechnen ──────────────────────────────────
    async function computeFreeSlots(maxSlots = 3, weeksAhead = 6) {
      // Bürozeiten laden
      const { data: settings } = await supabaseAdmin
        .from("user_settings")
        .select("office_hours")
        .eq("user_id", user_id)
        .maybeSingle();
      const officeHours = settings?.office_hours ?? [];
      if (officeHours.length === 0) return [];

      // Kalender-Events laden
      const fromDate = new Date(now);
      fromDate.setDate(fromDate.getDate() + 1);
      const toDate = new Date(now);
      toDate.setDate(toDate.getDate() + weeksAhead * 7);
      const fromStr = fromDate.toISOString().split("T")[0];
      const toStr = toDate.toISOString().split("T")[0];

      const { data: timedEvents } = await supabaseAdmin
        .from("calendar_events")
        .select("start_at, end_at, all_day, all_day_start_date, all_day_end_date")
        .eq("user_id", user_id)
        .not("status", "in", '("declined","cancelled")')
        .gte("start_at", fromStr)
        .lte("start_at", toStr + "T23:59:59Z");

      const { data: allDayEvents } = await supabaseAdmin
        .from("calendar_events")
        .select("start_at, end_at, all_day, all_day_start_date, all_day_end_date")
        .eq("user_id", user_id)
        .eq("all_day", true)
        .not("status", "in", '("declined","cancelled")')
        .gte("all_day_start_date", fromStr)
        .lte("all_day_start_date", toStr);

      // Belegte Daten als Set (YYYY-MM-DD)
      const busyDates = new Set();
      for (const e of (timedEvents ?? [])) {
        if (e.start_at) busyDates.add(e.start_at.split("T")[0]);
      }
      for (const e of (allDayEvents ?? [])) {
        if (e.all_day_start_date) busyDates.add(e.all_day_start_date);
      }

      // JS weekday: 0=Sonntag, 1=Montag ... 6=Samstag
      // Unsere Kodierung: 1=Montag ... 7=Sonntag
      const toJsWeekday = (d) => d === 7 ? 0 : d;

      const slots = [];
      const cursor = new Date(fromDate);
      while (slots.length < maxSlots && cursor <= toDate) {
        const jsDay = cursor.getDay();
        const dateStr = cursor.toISOString().split("T")[0];

        for (const rule of officeHours) {
          const ruleJsDays = (rule.weekdays ?? []).map(d =>
            typeof d === "number" ? toJsWeekday(d) : ["Sonntag","Montag","Dienstag","Mittwoch","Donnerstag","Freitag","Samstag"].indexOf(d)
          );
          if (ruleJsDays.includes(jsDay) && !busyDates.has(dateStr)) {
            // Frühest mögliche Uhrzeit in der Bürozeit
            const fromH = parseInt((rule.from ?? "08:00").split(":")[0]);
            const fromMin = parseInt((rule.from ?? "08:00").split(":")[1] ?? "0");
            const slotStart = fromH * 60 + fromMin;
            const slotEnd = slotStart + 60; // mind. 1 Stunde frei danach

            // Prüfe zeitgenaue Events auf Überlappung
            let blocked = false;
            for (const e of (timedEvents ?? [])) {
              if (!e.start_at) continue;
              if (!e.start_at.startsWith(dateStr)) continue;
              const eStartH = parseInt(e.start_at.split("T")[1]?.split(":")[0] ?? "0");
              const eStartMin = parseInt(e.start_at.split("T")[1]?.split(":")[1] ?? "0");
              const eStart = eStartH * 60 + eStartMin;
              // Blockiert wenn Event innerhalb der nächsten Stunde nach slotStart beginnt
              if (eStart >= slotStart && eStart < slotEnd) {
                blocked = true;
                break;
              }
            }

            if (!blocked) {
              const timeStr = `${String(fromH).padStart(2,"0")}:${String(fromMin).padStart(2,"0")}`;
              const [y, m, d2] = dateStr.split("-");
              slots.push(`${d2}.${m}.${y} ${timeStr}`);
              break;
            }
          }
        }
        cursor.setDate(cursor.getDate() + 1);
      }
      return slots;
    }

    // ── Tool-Implementierungen ───────────────────────────────────────────────
    async function executeTool(name, input) {
      if (name === "get_office_hours") {
        const { data } = await supabaseAdmin
          .from("user_settings")
          .select("office_hours")
          .eq("user_id", user_id)
          .maybeSingle();
        const dayNames = ["", "Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag", "Sonntag"];
        const hours = data?.office_hours ?? [];
        return hours.map(entry => ({
          ...entry,
          weekdays: entry.weekdays.map(d => dayNames[d] ?? d),
        }));
      }

      if (name === "get_calendar_events") {
        // Normale Termine (mit start_at)
        const { data: timed } = await supabaseAdmin
          .from("calendar_events")
          .select("title, start_at, end_at, all_day, all_day_start_date, all_day_end_date, status")
          .eq("user_id", user_id)
          .not("status", "in", '("declined","cancelled")')
          .gte("start_at", input.from)
          .lte("start_at", input.to + "T23:59:59Z")
          .order("start_at");

        // Ganztägige Termine (all_day_start_date)
        const { data: allDay } = await supabaseAdmin
          .from("calendar_events")
          .select("title, start_at, end_at, all_day, all_day_start_date, all_day_end_date, status")
          .eq("user_id", user_id)
          .eq("all_day", true)
          .not("status", "in", '("declined","cancelled")')
          .gte("all_day_start_date", input.from)
          .lte("all_day_start_date", input.to)
          .order("all_day_start_date");

        return [...(timed ?? []), ...(allDay ?? [])];
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

    // ── Terminvorschläge: direkt serverseitig berechnen ─────────────────────
    const now = new Date();
    if (task && task.includes("Termine")) {
      const slots = await computeFreeSlots(3, 6);
      if (slots.length === 0) {
        return res.json({ ok: true, text: "Keine freien Termine gefunden." });
      }
      return res.json({ ok: true, text: slots.join("\n") });
    }

    // ── Agentic Loop ─────────────────────────────────────────────────────────
    const today = now.toISOString().split("T")[0];
    const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString().split("T")[0];
    const messages = [
      {
        role: "user",
        content: `Heute ist der ${today}, aktuelle Uhrzeit: ${now.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit", timeZone: "Europe/Berlin" })} Uhr (Europe/Berlin).

WICHTIG: Schlage NUR Termine vor die in der Zukunft liegen. Der früheste mögliche Tag ist morgen (${tomorrow}). Heute (${today}) darf NICHT vorgeschlagen werden, auch wenn noch Bürozeit übrig ist.

Wochentag-Kodierung in den Bürozeiten: 1=Montag, 2=Dienstag, 3=Mittwoch, 4=Donnerstag, 5=Freitag, 6=Samstag, 7=Sonntag.

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
          console.log(`ai-compose: calling tool ${block.name}`, JSON.stringify(block.input));
          const result = await executeTool(block.name, block.input);
          console.log(`ai-compose: tool result ${block.name}:`, JSON.stringify(result));
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

app.post("/link-mail-to-job", async (req, res) => {
  try {
    const { jwt, system_action_id, client_id, job_id } = req.body || {};

    if (!jwt || !system_action_id || !client_id) {
      return res.status(400).json({ error: "Missing required fields: jwt, system_action_id, client_id" });
    }

    const supabaseUser = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY,
      { global: { headers: { Authorization: `Bearer ${jwt}` } } }
    );

    const { data: userData, error: userErr } = await supabaseUser.auth.getUser();
    if (userErr || !userData?.user) {
      return res.status(401).json({ error: "Invalid user" });
    }

    // System action laden um bestehenden payload zu erhalten
    const { data: existingAction, error: fetchErr } = await supabaseAdmin
      .from("system_actions")
      .select("payload, mail_message_id")
      .eq("id", system_action_id)
      .eq("user_id", userData.user.id)
      .single();

    if (fetchErr || !existingAction) {
      return res.status(404).json({ error: "system_action not found" });
    }

    // Tool detection auf der Mail ausführen
    let detectedTools = [];
    let openTopics = [];
    let detectedDates = [];

    if (existingAction.mail_message_id) {
      const { data: mail } = await supabaseAdmin
        .from("mail_messages")
        .select("body_text, body_clean, subject, from_email, sent_at, received_at")
        .eq("id", existingAction.mail_message_id)
        .single();

      if (mail) {
        try {
          const toolResult = await runToolDetection(mail);
          detectedTools = toolResult.detectedTools;
          openTopics = toolResult.openTopics;
          detectedDates = toolResult.detectedDates;
        } catch (e) {
          console.error("Tool detection error:", e.message);
        }
      }
    }

    // System action updaten mit client_id, job_id und payload
    const updatedPayload = {
      ...(existingAction.payload ?? {}),
      client_id,
      job_id: job_id ?? null,
      mail_message_id: existingAction.mail_message_id,
      detected_tools: detectedTools,
      open_topics: openTopics,
      detected_dates: detectedDates,
    };

    const { error: updateErr } = await supabaseAdmin
      .from("system_actions")
      .update({
        page_key: "answer_reply",
        status: "active",
        payload: updatedPayload,
      })
      .eq("id", system_action_id)
      .eq("user_id", userData.user.id);

    if (updateErr) {
      return res.status(500).json({ error: updateErr.message });
    }

    // Mail message mit client_id und job_id verknüpfen
    if (existingAction.mail_message_id) {
      await supabaseAdmin
        .from("mail_messages")
        .update({
          client_id,
          job_id: job_id ?? null,
        })
        .eq("id", existingAction.mail_message_id);
    }

    console.log(`link-mail-to-job: system_action ${system_action_id} → client ${client_id}, job ${job_id ?? "none"}, tools: ${JSON.stringify(detectedTools)}`);
    return res.json({ ok: true, detected_tools: detectedTools });

  } catch (e) {
    console.error("link-mail-to-job error:", e);
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
});


app.post('/activate-mail-action', async (req, res) => {
  try {
    const { jwt, job_action_id, system_action_id } = req.body || {};
    if (!jwt || (!job_action_id && !system_action_id)) {
      return res.status(400).json({ error: 'Missing required fields: jwt + job_action_id or system_action_id' });
    }

    const supabaseUser = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY,
      { global: { headers: { Authorization: `Bearer ${jwt}` } } }
    );

    const { data: userData, error: userErr } = await supabaseUser.auth.getUser();
    if (userErr || !userData?.user) {
      return res.status(401).json({ error: 'Invalid user' });
    }

    let action;
    if (job_action_id) {
      // Direkt per job_action_id
      const { data } = await supabaseAdmin
        .from('job_actions')
        .select('id, payload')
        .eq('id', job_action_id)
        .eq('user_id', userData.user.id)
        .single();
      action = data;
    } else {
      // Via system_action_id die zugehörige job_action finden
      const { data: sysAction } = await supabaseAdmin
        .from('system_actions')
        .select('mail_message_id')
        .eq('id', system_action_id)
        .eq('user_id', userData.user.id)
        .single();
      if (sysAction?.mail_message_id) {
        const { data } = await supabaseAdmin
          .from('job_actions')
          .select('id, payload')
          .eq('user_id', userData.user.id)
          .filter('payload->>mail_message_id', 'eq', sysAction.mail_message_id)
          .order('created_at', { ascending: false })
          .limit(1)
          .single();
        action = data;
      }
    }

    if (!action) return res.status(404).json({ error: 'job_action not found' });

    const mailMessageId = action.payload?.mail_message_id;
    if (!mailMessageId) return res.status(400).json({ error: 'No mail_message_id in payload' });

    // Mail laden
    const { data: mail } = await supabaseAdmin
      .from('mail_messages')
      .select('id, subject, body_text, body_clean')
      .eq('id', mailMessageId)
      .single();

    if (!mail) return res.status(404).json({ error: 'mail not found' });

    // Tool Detection — body_clean bevorzugen wenn vorhanden
    const mailForDetection = {
      ...mail,
      body_text: (mail.body_clean && mail.body_clean.trim()) ? mail.body_clean : mail.body_text,
    };

    const toolResult = await runToolDetection(mailForDetection);

    // payload updaten
    const updatedPayload = {
      ...(action.payload ?? {}),
      detected_tools: toolResult.detectedTools,
      open_topics: toolResult.openTopics,
      detected_dates: toolResult.detectedDates,
    };

    await supabaseAdmin
      .from('job_actions')
      .update({ payload: updatedPayload })
      .eq('id', job_action_id);

    console.log(`activate-mail-action: job_action ${job_action_id} → tools: ${JSON.stringify(toolResult.detectedTools)}, dates: ${JSON.stringify(toolResult.detectedDates)}`);
    return res.json({ ok: true, detected_tools: toolResult.detectedTools, detected_dates: toolResult.detectedDates });

  } catch (e) {
    console.error('activate-mail-action error:', e);
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
});

app.listen(PORT, () => {
  console.log(`Mail Service läuft auf Port ${PORT}`);
});
// Temporärer Endpoint: body_clean für eine Mail neu generieren
app.post("/retry-body-clean", async (req, res) => {
  try {
    const { mail_message_id } = req.body || {};
    if (!mail_message_id) return res.status(400).json({ error: "mail_message_id required" });

    const { data: mail } = await supabaseAdmin
      .from("mail_messages")
      .select("id, body_text, body_html")
      .eq("id", mail_message_id)
      .single();

    if (!mail) return res.status(404).json({ error: "mail not found" });

    const rawText = mail.body_text ?? "";
    if (!rawText.trim()) return res.json({ ok: false, reason: "no body_text" });

    const cleanInput = rawText
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
      .replace(/\r\n/g, "\n")
      .replace(/\r/g, "\n");

    const isHtmlMail = !!(mail.body_html && mail.body_html.trim());

    const prompt = isHtmlMail
      ? `Diese E-Mail wurde aus HTML in Text konvertiert. Fasse die wichtigsten Informationen übersichtlich auf Deutsch zusammen. Verwende kurze Absätze oder Stichpunkte wo sinnvoll. Entferne technische Artefakte und unwichtige Details. Gib nur die aufbereitete Version zurück, ohne Erklärung, ohne Anführungszeichen, ohne Markdown.\n\nE-Mail:\n${cleanInput.slice(0, 3000)}`
      : `Extrahiere aus dieser E-Mail nur den eigentlichen neuen Text der aktuellen Nachricht. Entferne vollständig: zitierte Vorgänger-Mails, automatische Signaturen, Header-Blöcke von zitierten Mails. Gib nur den bereinigten Text zurück, ohne Erklärung, ohne Anführungszeichen, ohne Markdown.\n\nE-Mail:\n${cleanInput.slice(0, 3000)}`;

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
        messages: [{ role: "user", content: prompt }],
      }),
    });

    const data = await response.json();
    const bodyClean = data.content?.[0]?.text?.trim() ?? null;

    if (!bodyClean) return res.json({ ok: false, reason: "no output from AI" });

    await supabaseAdmin
      .from("mail_messages")
      .update({ body_clean: bodyClean })
      .eq("id", mail_message_id);

    return res.json({ ok: true, isHtmlMail, body_clean: bodyClean });
  } catch (e) {
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
});
