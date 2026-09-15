import express from "express";
import { supabaseAdmin, supabaseAsUser } from "../lib/supabase.js";
import { normalizeEmail, clientIp } from "../lib/util.js";
import { newToken, hashToken, newCode, hashesMatch } from "../lib/crypto.js";
import { createHash } from "node:crypto";
import { sendMailAsUser } from "../lib/mailer.js";

export const portalRouter = express.Router();

// ═════════════════════════════════════════════════════════════════════════════
// KUNDENPORTAL — Etappe 2: Zugangskette
//
// Drei Schluessel, bewusst getrennt:
//   Einladungstoken  (Mail-Link, 90 Tage)  -> kann nur gegen eine Session tauschen
//   Session-Token    (14 Tage)             -> darf lesen
//   Aktionscode      (6 Stellen, 10 min)   -> genau eine Unterschrift
//
// Keiner davon wird im Klartext gespeichert, nur als SHA-256. Ein Datenbankleck
// macht damit keinen einzigen Link nutzbar.
// ═════════════════════════════════════════════════════════════════════════════

const PORTAL_BASE_URL = process.env.PORTAL_BASE_URL || "https://selfos.de";





// Einfache Ratenbegrenzung im Speicher. Reicht fuer einen Prozess hinter PM2;
// bei mehreren Instanzen muesste das in die Datenbank wandern.
const rateBuckets = new Map();

function rateLimit(key, maxAttempts, windowMs) {
  const now = Date.now();
  const bucket = rateBuckets.get(key);

  if (!bucket || now > bucket.resetAt) {
    rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }

  if (bucket.count >= maxAttempts) return false;
  bucket.count += 1;
  return true;
}

// Aufräumen, damit die Map nicht unbegrenzt wächst
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateBuckets) {
    if (now > bucket.resetAt) rateBuckets.delete(key);
  }
}, 10 * 60 * 1000).unref?.();

async function logPortalEvent(userId, accessId, type, req, meta = {}) {
  try {
    await supabaseAdmin.from("portal_events").insert({
      user_id: userId,
      portal_access_id: accessId,
      type,
      ip: clientIp(req),
      user_agent: req.headers["user-agent"] ?? null,
      meta,
    });
  } catch (e) {
    console.error("portal_event failed:", e.message);
  }
}


// Prüft den Session-Token und hängt Zugang + Session an den Request.
async function requirePortalSession(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";

    if (!token) return res.status(401).json({ error: "no_session" });

    const { data: session } = await supabaseAdmin
      .from("portal_sessions")
      .select("id, portal_access_id, expires_at, revoked_at")
      .eq("token_hash", hashToken(token))
      .maybeSingle();

    if (!session || session.revoked_at || new Date(session.expires_at) < new Date()) {
      return res.status(401).json({ error: "session_expired" });
    }

    const { data: access } = await supabaseAdmin
      .from("portal_access")
      .select("*")
      .eq("id", session.portal_access_id)
      .maybeSingle();

    if (!access || access.revoked_at || new Date(access.expires_at) < new Date()) {
      return res.status(401).json({ error: "access_revoked" });
    }

    req.portal = { access, session };

    supabaseAdmin
      .from("portal_access")
      .update({ last_seen_at: new Date().toISOString() })
      .eq("id", access.id)
      .then(() => {}, () => {});

    return next();
  } catch (e) {
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
}

// ── Zugang anlegen (Inhaber) ─────────────────────────────────────────────────
portalRouter.post("/portal/invite", async (req, res) => {
  try {
    const { jwt, job_id } = req.body || {};
    if (!jwt || !job_id) {
      return res.status(400).json({ error: "Missing required fields: jwt, job_id" });
    }

    const supabaseUser = supabaseAsUser(jwt);

    const { data: userData, error: userErr } = await supabaseUser.auth.getUser();
    if (userErr || !userData?.user) {
      return res.status(401).json({ error: "Invalid user" });
    }
    const userId = userData.user.id;

    const { data: job } = await supabaseAdmin
      .from("jobs")
      .select("id, user_id, client_id, title")
      .eq("id", job_id)
      .maybeSingle();

    if (!job || job.user_id !== userId) {
      return res.status(404).json({ error: "job_not_found" });
    }
    if (!job.client_id) {
      return res.status(400).json({ error: "job_without_client" });
    }

    // Empfängeradresse: client_emails ist die Wahrheit, clients.email nur Anzeige
    const { data: primary } = await supabaseAdmin
      .from("client_emails")
      .select("email")
      .eq("user_id", userId)
      .eq("client_id", job.client_id)
      .order("is_primary", { ascending: false })
      .limit(1)
      .maybeSingle();

    const email = normalizeEmail(primary?.email);
    if (!email) {
      return res.status(400).json({ error: "client_without_email" });
    }

    // Vorhandene Zugänge zu diesem Job zurückziehen — es gibt immer nur einen gültigen Link
    await supabaseAdmin
      .from("portal_access")
      .update({ revoked_at: new Date().toISOString() })
      .eq("job_id", job.id)
      .is("revoked_at", null);

    const token = newToken();

    const { data: access, error: accessErr } = await supabaseAdmin
      .from("portal_access")
      .insert({
        user_id: userId,
        job_id: job.id,
        client_id: job.client_id,
        email,
        token_hash: hashToken(token),
      })
      .select("id, expires_at")
      .single();

    if (accessErr) {
      return res.status(500).json({ error: accessErr.message });
    }

    const link = `${PORTAL_BASE_URL}/p/${token}`;

    await sendMailAsUser(
      userId,
      email,
      `Ihr persönlicher Bereich zu „${job.title ?? "Ihrem Projekt"}“`,
      `Hallo,

unter folgendem Link finden Sie alle Informationen zu Ihrem Projekt:

${link}

Dort sehen Sie den aktuellen Stand, Ihren Vertrag und Ihre Rechnungen.
Der Link ist persönlich — bitte geben Sie ihn nicht weiter.

Viele Grüße`
    );

    await logPortalEvent(userId, access.id, "invited", req, { job_id: job.id });

    // Der Klartext-Token wird hier einmalig zurückgegeben und nirgends gespeichert.
    return res.json({
      ok: true,
      portal_access_id: access.id,
      email,
      expires_at: access.expires_at,
      link,
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
});

// ── Einladungstoken gegen Session tauschen ───────────────────────────────────
portalRouter.post("/portal/session", async (req, res) => {
  try {
    const { k } = req.body || {};
    if (!k) return res.status(400).json({ error: "missing_token" });

    if (!rateLimit(`session:${clientIp(req)}`, 30, 15 * 60 * 1000)) {
      return res.status(429).json({ error: "too_many_requests" });
    }

    const { data: access } = await supabaseAdmin
      .from("portal_access")
      .select("*")
      .eq("token_hash", hashToken(k))
      .maybeSingle();

    if (!access || access.revoked_at || new Date(access.expires_at) < new Date()) {
      return res.status(401).json({ error: "invalid_or_expired" });
    }

    const sessionToken = newToken();

    const { data: session, error: sessionErr } = await supabaseAdmin
      .from("portal_sessions")
      .insert({
        portal_access_id: access.id,
        token_hash: hashToken(sessionToken),
        ip: clientIp(req),
        user_agent: req.headers["user-agent"] ?? null,
      })
      .select("expires_at")
      .single();

    if (sessionErr) return res.status(500).json({ error: sessionErr.message });

    await logPortalEvent(access.user_id, access.id, "login_link", req);

    return res.json({
      ok: true,
      session_token: sessionToken,
      expires_at: session.expires_at,
      job_id: access.job_id,
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
});

// ── Code anfordern ───────────────────────────────────────────────────────────
portalRouter.post("/portal/login/request", async (req, res) => {
  // Antwortet absichtlich IMMER mit ok. Sonst liesse sich über diesen Endpoint
  // herausfinden, wer Kunde ist.
  const okResponse = { ok: true };

  try {
    const email = normalizeEmail(req.body?.email);
    if (!email) return res.json(okResponse);

    if (!rateLimit(`loginreq:${clientIp(req)}`, 10, 15 * 60 * 1000)) {
      return res.json(okResponse);
    }
    if (!rateLimit(`loginreq:mail:${email}`, 5, 15 * 60 * 1000)) {
      return res.json(okResponse);
    }

    const { data: accesses } = await supabaseAdmin
      .from("portal_access")
      .select("*")
      .eq("email", email)
      .is("revoked_at", null)
      .gt("expires_at", new Date().toISOString())
      .order("created_at", { ascending: false })
      .limit(1);

    const access = accesses?.[0];
    if (!access) return res.json(okResponse);

    const code = newCode();

    await supabaseAdmin.from("portal_codes").insert({
      portal_access_id: access.id,
      code_hash: hashToken(code),
      purpose: "login",
    });

    await sendMailAsUser(
      access.user_id,
      email,
      "Ihr Anmeldecode",
      `Hallo,

Ihr Anmeldecode lautet: ${code}

Der Code ist 10 Minuten gültig.
Wenn Sie ihn nicht angefordert haben, können Sie diese Mail ignorieren.

Viele Grüße`
    );

    await logPortalEvent(access.user_id, access.id, "code_requested", req, {
      purpose: "login",
    });

    return res.json(okResponse);
  } catch (e) {
    console.error("portal login request failed:", e.message);
    return res.json(okResponse);
  }
});

// ── Code einlösen ────────────────────────────────────────────────────────────
portalRouter.post("/portal/login/verify", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const code = String(req.body?.code ?? "").trim();

    if (!email || !code) return res.status(400).json({ error: "missing_fields" });

    if (!rateLimit(`loginver:${clientIp(req)}`, 20, 15 * 60 * 1000)) {
      return res.status(429).json({ error: "too_many_requests" });
    }

    const { data: accesses } = await supabaseAdmin
      .from("portal_access")
      .select("*")
      .eq("email", email)
      .is("revoked_at", null)
      .gt("expires_at", new Date().toISOString())
      .order("created_at", { ascending: false })
      .limit(1);

    const access = accesses?.[0];
    if (!access) return res.status(401).json({ error: "invalid_code" });

    const { data: entry } = await supabaseAdmin
      .from("portal_codes")
      .select("*")
      .eq("portal_access_id", access.id)
      .eq("purpose", "login")
      .is("used_at", null)
      .gt("expires_at", new Date().toISOString())
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (!entry) {
      // Kein gueltiger Code vorhanden: abgelaufen, schon verbraucht oder nie
      // angefordert. Gehoert ins Protokoll — ein Wiederverwendungsversuch ist
      // genau das, was man dort spaeter sehen will.
      await logPortalEvent(access.user_id, access.id, "code_failed", req, {
        grund: "kein_gueltiger_code",
      });
      return res.status(401).json({ error: "invalid_code" });
    }

    if (entry.attempts >= 5) {
      return res.status(401).json({ error: "code_locked" });
    }

    const matches = hashesMatch(hashToken(code), entry.code_hash);

    if (!matches) {
      await supabaseAdmin
        .from("portal_codes")
        .update({ attempts: entry.attempts + 1 })
        .eq("id", entry.id);

      await logPortalEvent(access.user_id, access.id, "code_failed", req);
      return res.status(401).json({ error: "invalid_code" });
    }

    await supabaseAdmin
      .from("portal_codes")
      .update({ used_at: new Date().toISOString() })
      .eq("id", entry.id);

    const sessionToken = newToken();

    const { data: session, error: sessionErr } = await supabaseAdmin
      .from("portal_sessions")
      .insert({
        portal_access_id: access.id,
        token_hash: hashToken(sessionToken),
        ip: clientIp(req),
        user_agent: req.headers["user-agent"] ?? null,
      })
      .select("expires_at")
      .single();

    if (sessionErr) return res.status(500).json({ error: sessionErr.message });

    await logPortalEvent(access.user_id, access.id, "login_code", req);

    return res.json({
      ok: true,
      session_token: sessionToken,
      expires_at: session.expires_at,
      job_id: access.job_id,
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
});

// ── Zugang zurückziehen (Inhaber) ────────────────────────────────────────────
portalRouter.post("/portal/revoke", async (req, res) => {
  try {
    const { jwt, portal_access_id } = req.body || {};
    if (!jwt || !portal_access_id) {
      return res.status(400).json({ error: "missing_fields" });
    }

    const supabaseUser = supabaseAsUser(jwt);

    const { data: userData, error: userErr } = await supabaseUser.auth.getUser();
    if (userErr || !userData?.user) return res.status(401).json({ error: "Invalid user" });

    const now = new Date().toISOString();

    const { data: access } = await supabaseAdmin
      .from("portal_access")
      .select("id, user_id")
      .eq("id", portal_access_id)
      .maybeSingle();

    if (!access || access.user_id !== userData.user.id) {
      return res.status(404).json({ error: "not_found" });
    }

    await supabaseAdmin
      .from("portal_access")
      .update({ revoked_at: now })
      .eq("id", access.id);

    await supabaseAdmin
      .from("portal_sessions")
      .update({ revoked_at: now })
      .eq("portal_access_id", access.id)
      .is("revoked_at", null);

    await logPortalEvent(access.user_id, access.id, "revoked", req);

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
});

// ── Session prüfen (für die Portal-Oberfläche) ───────────────────────────────
portalRouter.get("/portal/me", requirePortalSession, async (req, res) => {
  return res.json({
    ok: true,
    job_id: req.portal.access.job_id,
    email: req.portal.access.email,
    expires_at: req.portal.session.expires_at,
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Etappe 3: Daten für den Kunden
//
// Diese Endpoints liefern bewusst KEINE Tabellenzeilen, sondern eine Auswahl.
// Interne Arbeitsebene bleibt draussen: mail_messages, system_actions,
// job_actions, Meilensteine, Notizen, interne Kalendereintraege.
//
// Jedes Textfeld ist immer vorhanden, fehlende Werte als leerer String —
// sonst zeigt die Oberflaeche irgendwann den Text "null" an.
// ═════════════════════════════════════════════════════════════════════════════

function text(value) {
  if (value === null || value === undefined) return "";
  const s = String(value).trim();
  return s.toLowerCase() === "null" ? "" : s;
}

function money(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

portalRouter.get("/portal/overview", requirePortalSession, async (req, res) => {
  try {
    const { access } = req.portal;

    const [jobRes, clientRes, offersRes, contractsRes, invoicesRes, eventsRes] =
      await Promise.all([
        supabaseAdmin
          .from("jobs")
          .select("id, title, event_date, status")
          .eq("id", access.job_id)
          .maybeSingle(),

        supabaseAdmin
          .from("clients")
          .select("id, first_name, name, email, phone, street, zip, city, country")
          .eq("id", access.client_id)
          .maybeSingle(),

        // Entwuerfe bleiben draussen — ein Angebot wird sichtbar, wenn es
        // den Entwurfsstatus verlassen hat.
        supabaseAdmin
          .from("offers")
          .select("id, title, status, intro_text, closing_text, total_gross, vat_rate, created_at")
          .eq("job_id", access.job_id)
          .neq("status", "draft")
          .order("created_at", { ascending: false }),

        // Ein Vertrag wird sichtbar, sobald er bewusst verschickt wurde.
        // sent_at ist die Freigabe, nicht der Status.
        supabaseAdmin
          .from("contracts")
          .select("id, name, status, total_gross, sent_at, signed_at, created_at")
          .eq("job_id", access.job_id)
          .not("sent_at", "is", null)
          .order("created_at", { ascending: false }),

        supabaseAdmin
          .from("invoices")
          .select("id, invoice_number, invoice_date, due_date, total_gross, status, invoice_type")
          .eq("job_id", access.job_id)
          .neq("status", "draft")
          .order("invoice_date", { ascending: false }),

        // Nur bestaetigte Termine. Vorschlaege sind interner Aushandlungsstand
        // und haben im Portal nichts verloren.
        supabaseAdmin
          .from("calendar_events")
          .select("id, title, start_at, end_at, all_day, all_day_start_date, all_day_end_date, location, job_event_type")
          .eq("job_id", access.job_id)
          .eq("status", "confirmed")
          .order("start_at", { ascending: true }),
      ]);

    const job = jobRes.data;
    if (!job) return res.status(404).json({ error: "job_not_found" });

    const client = clientRes.data ?? {};

    await logPortalEvent(access.user_id, access.id, "overview", req);

    return res.json({
      ok: true,
      projekt: {
        titel: text(job.title),
        termin: text(job.event_date),
      },
      kunde: {
        vorname: text(client.first_name),
        nachname: text(client.name),
        email: text(access.email),
        telefon: text(client.phone),
        strasse: text(client.street),
        plz: text(client.zip),
        ort: text(client.city),
        land: text(client.country),
      },
      angebote: (offersRes.data ?? []).map((o) => ({
        id: o.id,
        titel: text(o.title),
        status: text(o.status),
        summe_brutto: money(o.total_gross),
        datum: text(o.created_at),
      })),
      vertraege: (contractsRes.data ?? []).map((c) => ({
        id: c.id,
        titel: text(c.name),
        status: text(c.signed_at ? "signed" : c.status),
        summe_brutto: money(c.total_gross),
        verschickt_am: text(c.sent_at),
        unterschrieben_am: text(c.signed_at),
      })),
      rechnungen: (invoicesRes.data ?? []).map((r) => ({
        id: r.id,
        nummer: text(r.invoice_number),
        datum: text(r.invoice_date),
        faellig_am: text(r.due_date),
        summe_brutto: money(r.total_gross),
        status: text(r.status),
        art: text(r.invoice_type),
      })),
      termine: (eventsRes.data ?? []).map((e) => ({
        id: e.id,
        titel: text(e.title),
        ganztaegig: Boolean(e.all_day),
        beginn: text(e.all_day ? e.all_day_start_date : e.start_at),
        ende: text(e.all_day ? e.all_day_end_date : e.end_at),
        ort: text(e.location),
        art: text(e.job_event_type),
      })),
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
});

portalRouter.get("/portal/contract/:id", requirePortalSession, async (req, res) => {
  try {
    const { access } = req.portal;

    const { data: contract } = await supabaseAdmin
      .from("contracts")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();

    // Drei Bedingungen, alle noetig: es gibt ihn, er gehoert zu genau diesem
    // Job, und er wurde freigegeben. Die Job-Pruefung ist die wichtigste —
    // ohne sie liesse sich mit einer fremden Vertrags-ID alles auslesen.
    if (!contract || contract.job_id !== access.job_id || !contract.sent_at) {
      return res.status(404).json({ error: "not_found" });
    }

    const [blocksRes, itemsRes, signersRes] = await Promise.all([
      supabaseAdmin
        .from("contract_content_blocks")
        .select("id, parent_id, level, position, content, content_type, display_number")
        .eq("contract_id", contract.id)
        .order("position", { ascending: true }),

      supabaseAdmin
        .from("contract_items")
        .select("id, position, item_type, title, description, price, quantity, unit, is_percentage")
        .eq("contract_id", contract.id)
        .order("position", { ascending: true }),

      supabaseAdmin
        .from("contract_signers")
        .select("id, name, email, sign_order, status, signed_at")
        .eq("contract_id", contract.id)
        .order("sign_order", { ascending: true }),
    ]);

    await logPortalEvent(access.user_id, access.id, "contract_view", req, {
      contract_id: contract.id,
    });

    return res.json({
      ok: true,
      vertrag: {
        id: contract.id,
        titel: text(contract.name),
        ueberschrift: text(contract.title_page_heading),
        leistung_intro: text(contract.leistungsumfang_intro),
        leistung_preis: text(contract.leistungsumfang_preis),
        status: text(contract.signed_at ? "signed" : contract.status),
        summe_brutto: money(contract.total_gross),
        mwst_satz: money(contract.vat_rate),
        anzahlung_brutto: money(contract.deposit_gross),
        restbetrag_brutto: money(contract.remaining_gross),
        verschickt_am: text(contract.sent_at),
        unterschrieben_am: text(contract.signed_at),
        unterschreibbar: !contract.signed_at,
      },
      bloecke: (blocksRes.data ?? []).map((b) => ({
        id: b.id,
        parent_id: b.parent_id,
        ebene: text(b.level),
        position: Number(b.position ?? 0),
        nummer: b.display_number ?? null,
        art: text(b.content_type),
        inhalt: text(b.content),
      })),
      positionen: (itemsRes.data ?? []).map((i) => ({
        id: i.id,
        position: Number(i.position ?? 0),
        art: text(i.item_type),
        titel: text(i.title),
        beschreibung: text(i.description),
        preis: money(i.price),
        menge: money(i.quantity),
        einheit: text(i.unit),
        prozentual: Boolean(i.is_percentage),
      })),
      unterzeichner: (signersRes.data ?? []).map((s) => ({
        id: s.id,
        name: text(s.name),
        email: text(s.email),
        reihenfolge: Number(s.sign_order ?? 1),
        status: text(s.status),
        unterschrieben_am: text(s.signed_at),
      })),
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// Etappe 5: Unterschrift
//
// Der entscheidende Vorgang im ganzen Portal. Alles, was hier passiert, muss
// spaeter nachvollziehbar sein — deshalb wird nicht nur ein Status gesetzt,
// sondern der Vertragstext im Moment der Unterschrift eingefroren und gehasht.
//
// Reihenfolge ist nicht beliebig: signed_at, frozen_html und content_hash
// gehen in EINEM Update raus. Wird signed_at zuerst gesetzt, sperrt der
// Datenbank-Trigger den Vertrag und die Nachtraege schlagen fehl.
// ═════════════════════════════════════════════════════════════════════════════

const MAX_SIGNATURE_BYTES = 2 * 1024 * 1024;

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Baut aus den Bloecken den Vertragstext — einmal als HTML zum Einfrieren,
// einmal als Klartext fuer die Bestaetigungsmail.
function renderContractText(contract, blocks, items) {
  const byParent = new Map();
  for (const b of blocks) {
    const key = b.parent_id ?? "root";
    if (!byParent.has(key)) byParent.set(key, []);
    byParent.get(key).push(b);
  }
  for (const list of byParent.values()) {
    list.sort((a, b) => (a.position ?? 0) - (b.position ?? 0));
  }

  const html = [];
  const plain = [];

  html.push(`<h1>${escapeHtml(contract.title_page_heading || contract.name || "Vertrag")}</h1>`);
  plain.push(String(contract.title_page_heading || contract.name || "Vertrag").toUpperCase());
  plain.push("");

  function walk(parentKey, depth) {
    for (const block of byParent.get(parentKey) ?? []) {
      const nummer = block.display_number ? `${block.display_number}. ` : "";
      const inhalt = String(block.content ?? "").trim();

      if (block.level === "title") {
        html.push(`<h2>${escapeHtml(nummer + inhalt)}</h2>`);
        plain.push("");
        plain.push(nummer + inhalt);
      } else {
        html.push(`<p>${escapeHtml(inhalt).replace(/\n/g, "<br>")}</p>`);
        plain.push(inhalt);
        plain.push("");
      }

      walk(block.id, depth + 1);
    }
  }

  walk("root", 0);

  if (items.length) {
    html.push("<h2>Leistungen</h2>");
    plain.push("");
    plain.push("LEISTUNGEN");
    html.push("<ul>");
    for (const i of items) {
      const menge = i.quantity ? `${i.quantity} x ` : "";
      const zeile = `${menge}${i.title ?? ""} — ${money(i.price).toFixed(2)} EUR`;
      html.push(`<li>${escapeHtml(zeile)}</li>`);
      plain.push("- " + zeile);
    }
    html.push("</ul>");
  }

  const summe = `Gesamtbetrag brutto: ${money(contract.total_gross).toFixed(2)} EUR`;
  html.push(`<p><strong>${escapeHtml(summe)}</strong></p>`);
  plain.push("");
  plain.push(summe);

  return { html: html.join("\n"), plain: plain.join("\n") };
}

async function loadSignableContract(access, contractId) {
  const { data: contract } = await supabaseAdmin
    .from("contracts")
    .select("*")
    .eq("id", contractId)
    .maybeSingle();

  if (!contract || contract.job_id !== access.job_id || !contract.sent_at) {
    return { error: "not_found", status: 404 };
  }
  if (contract.signed_at) {
    return { error: "already_signed", status: 409 };
  }
  return { contract };
}

// ── Bestätigungscode für die Unterschrift anfordern ──────────────────────────
portalRouter.post("/portal/sign/request", requirePortalSession, async (req, res) => {
  try {
    const { access } = req.portal;
    const contractId = req.body?.contract_id;

    if (!contractId) return res.status(400).json({ error: "missing_contract_id" });

    if (!rateLimit(`signreq:${access.id}`, 5, 15 * 60 * 1000)) {
      return res.status(429).json({ error: "too_many_requests" });
    }

    const found = await loadSignableContract(access, contractId);
    if (found.error) return res.status(found.status).json({ error: found.error });

    const code = newCode();

    await supabaseAdmin.from("portal_codes").insert({
      portal_access_id: access.id,
      code_hash: hashToken(code),
      purpose: "sign",
      contract_id: contractId,
    });

    await sendMailAsUser(
      access.user_id,
      access.email,
      "Ihr Bestätigungscode zur Unterschrift",
      `Hallo,

Sie möchten den Vertrag „${found.contract.name ?? ""}“ unterschreiben.

Ihr Bestätigungscode lautet: ${code}

Der Code ist 10 Minuten gültig. Wir fragen ihn ab, damit sicher ist, dass die
Unterschrift wirklich von Ihnen stammt und nicht von jemandem, der zufällig
Ihren Zugangslink hat.

Wenn Sie das nicht waren, unterschreiben Sie bitte nicht und melden Sie sich
bei uns.

Viele Grüße`
    );

    await logPortalEvent(access.user_id, access.id, "sign_code_requested", req, {
      contract_id: contractId,
    });

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
});

// ── Unterschreiben ───────────────────────────────────────────────────────────
portalRouter.post("/portal/sign", requirePortalSession, async (req, res) => {
  try {
    const { access, session } = req.portal;
    const {
      contract_id: contractId,
      code,
      typed_name: typedName,
      signature_base64: signatureBase64,
    } = req.body || {};

    if (!contractId || !code || !typedName) {
      return res.status(400).json({ error: "missing_fields" });
    }

    if (!rateLimit(`sign:${access.id}`, 20, 15 * 60 * 1000)) {
      return res.status(429).json({ error: "too_many_requests" });
    }

    const found = await loadSignableContract(access, contractId);
    if (found.error) return res.status(found.status).json({ error: found.error });
    const contract = found.contract;

    // ── Code prüfen ──
    const { data: entry } = await supabaseAdmin
      .from("portal_codes")
      .select("*")
      .eq("portal_access_id", access.id)
      .eq("purpose", "sign")
      .eq("contract_id", contractId)
      .is("used_at", null)
      .gt("expires_at", new Date().toISOString())
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (!entry) {
      await logPortalEvent(access.user_id, access.id, "sign_code_failed", req, {
        contract_id: contractId,
        grund: "kein_gueltiger_code",
      });
      return res.status(401).json({ error: "invalid_code" });
    }

    if (entry.attempts >= 5) return res.status(401).json({ error: "code_locked" });

    if (!hashesMatch(hashToken(String(code).trim()), entry.code_hash)) {
      await supabaseAdmin
        .from("portal_codes")
        .update({ attempts: entry.attempts + 1 })
        .eq("id", entry.id);

      await logPortalEvent(access.user_id, access.id, "sign_code_failed", req, {
        contract_id: contractId,
      });
      return res.status(401).json({ error: "invalid_code" });
    }

    await supabaseAdmin
      .from("portal_codes")
      .update({ used_at: new Date().toISOString() })
      .eq("id", entry.id);

    // ── Vertragstext einfrieren ──
    const [{ data: blocks }, { data: items }] = await Promise.all([
      supabaseAdmin
        .from("contract_content_blocks")
        .select("id, parent_id, level, position, content, display_number")
        .eq("contract_id", contract.id),
      supabaseAdmin
        .from("contract_items")
        .select("position, item_type, title, description, price, quantity")
        .eq("contract_id", contract.id)
        .order("position", { ascending: true }),
    ]);

    const rendered = renderContractText(contract, blocks ?? [], items ?? []);
    const contentHash = createHash("sha256").update(rendered.html, "utf8").digest("hex");

    // ── Unterschriftsbild ablegen ──
    let signaturePath = null;
    if (signatureBase64) {
      const raw = String(signatureBase64).replace(/^data:image\/png;base64,/, "");
      const bytes = Buffer.from(raw, "base64");

      if (!bytes.length) return res.status(400).json({ error: "signature_unreadable" });
      if (bytes.length > MAX_SIGNATURE_BYTES) {
        return res.status(413).json({ error: "signature_too_large" });
      }

      // Eindeutiger Pfad, upsert aus: eine Unterschrift darf nie ueberschrieben werden.
      signaturePath = `${access.user_id}/${contract.id}/signature-${Date.now()}-${newToken().slice(0, 8)}.png`;

      const { error: upErr } = await supabaseAdmin.storage
        .from("contracts")
        .upload(signaturePath, bytes, { contentType: "image/png", upsert: false });

      if (upErr) {
        return res.status(500).json({ error: "signature_upload_failed", detail: upErr.message });
      }
    }

    // ── Unterzeichner sicherstellen ──
    let { data: signer } = await supabaseAdmin
      .from("contract_signers")
      .select("id")
      .eq("contract_id", contract.id)
      .order("sign_order", { ascending: true })
      .limit(1)
      .maybeSingle();

    if (!signer) {
      const { data: created } = await supabaseAdmin
        .from("contract_signers")
        .insert({
          user_id: access.user_id,
          contract_id: contract.id,
          name: String(typedName).trim(),
          email: access.email,
          sign_order: 1,
        })
        .select("id")
        .single();
      signer = created;
    }

    const now = new Date().toISOString();

    const { error: sigErr } = await supabaseAdmin.from("contract_signatures").insert({
      user_id: access.user_id,
      contract_id: contract.id,
      signer_id: signer?.id ?? null,
      portal_session_id: session.id,
      typed_name: String(typedName).trim(),
      signature_path: signaturePath,
      content_hash: contentHash,
      ip: clientIp(req),
      user_agent: req.headers["user-agent"] ?? null,
      signed_at: now,
    });

    if (sigErr) {
      return res.status(500).json({ error: "signature_insert_failed", detail: sigErr.message });
    }

    // ── Vertrag abschliessen: EIN Update, sonst sperrt der Trigger ──
    const { error: contractErr } = await supabaseAdmin
      .from("contracts")
      .update({
        signed_at: now,
        status: "signed",
        frozen_html: rendered.html,
        content_hash: contentHash,
      })
      .eq("id", contract.id);

    if (contractErr) {
      return res.status(500).json({ error: "contract_update_failed", detail: contractErr.message });
    }

    if (signer?.id) {
      await supabaseAdmin
        .from("contract_signers")
        .update({ status: "signed", signed_at: now })
        .eq("id", signer.id);
    }

    await supabaseAdmin.from("milestones").insert({
      user_id: access.user_id,
      job_id: access.job_id,
      milestone_key: "contract_signed",
      payload: { contract_id: contract.id, content_hash: contentHash },
    });

    // ── Bestaetigung an beide Seiten ──
    // Die Mail ist der dauerhafte Datentraeger: sie enthaelt den vollstaendigen
    // Vertragstext im Zustand der Unterschrift, nicht nur einen Link.
    const protokoll = `--- Protokoll ---
Unterschrieben am: ${new Date(now).toLocaleString("de-DE", { timeZone: "Europe/Berlin" })}
Name: ${String(typedName).trim()}
E-Mail: ${access.email}
IP-Adresse: ${clientIp(req) ?? "unbekannt"}
Geraet: ${req.headers["user-agent"] ?? "unbekannt"}
Pruefsumme des Vertragstextes (SHA-256):
${contentHash}`;

    const mailText = `${rendered.plain}

${protokoll}`;

    try {
      await sendMailAsUser(
        access.user_id,
        access.email,
        `Ihr unterschriebener Vertrag: ${contract.name ?? ""}`,
        `Hallo,

vielen Dank — der Vertrag wurde soeben unterschrieben. Nachfolgend der
vollständige Vertragstext in der Fassung, die Sie unterschrieben haben.
Bitte bewahren Sie diese E-Mail auf.

${mailText}`
      );
    } catch (e) {
      console.error("Bestaetigungsmail an Kunden fehlgeschlagen:", e.message);
    }

    try {
      const { data: account } = await supabaseAdmin
        .from("mail_accounts")
        .select("email")
        .eq("user_id", access.user_id)
        .eq("is_active", true)
        .order("is_default", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (account?.email) {
        await sendMailAsUser(
          access.user_id,
          account.email,
          `Vertrag unterschrieben: ${contract.name ?? ""}`,
          `${String(typedName).trim()} hat den Vertrag unterschrieben.

${mailText}`
        );
      }
    } catch (e) {
      console.error("Benachrichtigung an Inhaber fehlgeschlagen:", e.message);
    }

    await logPortalEvent(access.user_id, access.id, "signed", req, {
      contract_id: contract.id,
      content_hash: contentHash,
    });

    return res.json({
      ok: true,
      contract_id: contract.id,
      signed_at: now,
      content_hash: contentHash,
      signature_gespeichert: Boolean(signaturePath),
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message ?? String(e) });
  }
});
