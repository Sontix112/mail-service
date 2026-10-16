import express from "express";
import { supabaseAdmin, supabaseAsUser } from "../lib/supabase.js";
import { normalizeEmail, clientIp } from "../lib/util.js";
import { newToken, hashToken, newCode, hashesMatch } from "../lib/crypto.js";
import { createHash } from "node:crypto";
import { sendMailAsUser } from "../lib/mailer.js";

export const portalRouter = express.Router();

// ── Lesbare Meldungen fuer die Portal-Oberflaeche ────────────────────────────
// Jede Portal-Antwort bekommt ein Feld "meldung": bei Erfolg ein leerer Text,
// bei Fehlern ein deutscher Satz fuer den Kunden. Die Oberflaeche zeigt nur
// dieses Feld an - nie den technischen Fehlercode und nie ein fehlendes Feld,
// das FlutterFlow sonst als Text "null" darstellt.
const MELDUNGEN = {
  invalid_code: "Der Code ist nicht korrekt oder abgelaufen. Bitte prüfen Sie ihn oder fordern Sie einen neuen an.",
  code_locked: "Zu viele Fehlversuche. Bitte fordern Sie einen neuen Code an.",
  too_many_requests: "Zu viele Versuche in kurzer Zeit. Bitte warten Sie ein paar Minuten.",
  missing_fields: "Bitte geben Sie Ihren vollständigen Namen und den Code ein.",
  missing_contract_id: "Der Vertrag konnte nicht zugeordnet werden. Bitte laden Sie die Seite neu.",
  already_signed: "Dieser Vertrag ist bereits unterschrieben.",
  not_found: "Dieser Vertrag ist nicht (mehr) verfügbar.",
  no_session: "Ihre Sitzung ist abgelaufen. Bitte öffnen Sie den Link aus Ihrer E-Mail erneut.",
  missing_token: "Ihre Sitzung ist abgelaufen. Bitte öffnen Sie den Link aus Ihrer E-Mail erneut.",
  session_expired: "Ihre Sitzung ist abgelaufen. Bitte öffnen Sie den Link aus Ihrer E-Mail erneut.",
  invalid_or_expired: "Der Link ist nicht mehr gültig. Bitte fordern Sie einen neuen an.",
  access_revoked: "Dieser Zugang wurde beendet. Bitte wenden Sie sich direkt an uns.",
  signature_unreadable: "Die Unterschrift konnte nicht gelesen werden. Bitte versuchen Sie es erneut.",
  signature_too_large: "Die Unterschrift ist zu groß. Bitte versuchen Sie es erneut.",
};
const MELDUNG_ALLGEMEIN =
  "Da ist leider etwas schiefgegangen. Bitte versuchen Sie es später erneut oder melden Sie sich bei uns.";

portalRouter.use("/portal", (req, res, next) => {
  // Pfad hier festhalten: innerhalb der Route ist req.path ein anderer.
  const istUnterschrift = req.originalUrl.split("?")[0] === "/portal/sign";
  const json = res.json.bind(res);
  res.json = (body) => {
    if (body && typeof body === "object" && !Array.isArray(body) && !("meldung" in body)) {
      const meldung = body.error
        ? body.message || MELDUNGEN[body.error] || MELDUNG_ALLGEMEIN
        : "";
      body = { ...body, meldung };
      // Beim Unterschreiben liest die Seite signed_at. Fehlt es im
      // Fehlerfall, macht FlutterFlow daraus den Text "null" und haelt den
      // Vertrag fuer unterschrieben - deshalb immer mitliefern.
      if (istUnterschrift && !("signed_at" in body)) body.signed_at = "";
    }
    return json(body);
  };
  next();
});

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
    const { jwt, job_id, send_mail, reuse } = req.body || {};
    if (!jwt || !job_id) {
      return res.status(400).json({ error: "Missing required fields: jwt, job_id" });
    }

    // Mit reuse wird ein bestehender gueltiger Zugang nicht angetastet.
    // Das ist fuer wiederholbare Ablaeufe gedacht: ein zweiter Durchlauf
    // soll den Link nicht entwerten, den der Kunde laengst bekommen hat.
    const wiederverwenden = reuse === true;

    // Standardmaessig verschickt der Endpunkt die Einladung selbst. Wird der
    // Link dagegen in eine Mail eingebaut, die der Nutzer vorher noch prueft,
    // soll hier nichts rausgehen - dann liefert die Antwort nur den Link.
    const mailVerschicken = send_mail !== false;

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

    if (wiederverwenden) {
      // Nur ein bereits ausgelieferter Zugang ist schuetzenswert. Einer, der
      // noch nie verschickt wurde, darf ersetzt werden - den kennt niemand.
      const { data: bestehend } = await supabaseAdmin
        .from("portal_access")
        .select("id, expires_at")
        .eq("job_id", job.id)
        .is("revoked_at", null)
        .not("delivered_at", "is", null)
        .gt("expires_at", new Date().toISOString())
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (bestehend) {
        // Der Klartext-Token existiert nur einmal, bei der Ausgabe. Ein
        // bestehender Zugang laesst sich deshalb bestaetigen, aber sein
        // Link nicht erneut ausgeben - dafuer muesste ein neuer her.
        return res.json({
          ok: true,
          existing: true,
          portal_access_id: bestehend.id,
          email,
          expires_at: bestehend.expires_at,
          link: null,
          mail_sent: false,
        });
      }
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

    if (mailVerschicken) {
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

      // Ab jetzt ist der Link beim Kunden. Er darf nicht mehr stillschweigend
      // durch einen neuen ersetzt werden.
      await supabaseAdmin
        .from("portal_access")
        .update({ delivered_at: new Date().toISOString() })
        .eq("id", access.id);
    }

    await logPortalEvent(userId, access.id, "invited", req, {
      job_id: job.id,
      mail_verschickt: mailVerschicken,
    });

    // Der Klartext-Token wird hier einmalig zurückgegeben und nirgends gespeichert.
    return res.json({
      ok: true,
      portal_access_id: access.id,
      email,
      expires_at: access.expires_at,
      link,
      mail_sent: mailVerschicken,
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

    const uhrzeit = new Date().toLocaleTimeString("de-DE", {
      timeZone: "Europe/Berlin",
      hour: "2-digit",
      minute: "2-digit",
    });

    await sendMailAsUser(
      access.user_id,
      email,
      `Anmeldung im Kundenbereich — Code ${code} (${uhrzeit} Uhr)`,
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

// Anschrift in einer Zeile: "Musterstr. 1, 49074 Osnabrueck".
// Das Land nur, wenn es nicht Deutschland ist - fuer deutsche Kunden waere
// es Rauschen.
function adresseZeile(client) {
  const ortTeil = [text(client?.zip), text(client?.city)].filter(Boolean).join(" ");
  const land = text(client?.country);
  const istDeutschland = !land || /^(de|deu|deutschland|germany)$/i.test(land);
  return [text(client?.street), ortTeil, istDeutschland ? "" : land]
    .filter(Boolean)
    .join(", ");
}

// Vertrags-HTML in Anzeige-Bausteine zerlegen: [{ art, text }].
// art: "titel" (h1), "titelseite" (h3), "ueberschrift" (h2), "absatz" (p), "posten" (li),
// "summe" (p mit <strong>). Der Renderer erzeugt nur diese Tags, daher
// reicht ein einfacher Durchlauf ohne vollstaendigen HTML-Parser.
function htmlZuAbschnitten(html) {
  const entities = (t) =>
    t
      .replace(/<br\s*\/?>/gi, "\n")
      .replace(/<[^>]+>/g, "")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&amp;/g, "&")
      .trim();

  const abschnitte = [];
  const re = /<(h1|h2|h3|p|li)>([\s\S]*?)<\/\1>/gi;
  let m;
  while ((m = re.exec(String(html ?? "")))) {
    const tag = m[1].toLowerCase();
    const inhalt = m[2];
    const text = entities(inhalt);
    if (!text) continue;

    const art =
      tag === "h1" ? "titel"
      : tag === "h3" ? "titelseite"
      : tag === "h2" ? "ueberschrift"
      : tag === "li" ? "posten"
      : /<strong>/i.test(inhalt) ? "summe"
      : "absatz";

    // Zusaetzlich ein eigenes Feld pro Art, nur bei der passenden Art befuellt,
    // sonst null. FlutterFlow knuepft die Sichtbarkeit an "Feld existiert";
    // ein leerer Text gilt bei JSON-Werten dort als vorhanden, null nicht.
    abschnitte.push({
      art,
      text,
      titel: art === "titel" ? text : null,
      titelseite: art === "titelseite" ? text : null,
      ueberschrift: art === "ueberschrift" ? text : null,
      absatz: art === "absatz" ? text : null,
      posten: art === "posten" ? text : null,
      summe: art === "summe" ? text : null,
    });
  }
  return abschnitte;
}

// Eingefrorenes Vertrags-HTML in Lesetext zurueckverwandeln.
// Bewusst simpel: der Text stammt aus unserem eigenen Renderer, enthaelt also
// nur h1/h2/p/ul/li/br und keine Skripte oder Attribute.
function htmlZuText(html) {
  return String(html ?? "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(h1|h2|h3|p|li|ul)>/gi, "\n")
    .replace(/<li>/gi, "- ")
    .replace(/<[^>]+>/g, "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

// Kurzes Anzeigedatum fuer die Terminliste: "11.03." bzw. "11.03., 14:00".
//
// Formatiert wird hier und nicht in der Oberflaeche, weil die Zeitzone sonst
// vom Geraet des Kunden abhaengt — ein Termin um 00:30 waere je nach Handy
// mal der 11., mal der 10. Maerz. Massgeblich ist Europe/Berlin.
function datumKurz(value, ganztaegig) {
  if (!value) return "";

  const d = new Date(ganztaegig ? `${String(value).slice(0, 10)}T12:00:00Z` : value);
  if (Number.isNaN(d.getTime())) return "";

  const opt = { timeZone: "Europe/Berlin", day: "2-digit", month: "2-digit" };
  const tag = new Intl.DateTimeFormat("de-DE", opt).format(d);

  if (ganztaegig) return tag;

  const zeit = new Intl.DateTimeFormat("de-DE", {
    timeZone: "Europe/Berlin",
    hour: "2-digit",
    minute: "2-digit",
  }).format(d);

  return `${tag} ${zeit}`;
}

// Eine Vertrags- oder Angebotsposition in die Portal-Form bringen.
//
// Die Beschreibung ist Freitext, den der Inhaber getippt hat — mal mit
// "-" am Zeilenanfang, mal ohne, mal als Aufzaehlung, mal als Satz.
// Deshalb wird jede Zeile von fuehrenden Strichen befreit und danach
// einheitlich neu gesetzt. Sonst stehen im Portal doppelte Striche.
function itemZuLeistung(item) {
  const details = text(item?.description)
    .split("\n")
    .map((zeile) => zeile.replace(/^\s*[-–•*]\s*/, "").trim())
    .filter(Boolean);

  const menge = Number(item?.quantity);
  const einzel = money(item?.price ?? item?.unit_price_gross);
  const summe = item?.line_total_gross != null
    ? money(item.line_total_gross)
    : einzel * (Number.isFinite(menge) && menge > 0 ? menge : 1);

  return {
    id: text(item?.id),
    titel: text(item?.title),
    details,
    // Fertige Anzeigezeile, damit die Karte im Portal einen Textwert bekommt
    // und die Oberflaeche nicht aus einer Liste Text bauen muss.
    beschreibung: details.join(", "),
    einzelpreis: einzel,
    preis: summe,
    menge: Number.isFinite(menge) ? menge : 1,
    einheit: text(item?.unit),
  };
}

// Anzeigefertiger Block fuer das Portal. Die Oberflaeche bekommt fertigen
// Text, keine Formatierungsaufgabe — FlutterFlow kann in einem Text-Widget
// ohnehin nicht pro Zeile gestalten.
function leistungenAlsText(leistungen) {
  return leistungen
    .map((l) =>
      l.details.length ? `- ${l.titel}: ${l.details.join(", ")}` : `- ${l.titel}`
    )
    .join("\n");
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
    const offers = offersRes.data ?? [];
    const contracts = contractsRes.data ?? [];

    // Kundensicht-Status. Der interne jobs.status ist Arbeitsstand des
    // Inhabers ("lead", "offer_sent", ...) und hat im Portal nichts verloren.
    const signedContract = contracts.find((c) => c.signed_at);
    const projektStatus = signedContract
      ? "Vertrag unterschrieben"
      : contracts.length
        ? "Vertrag liegt zur Unterschrift bereit"
        : offers.length
          ? "Angebot liegt vor"
          : "In Vorbereitung";

    // Leistungsumfang: was tatsaechlich gilt. Vertrag schlaegt Angebot,
    // unterschriebener Vertrag schlaegt verschickten.
    const quelleVertrag = signedContract ?? contracts[0] ?? null;
    let leistungen = [];

    if (quelleVertrag) {
      const { data } = await supabaseAdmin
        .from("contract_items")
        .select("id, title, description, item_type, position, quantity, unit, price")
        .eq("contract_id", quelleVertrag.id)
        .order("position", { ascending: true });

      leistungen = (data ?? [])
        .filter((i) => String(i.item_type ?? "") !== "discount")
        .map(itemZuLeistung);
    } else if (offers.length) {
      const { data } = await supabaseAdmin
        .from("offer_items")
        .select("id, title, description, pos, quantity, unit_price_gross, line_total_gross")
        .eq("offer_id", offers[0].id)
        .order("pos", { ascending: true });

      leistungen = (data ?? []).map(itemZuLeistung);
    }

    leistungen = leistungen.filter((l) => l.titel);

    await logPortalEvent(access.user_id, access.id, "overview", req);

    return res.json({
      ok: true,
      projekt: {
        titel: text(job.title),
        termin: text(job.event_date),
        status: projektStatus,
        leistungsumfang: leistungenAlsText(leistungen),
        leistungen,
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
        // Fertige Anzeigezeilen fuer "Deine Daten". Leere Teile fallen weg,
        // damit nie "Musterstr. 1, , " oder ein einzelnes Komma dasteht.
        name: [text(client.first_name), text(client.name)].filter(Boolean).join(" "),
        adresse: adresseZeile(client),
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
        // Anzeigetext fuer den Kunden. Der Rohstatus ("sent", "signed") ist
        // Systemsprache und gehoert nicht in die Oberflaeche.
        status_text: c.signed_at ? "Unterschrieben" : "Zur Unterschrift bereit",
        summe_brutto: money(c.total_gross),
        verschickt_am: text(c.sent_at),
        // null statt leerem Text: FlutterFlow wertet "" bei JSON-Werten als
        // vorhanden und zeigte den Vertrag sonst als unterzeichnet an.
        unterschrieben_am: c.signed_at ? text(c.signed_at) : null,
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
        datum_kurz: datumKurz(
          e.all_day ? e.all_day_start_date : e.start_at,
          Boolean(e.all_day)
        ),
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

    // Anzeigetext. Bei einem unterschriebenen Vertrag ist frozen_html der
    // verbindliche Stand — dann zeigt das Portal genau den, nicht den aus den
    // aktuellen Bausteinen neu gebauten. Sonst waere der angezeigte Text ein
    // anderer als der unterschriebene, sobald jemand einen Baustein aendert.
    const gerendert = contract.frozen_html
      ? null
      : renderContractText(
          contract,
          blocksRes.data ?? [],
          itemsRes.data ?? [],
          await ladeParteien(contract)
        );

    const vertragstext = contract.frozen_html
      ? htmlZuText(contract.frozen_html)
      : gerendert.plain;

    // Pruefsumme des Standes, der hier gerade ausgeliefert wird. Beim
    // unterschriebenen Vertrag steht sie in der Zeile; davor wird sie aus dem
    // gerenderten Text gebildet - nach derselben Regel wie beim Unterschreiben.
    // Das Portal schickt sie dort zurueck, damit niemand eine Fassung
    // unterschreibt, die er nie zu sehen bekommen hat.
    const pruefsumme = contract.content_hash
      ? contract.content_hash
      : createHash("sha256").update(gerendert.html, "utf8").digest("hex");

    return res.json({
      ok: true,
      vertrag: {
        id: contract.id,
        text: vertragstext,
        // Gegliederte Fassung fuer die Anzeige. Gebaut aus genau dem HTML,
        // ueber das die Pruefsumme laeuft - die schoene Ansicht kann also
        // nichts anderes zeigen als das, was unterschrieben wird.
        abschnitte: htmlZuAbschnitten(contract.frozen_html ?? gerendert.html),
        pruefsumme: pruefsumme,
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
// Vertragsparteien fuer die Titelseite laden: Kunde aus dem Vertrag,
// Auftragnehmer aus den Einstellungen des Inhabers. Dieselbe Quelle wie die
// Titelseite im Vertragseditor der App.
async function ladeParteien(contract) {
  const [kundeRes, ichRes] = await Promise.all([
    contract.client_id
      ? supabaseAdmin
          .from("clients")
          .select("first_name, name, street, zip, city")
          .eq("id", contract.client_id)
          .maybeSingle()
      : Promise.resolve({ data: null }),
    supabaseAdmin
      .from("user_settings")
      .select("first_name, last_name, street, street_number, zip, city")
      .eq("user_id", contract.user_id)
      .maybeSingle(),
  ]);
  return { kunde: kundeRes.data ?? null, ich: ichRes.data ?? null };
}

// Anschriftenblock einer Partei als Zeilen, leere Zeilen fallen weg.
function parteiZeilen(name, strasse, plzOrt) {
  return [name, strasse, plzOrt].map((z) => String(z ?? "").trim()).filter(Boolean);
}

function renderContractText(contract, blocks, items, parteien = {}) {
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

  // ── Titelseite: Kunde "und" Auftragnehmer ──
  // Gehoert zum Vertragstext und damit auch in die Pruefsumme: wer
  // unterschreibt, unterschreibt zwischen genau diesen beiden Parteien.
  const k = parteien.kunde;
  const i = parteien.ich;
  const kundeZeilen = k
    ? parteiZeilen(
        [k.first_name, k.name].filter(Boolean).join(" "),
        k.street,
        [k.zip, k.city].filter(Boolean).join(" ")
      )
    : [];
  const ichZeilen = i
    ? parteiZeilen(
        [i.first_name, i.last_name].filter(Boolean).join(" "),
        [i.street, i.street_number].filter(Boolean).join(" "),
        [i.zip, i.city].filter(Boolean).join(" ")
      )
    : [];

  if (kundeZeilen.length || ichZeilen.length) {
    if (kundeZeilen.length) {
      html.push(`<h3>${kundeZeilen.map(escapeHtml).join("<br>")}</h3>`);
      plain.push(...kundeZeilen);
    }
    html.push("<h3>und</h3>");
    plain.push("", "und", "");
    if (ichZeilen.length) {
      html.push(`<h3>${ichZeilen.map(escapeHtml).join("<br>")}</h3>`);
      plain.push(...ichZeilen);
    }
    plain.push("");
  }

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
      `Vertrag unterschreiben — Code ${code} (${new Date().toLocaleTimeString("de-DE", { timeZone: "Europe/Berlin", hour: "2-digit", minute: "2-digit" })} Uhr)`,
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
      expected_hash: expectedHash,
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

    const rendered = renderContractText(contract, blocks ?? [], items ?? [], await ladeParteien(contract));
    const contentHash = createHash("sha256").update(rendered.html, "utf8").digest("hex");

    // Der Kunde unterschreibt, was auf seinem Bildschirm steht. Wurde der
    // Vertrag geaendert, waehrend das Portal offen war, passt die mitgeschickte
    // Pruefsumme nicht mehr - dann wird abgelehnt, statt stillschweigend eine
    // andere Fassung zu unterschreiben. Diese Pruefung steht bewusst vor dem
    // Entwerten des Codes: der Kunde soll nach dem Neuladen direkt weiter
    // unterschreiben koennen, ohne einen neuen Code anzufordern.
    if (expectedHash && String(expectedHash).trim() !== contentHash) {
      await logPortalEvent(access.user_id, access.id, "sign_hash_mismatch", req, {
        contract_id: contract.id,
        erwartet: String(expectedHash).trim(),
        tatsaechlich: contentHash,
      });
      return res.status(409).json({
        error: "contract_changed",
        message:
          "Der Vertrag wurde zwischenzeitlich geändert. Bitte laden Sie die Seite neu und prüfen Sie den aktuellen Stand.",
      });
    }

    await supabaseAdmin
      .from("portal_codes")
      .update({ used_at: new Date().toISOString() })
      .eq("id", entry.id);

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
