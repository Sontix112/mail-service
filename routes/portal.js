import express from "express";
import { supabaseAdmin, supabaseAsUser } from "../lib/supabase.js";
import { normalizeEmail, clientIp } from "../lib/util.js";
import { newToken, hashToken, newCode, hashesMatch } from "../lib/crypto.js";
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

    if (!entry) return res.status(401).json({ error: "invalid_code" });

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
