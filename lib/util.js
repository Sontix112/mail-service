// Kleine Helfer ohne eigene Abhaengigkeiten.

// Domain einer Mailadresse, klein geschrieben. Null wenn keine Adresse.
export function emailDomain(addr) {
  const m = String(addr ?? "").toLowerCase().trim().match(/@([^@\s>]+)$/);
  return m ? m[1] : null;
}

export function normalizeEmail(addr) {
  const v = String(addr ?? "").toLowerCase().trim();
  return v.includes("@") ? v : null;
}

// IP des Aufrufers, auch hinter einem Reverse Proxy.
export function clientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  const raw = Array.isArray(fwd) ? fwd[0] : (fwd || "").split(",")[0].trim();
  return raw || req.socket?.remoteAddress || null;
}
