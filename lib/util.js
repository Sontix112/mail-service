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

// IP des Aufrufers hinter dem eigenen nginx.
//
// X-Forwarded-For ist von aussen faelschbar: wer will, schickt den Header
// einfach mit. nginx haengt mit $proxy_add_x_forwarded_for die tatsaechliche
// Verbindungsadresse HINTEN an. Der letzte Eintrag stammt damit immer vom
// eigenen Proxy, alle davor koennen erfunden sein — deshalb der letzte und
// nicht der erste.
export function clientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  const chain = Array.isArray(fwd) ? fwd.join(",") : String(fwd ?? "");
  const entries = chain.split(",").map((s) => s.trim()).filter(Boolean);

  return entries.length
    ? entries[entries.length - 1]
    : req.socket?.remoteAddress ?? null;
}
