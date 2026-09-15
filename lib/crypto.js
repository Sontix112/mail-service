import { webcrypto, randomBytes, randomInt, createHash, timingSafeEqual } from "node:crypto";

// Base64 helper
function fromBase64(base64) {
  return Uint8Array.from(Buffer.from(base64, "base64"));
}

// Decrypt password
export async function decryptPassword(encrypted, secret) {
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
export async function encryptPassword(plainText, secret) {
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

// ── Portal-Schluessel ────────────────────────────────────────────────────────
// Tokens werden nie im Klartext gespeichert, nur als SHA-256.

export function newToken() {
  return randomBytes(32).toString("base64url");
}

export function hashToken(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

export function newCode() {
  return String(randomInt(0, 1_000_000)).padStart(6, "0");
}

// Vergleich in konstanter Zeit, damit sich der richtige Code nicht ueber
// Antwortzeiten erraten laesst.
export function hashesMatch(hexA, hexB) {
  const a = Buffer.from(String(hexA), "hex");
  const b = Buffer.from(String(hexB), "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}
