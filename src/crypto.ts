const enc = new TextEncoder();

export function hex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(text: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}

async function hmacKey(secret: string, purpose: string): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const derived = await crypto.subtle.sign("HMAC", base, enc.encode(purpose));
  return crypto.subtle.importKey("raw", derived, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function hmacHex(secret: string, purpose: string, data: string): Promise<string> {
  const key = await hmacKey(secret, purpose);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(data)));
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(s: string): Uint8Array {
  const pad = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  return Uint8Array.from(atob(pad), (c) => c.charCodeAt(0));
}

export function randomHex(bytes: number): string {
  return hex(crypto.getRandomValues(new Uint8Array(bytes)).buffer as ArrayBuffer);
}

export async function signToken(secret: string, purpose: string, payload: object): Promise<string> {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const key = await hmacKey(secret, purpose);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(body)));
  return `${body}.${b64url(sig)}`;
}

/** Returns the payload when the signature is valid, otherwise null. */
export async function verifyToken(secret: string, purpose: string, token: string): Promise<unknown> {
  const parts = token.split(".");
  if (parts.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(parts[0]) || !/^[A-Za-z0-9_-]+$/.test(parts[1])) return null;
  const key = await hmacKey(secret, purpose);
  let ok: boolean;
  try {
    ok = await crypto.subtle.verify("HMAC", key, fromB64url(parts[1]), enc.encode(parts[0]));
  } catch {
    return null;
  }
  if (!ok) return null;
  try {
    return JSON.parse(new TextDecoder().decode(fromB64url(parts[0])));
  } catch {
    return null;
  }
}

/** Constant-time comparison of two equal-length hex strings. */
export function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
