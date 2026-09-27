import type { Env } from "./env";
import { hmacHex, randomHex, sha256Hex, signToken, timingSafeEqualHex, verifyToken } from "./crypto";
import { MAX_BODY_BYTES, NONCE_RE, UUID_RE, feedbackDigest, validateSubmission } from "./schema";
import { exactOrigin, verifyPage, type Theme, type VerifyParams } from "./verify-page";
import { bumpCursorStatement, incrementCounter } from "./db";
import { MAX_CLASSIFY_ATTEMPTS, classifyItem } from "./classify";

export const LIMITS = {
  attemptsPerIpPerMinute: 10,
  perInstallPerHour: 10,
  perInstallPerDay: 30,
  perIpPerDay: 50,
  globalPerDay: 1000,
  classifyRetriesPerDay: 200,
  keysPerIpPerDay: 5,
  ticketTtlMs: 5 * 60_000,
  retentionDays: 90,
  tombstoneDays: 180,
  ipHashHours: 48,
};

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const TICKET_PURPOSE = "ticket-v1";

type ErrorCode =
  | "invalid_request"
  | "payload_too_large"
  | "invalid_ticket"
  | "ticket_expired"
  | "conflict"
  | "rate_limited"
  | "intake_disabled"
  | "over_capacity"
  | "invalid_install_key"
  | "unauthorized"
  | "not_found"
  | "verification_failed"
  | "internal_error";

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" };

function json(status: number, body: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...JSON_HEADERS, ...extra } });
}

function error(status: number, code: ErrorCode, message: string, retryAfterSeconds?: number): Response {
  const body: Record<string, unknown> = { error: code, message };
  const extra: Record<string, string> = {};
  if (retryAfterSeconds !== undefined) {
    body.retry_after_seconds = retryAfterSeconds;
    extra["retry-after"] = String(retryAfterSeconds);
  }
  return json(status, body, extra);
}

function clientIp(req: Request): string {
  return req.headers.get("cf-connecting-ip") ?? "unknown";
}

async function ipHash(env: Env, req: Request): Promise<string> {
  return (await hmacHex(env.HMAC_SECRET, "ip-v1", clientIp(req))).slice(0, 32);
}

/** Counts a submission or verification attempt; returns a 429 response when over the per-minute limit. */
async function checkAttemptLimit(env: Env, req: Request, now: number): Promise<Response | null> {
  const minute = Math.floor(now / 60_000);
  const count = await incrementCounter(env, `attempt:${await ipHash(env, req)}:${minute}`, (minute + 2) * 60_000);
  if (count > LIMITS.attemptsPerIpPerMinute) {
    return error(429, "rate_limited", "Too many attempts from this network. Wait a minute and try again.", Math.max(1, Math.ceil(((minute + 1) * 60_000 - now) / 1000)));
  }
  return null;
}

/** Reads a JSON body without trusting Content-Length, refusing anything over the byte limit. */
async function readJson(req: Request, maxBytes: number): Promise<{ ok: true; value: unknown } | { ok: false; response: Response }> {
  const type = req.headers.get("content-type") ?? "";
  if (!type.toLowerCase().startsWith("application/json")) {
    return { ok: false, response: error(400, "invalid_request", "Content-Type must be application/json.") };
  }
  const declared = Number(req.headers.get("content-length") ?? "0");
  const tooLarge = () => ({ ok: false as const, response: error(413, "payload_too_large", `The request is larger than ${maxBytes} bytes.`) });
  if (declared > maxBytes) return tooLarge();
  const reader = req.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        return tooLarge();
      }
      chunks.push(value);
    }
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const c of chunks) {
    bytes.set(c, offset);
    offset += c.byteLength;
  }
  try {
    return { ok: true, value: JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes)) };
  } catch {
    return { ok: false, response: error(400, "invalid_request", "The request body is not valid UTF-8 JSON.") };
  }
}

interface TicketPayload {
  v: 1;
  p: "install";
  i: string;
  n: string;
  exp: number;
  j: string;
}

function isTicketPayload(p: unknown): p is TicketPayload {
  const t = p as TicketPayload;
  return typeof t === "object" && t !== null && t.v === 1 && t.p === "install" && typeof t.i === "string" && typeof t.exp === "number" && typeof t.j === "string";
}

// ---------------------------------------------------------------------------------------------
// GET /v1/verify

function handleVerifyPage(req: Request, env: Env): Response {
  const url = new URL(req.url);
  const parentOrigin = exactOrigin(url.searchParams.get("parent_origin"));
  const p = Object.fromEntries(["purpose", "nonce", "install_id"].map((k) => [k, url.searchParams.get(k) ?? ""]));
  let invalid: string | null = null;
  if (!parentOrigin) invalid = "parent_origin must be the exact origin of the Lattice page, such as http://localhost:3045.";
  else if (p.purpose !== "install") invalid = "purpose must be install.";
  else if (!NONCE_RE.test(p.nonce)) invalid = "nonce must be 32 lowercase hex characters.";
  else if (!UUID_RE.test(p.install_id)) invalid = "install_id must be a lowercase UUID.";
  const themeParam = url.searchParams.get("theme") ?? "auto";
  const theme: Theme = themeParam === "light" || themeParam === "dark" ? themeParam : "auto";
  if (!invalid && !["light", "dark", "auto"].includes(themeParam)) invalid = "theme must be light, dark or auto.";
  const params: VerifyParams | null = invalid ? null : ({ ...p, parent_origin: parentOrigin } as VerifyParams);
  return verifyPage(env.TURNSTILE_SITE_KEY, params, invalid, parentOrigin, theme);
}

// ---------------------------------------------------------------------------------------------
// POST /v1/tickets (called by the verify page after Turnstile passes)

async function handleTicket(req: Request, env: Env, now: number): Promise<Response> {
  const limited = await checkAttemptLimit(env, req, now);
  if (limited) return limited;
  const body = await readJson(req, 8192);
  if (!body.ok) return body.response;
  const b = body.value as Record<string, unknown>;
  if (typeof b !== "object" || b === null) return error(400, "invalid_request", "The request body must be a JSON object.");
  const { turnstile_token, purpose, nonce, install_id } = b;
  if (typeof turnstile_token !== "string" || turnstile_token.length === 0 || turnstile_token.length > 2048) return error(400, "invalid_request", "turnstile_token is missing.");
  if (purpose !== "install") return error(400, "invalid_request", "purpose must be install.");
  if (typeof nonce !== "string" || !NONCE_RE.test(nonce)) return error(400, "invalid_request", "nonce must be 32 lowercase hex characters.");
  if (typeof install_id !== "string" || !UUID_RE.test(install_id)) return error(400, "invalid_request", "install_id must be a lowercase UUID.");

  const form = new FormData();
  form.append("secret", env.TURNSTILE_SECRET_KEY);
  form.append("response", turnstile_token);
  form.append("remoteip", clientIp(req));
  form.append("idempotency_key", crypto.randomUUID());
  let outcome: Record<string, unknown>;
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
    outcome = (await res.json()) as Record<string, unknown>;
  } catch {
    return error(503, "verification_failed", "The bot check service could not be reached. Try again.");
  }
  const expectedHost = env.TURNSTILE_HOSTNAME || new URL(req.url).hostname;
  const testKey = env.ALLOW_TURNSTILE_TEST_KEYS === "1" && (outcome.metadata as Record<string, unknown> | undefined)?.result_with_testing_key === true;
  if (outcome.success !== true) return error(403, "verification_failed", "The bot check did not pass. Try again.");
  if (outcome.hostname !== expectedHost) return error(403, "verification_failed", "The bot check was completed on a different site.");
  if (!testKey && outcome.action !== "feedback") return error(403, "verification_failed", "The bot check was for a different action.");

  const exp = now + LIMITS.ticketTtlMs;
  const payload: TicketPayload = { v: 1, p: "install", i: install_id, n: nonce, exp, j: randomHex(16) };
  const ticket = await signToken(env.HMAC_SECRET, TICKET_PURPOSE, payload);
  return json(200, { ticket, expires_at: new Date(exp).toISOString() });
}

// ---------------------------------------------------------------------------------------------
// POST /v1/installs (Lattice server exchanges a ticket for an install key)

async function handleInstall(req: Request, env: Env, now: number): Promise<Response> {
  const body = await readJson(req, 8192);
  if (!body.ok) return body.response;
  const limited = await checkAttemptLimit(env, req, now);
  if (limited) return limited;
  const b = body.value as Record<string, unknown>;
  if (typeof b !== "object" || b === null || Array.isArray(b)) return error(400, "invalid_request", "The request body must be a JSON object.");
  const unknown = Object.keys(b).filter((k) => k !== "install_id" && k !== "ticket");
  if (unknown.length) return error(400, "invalid_request", `Unknown fields: ${unknown.join(", ")}.`);
  const { install_id, ticket } = b;
  if (typeof install_id !== "string" || !UUID_RE.test(install_id)) return error(400, "invalid_request", "install_id must be a lowercase UUID.");
  if (typeof ticket !== "string" || ticket.length > 2048) return error(400, "invalid_request", "ticket must be a string.");

  const payload = await verifyToken(env.HMAC_SECRET, TICKET_PURPOSE, ticket);
  if (!isTicketPayload(payload) || payload.i !== install_id) return error(403, "invalid_ticket", "The verification ticket is not valid. Run the check again.");
  if (payload.exp < now) return error(403, "ticket_expired", "The verification expired. Run the check again.");

  const day = Math.floor(now / DAY);
  const created = await incrementCounter(env, `install:${await ipHash(env, req)}:${day}`, (day + 2) * DAY);
  if (created > LIMITS.keysPerIpPerDay) {
    return error(429, "rate_limited", "Too many Lattice installs have registered from this network today. Try again tomorrow.", Math.max(1, Math.ceil(((day + 1) * DAY - now) / 1000)));
  }

  const installKey = `lfk_${randomHex(32)}`;
  const createdAt = new Date(now).toISOString();
  // The ticket id is stored so a ticket can mint only one key; earlier keys for the install are revoked.
  const [, inserted] = await env.DB.batch([
    env.DB.prepare("UPDATE install_keys SET revoked_at = ? WHERE install_id = ? AND revoked_at IS NULL AND NOT EXISTS (SELECT 1 FROM install_keys WHERE ticket_id = ?)").bind(createdAt, install_id, payload.j),
    env.DB.prepare("INSERT OR IGNORE INTO install_keys (key_hash, install_id, ticket_id, created_at, created_ms) VALUES (?, ?, ?, ?, ?)").bind(await sha256Hex(installKey), install_id, payload.j, createdAt, now),
  ]);
  if (inserted.meta.changes !== 1) return error(403, "invalid_ticket", "This verification was already used. Run the check again.");
  console.log(JSON.stringify({ event: "install_registered" }));
  return json(201, { install_id, install_key: installKey, created_at: createdAt });
}

interface InstallKeyRow {
  key_hash: string;
  install_id: string;
  created_at: string;
  revoked_at: string | null;
}

/** Resolves the Bearer install key, or returns the 401 response to send. */
async function authenticateInstall(req: Request, env: Env): Promise<{ ok: true; key: InstallKeyRow } | { ok: false; response: Response }> {
  const fail = { ok: false as const, response: error(401, "invalid_install_key", "This Lattice install is not registered with the feedback collector, or its key was revoked. Run the check again.") };
  const m = /^Bearer (lfk_[0-9a-f]{64})$/.exec(req.headers.get("authorization") ?? "");
  if (!m) return fail;
  const key = await env.DB.prepare("SELECT key_hash, install_id, created_at, revoked_at FROM install_keys WHERE key_hash = ?").bind(await sha256Hex(m[1])).first<InstallKeyRow>();
  if (!key || key.revoked_at) return fail;
  return { ok: true, key };
}

async function handleInstallMe(req: Request, env: Env): Promise<Response> {
  const auth = await authenticateInstall(req, env);
  if (!auth.ok) return auth.response;
  return json(200, { install_id: auth.key.install_id, created_at: auth.key.created_at });
}

// ---------------------------------------------------------------------------------------------
// POST /v1/feedback

interface StoredRow {
  id: string;
  submission_id: string;
  digest: string;
  received_at: string;
}

function receipt(row: StoredRow, duplicate: boolean): Response {
  return json(duplicate ? 200 : 201, { id: row.id, submission_id: row.submission_id, received_at: row.received_at, duplicate });
}

async function handleSubmit(req: Request, env: Env, ctx: ExecutionContext, now: number): Promise<Response> {
  const body = await readJson(req, MAX_BODY_BYTES);
  if (!body.ok) return body.response;
  const limited = await checkAttemptLimit(env, req, now);
  if (limited) return limited;
  const auth = await authenticateInstall(req, env);
  if (!auth.ok) return auth.response;
  const v = validateSubmission(body.value);
  if (!v.ok) return error(400, "invalid_request", v.message);
  const f = v.feedback;
  if (f.install_id !== auth.key.install_id) return error(401, "invalid_install_key", "This install key belongs to a different Lattice install. Run the check again.");
  // Stored so a retry can be told apart from different content under the same submission_id.
  const digest = await feedbackDigest(f);

  const existing = await env.DB.prepare("SELECT id, submission_id, digest, received_at FROM feedback WHERE submission_id = ?").bind(f.submission_id).first<StoredRow>();
  if (existing) {
    if (existing.digest === digest) return receipt(existing, true);
    return error(409, "conflict", "This submission ID was already used for different content.");
  }
  if (env.INTAKE_DISABLED === "1") return error(503, "intake_disabled", "The feedback collector isn't accepting feedback right now. Your draft is kept; try again later.");

  const id = crypto.randomUUID();
  const ip = await ipHash(env, req);
  const receivedAt = new Date(now).toISOString();
  await env.DB.batch([
    bumpCursorStatement(env),
    env.DB.prepare(
      `INSERT OR IGNORE INTO feedback (id, cursor, submission_id, digest, received_at, received_ms, ip_hash,
         schema_version, install_id, source, category, message, scope, screen, session_ref, lattice_version, provider, model)
       SELECT ?1, (SELECT value FROM seq WHERE name = 'cursor'), ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17
       WHERE (SELECT COUNT(*) FROM feedback WHERE install_id = ?8 AND received_ms > ?5 - ${HOUR}) < ${LIMITS.perInstallPerHour}
         AND (SELECT COUNT(*) FROM feedback WHERE install_id = ?8 AND received_ms > ?5 - ${DAY}) < ${LIMITS.perInstallPerDay}
         AND (SELECT COUNT(*) FROM feedback WHERE ip_hash = ?6 AND received_ms > ?5 - ${DAY}) < ${LIMITS.perIpPerDay}
         AND (SELECT COUNT(*) FROM feedback WHERE received_ms > ?5 - ${DAY}) < ${LIMITS.globalPerDay}`,
    ).bind(
      id, f.submission_id, digest, receivedAt, now, ip,
      f.schema_version, f.install_id, f.source, f.category, f.message, f.scope, f.screen, f.session_ref, f.lattice_version, f.provider, f.model,
    ),
    env.DB.prepare("UPDATE install_keys SET last_used_ms = ? WHERE key_hash = ?").bind(now, auth.key.key_hash),
  ]);

  const stored = await env.DB.prepare("SELECT id, submission_id, digest, received_at FROM feedback WHERE submission_id = ?").bind(f.submission_id).first<StoredRow>();
  if (stored) {
    if (stored.id === id) {
      console.log(JSON.stringify({ event: "accepted", id }));
      ctx.waitUntil(classifyItem(env, id));
      return receipt(stored, false);
    }
    // A concurrent request with the same submission ID won the insert.
    if (stored.digest === digest) return receipt(stored, true);
    return error(409, "conflict", "This submission ID was already used for different content.");
  }
  return rejectionReason(env, f.install_id, ip, now);
}

/** Explains why the conditional insert stored nothing. */
async function rejectionReason(env: Env, installId: string, ip: string, now: number): Promise<Response> {
  const retryAfter = (oldest: number | null, window: number) => Math.max(1, Math.ceil(((oldest ?? now) + window - now) / 1000));
  const q = (where: string, window: number, ...binds: unknown[]) =>
    env.DB.prepare(`SELECT COUNT(*) AS n, MIN(received_ms) AS oldest FROM feedback WHERE ${where} AND received_ms > ?`)
      .bind(...binds, now - window)
      .first<{ n: number; oldest: number | null }>();
  const global = await q("1 = 1", DAY);
  if (global!.n >= LIMITS.globalPerDay) {
    return error(503, "over_capacity", "The feedback collector has reached its daily limit. Your draft is kept; try again later.", retryAfter(global!.oldest, DAY));
  }
  const hour = await q("install_id = ?", HOUR, installId);
  if (hour!.n >= LIMITS.perInstallPerHour) {
    return error(429, "rate_limited", `This Lattice install has sent ${LIMITS.perInstallPerHour} items in the last hour. Try again later.`, retryAfter(hour!.oldest, HOUR));
  }
  const day = await q("install_id = ?", DAY, installId);
  if (day!.n >= LIMITS.perInstallPerDay) {
    return error(429, "rate_limited", `This Lattice install has sent ${LIMITS.perInstallPerDay} items in the last day. Try again later.`, retryAfter(day!.oldest, DAY));
  }
  const ipDay = await q("ip_hash = ?", DAY, ip);
  if (ipDay!.n >= LIMITS.perIpPerDay) {
    return error(429, "rate_limited", "Too many items have been sent from this network today. Try again later.", retryAfter(ipDay!.oldest, DAY));
  }
  // The limits changed between the insert and this check; the client may simply retry.
  return error(429, "rate_limited", "The collector is busy. Try again shortly.", 5);
}

// ---------------------------------------------------------------------------------------------
// GET /v1/changes (the maintainer's read feed)

interface FeedRow {
  id: string;
  cursor: number;
  deleted: number;
  received_at: string;
  schema_version: number;
  submission_id: string;
  install_id: string;
  source: string;
  category: string;
  message: string;
  scope: string;
  screen: string;
  session_ref: string | null;
  lattice_version: string;
  provider: string | null;
  model: string | null;
  classification_state: string;
  off_topic: number | null;
  abusive: number | null;
  classification_reason: string | null;
  classifier_version: string | null;
}

function feedItem(r: FeedRow) {
  if (r.deleted) return { id: r.id, cursor: r.cursor, deleted: true };
  const bool = (n: number | null) => (n === null ? null : n === 1);
  return {
    id: r.id,
    cursor: r.cursor,
    deleted: false,
    received_at: r.received_at,
    schema_version: r.schema_version,
    submission_id: r.submission_id,
    install_id: r.install_id,
    source: r.source,
    category: r.category,
    message: r.message,
    scope: r.scope,
    screen: r.screen,
    session_ref: r.session_ref,
    lattice_version: r.lattice_version,
    provider: r.provider,
    model: r.model,
    classification_state: r.classification_state,
    off_topic: bool(r.off_topic),
    abusive: bool(r.abusive),
    classification_reason: r.classification_reason,
    classifier_version: r.classifier_version,
  };
}

async function authorized(req: Request, env: Env): Promise<boolean> {
  const header = req.headers.get("authorization") ?? "";
  const m = /^Bearer ([\x21-\x7e]{16,512})$/.exec(header);
  if (!m || !env.READ_TOKEN_SHA256) return false;
  return timingSafeEqualHex(await sha256Hex(m[1]), env.READ_TOKEN_SHA256.toLowerCase());
}

async function handleChanges(req: Request, env: Env): Promise<Response> {
  if (!(await authorized(req, env))) return error(401, "unauthorized", "A valid read token is required.");
  const url = new URL(req.url);
  const afterRaw = url.searchParams.get("after") ?? "0";
  const limitRaw = url.searchParams.get("limit") ?? "100";
  if (!/^\d{1,15}$/.test(afterRaw)) return error(400, "invalid_request", "after must be a non-negative integer.");
  if (!/^\d{1,3}$/.test(limitRaw) || Number(limitRaw) < 1 || Number(limitRaw) > 200) return error(400, "invalid_request", "limit must be between 1 and 200.");
  const after = Number(afterRaw);
  const limit = Number(limitRaw);
  const { results } = await env.DB.prepare("SELECT * FROM feedback WHERE cursor > ? ORDER BY cursor ASC LIMIT ?").bind(after, limit + 1).all<FeedRow>();
  const page = results.slice(0, limit);
  return json(200, {
    items: page.map(feedItem),
    next_cursor: page.length ? page[page.length - 1].cursor : after,
    has_more: results.length > limit,
  });
}

// ---------------------------------------------------------------------------------------------
// Scheduled maintenance: classification retries and retention.

export async function maintenance(env: Env, now: number): Promise<void> {
  // Retry pending classifications that the post-accept attempt did not finish.
  const pending = await env.DB.prepare(
    `SELECT id FROM feedback WHERE classification_state = 'pending' AND deleted = 0 AND classify_attempts < ? AND received_ms < ?
     ORDER BY received_ms LIMIT 20`,
  )
    .bind(MAX_CLASSIFY_ATTEMPTS, now - 2 * 60_000)
    .all<{ id: string }>();
  const day = Math.floor(now / DAY);
  for (const { id } of pending.results) {
    const used = await incrementCounter(env, `classify-retry:${day}`, (day + 2) * DAY);
    if (used > LIMITS.classifyRetriesPerDay) break;
    await classifyItem(env, id);
  }

  // Forget IP hashes after 48 hours.
  await env.DB.prepare("UPDATE feedback SET ip_hash = NULL WHERE ip_hash IS NOT NULL AND received_ms < ?").bind(now - LIMITS.ipHashHours * HOUR).run();

  // Past retention, clear content and leave a tombstone so feed readers drop the item.
  const expired = await env.DB.prepare("SELECT id FROM feedback WHERE deleted = 0 AND received_ms < ? LIMIT 200")
    .bind(now - LIMITS.retentionDays * DAY)
    .all<{ id: string }>();
  for (const { id } of expired.results) {
    await env.DB.batch([
      bumpCursorStatement(env),
      env.DB.prepare(
        `UPDATE feedback SET deleted = 1, cursor = (SELECT value FROM seq WHERE name = 'cursor'), ip_hash = NULL,
           install_id = NULL, source = NULL, category = NULL, message = NULL, scope = NULL, screen = NULL, session_ref = NULL,
           lattice_version = NULL, provider = NULL, model = NULL, off_topic = NULL, abusive = NULL, classification_reason = NULL
         WHERE id = ?`,
      ).bind(id),
    ]);
  }

  // Remove tombstones once every reader has had ample time to see them.
  await env.DB.prepare("DELETE FROM feedback WHERE deleted = 1 AND received_ms < ?").bind(now - LIMITS.tombstoneDays * DAY).run();
  await env.DB.prepare("DELETE FROM counters WHERE expires_ms < ?").bind(now).run();
}

// ---------------------------------------------------------------------------------------------

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    const now = Date.now();
    try {
      if (url.pathname === "/v1/health" && req.method === "GET") {
        return json(200, { ok: true, intake: env.INTAKE_DISABLED === "1" ? "disabled" : "enabled", schema_version: 1 });
      }
      if (url.pathname === "/v1/verify" && req.method === "GET") return handleVerifyPage(req, env);
      if (url.pathname === "/v1/tickets" && req.method === "POST") return await handleTicket(req, env, now);
      if (url.pathname === "/v1/installs" && req.method === "POST") return await handleInstall(req, env, now);
      if (url.pathname === "/v1/installs/me" && req.method === "GET") return await handleInstallMe(req, env);
      if (url.pathname === "/v1/feedback" && req.method === "POST") return await handleSubmit(req, env, ctx, now);
      if (url.pathname === "/v1/changes" && req.method === "GET") return await handleChanges(req, env);
      return error(404, "not_found", "Not found.");
    } catch (err) {
      console.log(JSON.stringify({ event: "internal_error", path: url.pathname, error: String(err) }));
      return error(500, "internal_error", "The feedback collector hit an internal error. Your draft is kept; try again later.");
    }
  },

  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(maintenance(env, Date.now()));
  },
} satisfies ExportedHandler<Env>;
