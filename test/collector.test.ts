import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker, { LIMITS, maintenance } from "../src/index";
import { signToken } from "../src/crypto";
import type { Feedback } from "../src/schema";
import { parseVerdict } from "../src/classify";
import type { Env } from "../src/env";

const BASE = "https://collector.test";
const READ_TOKEN = "test-read-token-0123456789";
const PARENT = "http://localhost:3045";

type AiReply = { response: unknown } | Error;
let aiReplies: AiReply[] = [];
let siteverify: Record<string, unknown>;

function testEnv(extra: Partial<Env> = {}): Env {
  const ai = {
    run: vi.fn(async () => {
      const next = aiReplies.shift() ?? { response: '{"relevant": true, "abusive": false, "reason": "About Lattice."}' };
      if (next instanceof Error) throw next;
      return next;
    }),
  };
  return { ...env, AI: ai as unknown as Ai, ...extra };
}

async function call(req: Request, e: Env = testEnv()): Promise<Response> {
  const ctx = createExecutionContext();
  const res = await worker.fetch(req, e, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

function feedback(over: Partial<Feedback> = {}): Feedback {
  return {
    schema_version: 1,
    submission_id: crypto.randomUUID(),
    install_id: crypto.randomUUID(),
    source: "human",
    category: "bug",
    message: "The session list jumps when a new session starts.",
    scope: "app",
    screen: "home",
    session_ref: null,
    lattice_version: "3.2.1",
    provider: "claude",
    model: "claude-opus-5-5",
    ...over,
  };
}

const nonce = () => "ab".repeat(16);

async function mintTicket(installId: string, ip = "203.0.113.1", e?: Env): Promise<Response> {
  return call(
    new Request(`${BASE}/v1/tickets`, {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": ip },
      body: JSON.stringify({ turnstile_token: "tok", purpose: "install", nonce: nonce(), install_id: installId }),
    }),
    e,
  );
}

async function ticketFor(installId: string, ip?: string): Promise<string> {
  const res = await mintTicket(installId, ip);
  expect(res.status).toBe(200);
  return ((await res.json()) as { ticket: string }).ticket;
}

function installRaw(body: unknown, ip = "203.0.113.1"): Promise<Response> {
  return call(new Request(`${BASE}/v1/installs`, { method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": ip }, body: JSON.stringify(body) }));
}

async function register(installId: string, ip?: string): Promise<string> {
  const res = await installRaw({ install_id: installId, ticket: await ticketFor(installId, ip) }, ip);
  expect(res.status).toBe(201);
  return ((await res.json()) as { install_key: string }).install_key;
}

function submitRaw(body: unknown, key: string | null, ip = "203.0.113.1", e?: Env): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json", "cf-connecting-ip": ip };
  if (key) headers.authorization = `Bearer ${key}`;
  return call(new Request(`${BASE}/v1/feedback`, { method: "POST", headers, body: JSON.stringify(body) }), e);
}

const keys = new Map<string, string>();

/** Submits with the install's key, registering the install on first use. */
async function submit(f: Feedback, ip?: string, e?: Env): Promise<Response> {
  let key = keys.get(f.install_id);
  if (!key) {
    key = await register(f.install_id, `10.0.${keys.size >> 8}.${keys.size & 255}`);
    keys.set(f.install_id, key);
  }
  return submitRaw(f, key, ip, e);
}

function changes(after = 0, limit?: number, token: string | null = READ_TOKEN): Promise<Response> {
  const headers: Record<string, string> = token ? { authorization: `Bearer ${token}` } : {};
  return call(new Request(`${BASE}/v1/changes?after=${after}${limit ? `&limit=${limit}` : ""}`, { headers }));
}

async function feedItems(): Promise<Array<Record<string, unknown>>> {
  const res = await changes(0, 200);
  return ((await res.json()) as { items: Array<Record<string, unknown>> }).items;
}

beforeEach(async () => {
  aiReplies = [];
  siteverify = { success: true, hostname: "collector.test", action: "feedback", "error-codes": [] };
  const realFetch = globalThis.fetch;
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url === "https://challenges.cloudflare.com/turnstile/v0/siteverify") return Response.json(siteverify);
    return realFetch(input, init);
  });
  keys.clear();
  await env.DB.batch([env.DB.prepare("DELETE FROM feedback"), env.DB.prepare("DELETE FROM counters"), env.DB.prepare("DELETE FROM install_keys")]);
});

afterEach(() => vi.restoreAllMocks());

describe("health and verify page", () => {
  it("reports health", async () => {
    const res = await call(new Request(`${BASE}/v1/health`));
    expect(await res.json()).toEqual({ ok: true, intake: "enabled", schema_version: 1 });
  });

  it("serves the panel framable only by the declared parent origin", async () => {
    const q = new URLSearchParams({ purpose: "install", nonce: nonce(), install_id: crypto.randomUUID(), parent_origin: PARENT });
    const res = await call(new Request(`${BASE}/v1/verify?${q}`));
    expect(res.status).toBe(200);
    expect(res.headers.get("content-security-policy")).toContain(`frame-ancestors ${PARENT}`);
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    const html = await res.text();
    expect(html).toContain("1x00000000000000000000AA");
    expect(html).not.toContain("postMessage(msg, \"*\")");
  });

  it("matches the embedding page's theme", async () => {
    const q = new URLSearchParams({ purpose: "install", nonce: nonce(), install_id: crypto.randomUUID(), parent_origin: PARENT, theme: "dark" });
    const html = await (await call(new Request(`${BASE}/v1/verify?${q}`))).text();
    expect(html).toContain("color-scheme: dark;");
    expect(html).toContain('"theme":"dark"');
    q.set("theme", "neon");
    expect((await call(new Request(`${BASE}/v1/verify?${q}`))).status).toBe(400);
  });

  it("refuses a parent origin with a path and cannot be framed", async () => {
    const q = new URLSearchParams({ purpose: "install", nonce: nonce(), install_id: crypto.randomUUID(), parent_origin: `${PARENT}/x` });
    const res = await call(new Request(`${BASE}/v1/verify?${q}`));
    expect(res.status).toBe(400);
    expect(res.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
  });
});

describe("tickets and install keys", () => {
  it("rejects a failed Turnstile check", async () => {
    siteverify = { success: false, "error-codes": ["invalid-input-response"] };
    expect((await mintTicket(crypto.randomUUID())).status).toBe(403);
  });

  it("rejects a token solved on another hostname or for another action", async () => {
    siteverify = { success: true, hostname: "evil.test", action: "feedback" };
    expect((await mintTicket(crypto.randomUUID())).status).toBe(403);
    siteverify = { success: true, hostname: "collector.test", action: "login" };
    expect((await mintTicket(crypto.randomUUID())).status).toBe(403);
  });

  it("accepts test-key results only when test keys are allowed", async () => {
    siteverify = { success: true, hostname: "collector.test", metadata: { result_with_testing_key: true } };
    expect((await mintTicket(crypto.randomUUID())).status).toBe(403);
    expect((await mintTicket(crypto.randomUUID(), undefined, testEnv({ ALLOW_TURNSTILE_TEST_KEYS: "1" }))).status).toBe(200);
  });
});

describe("install keys", () => {
  it("issues a key once per ticket, revokes older keys, and checks the key", async () => {
    const install_id = crypto.randomUUID();
    const ticket = await ticketFor(install_id);
    const first = await installRaw({ install_id, ticket });
    expect(first.status).toBe(201);
    const { install_key } = (await first.json()) as { install_key: string };
    expect(install_key).toMatch(/^lfk_[0-9a-f]{64}$/);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM install_keys WHERE key_hash = ?").bind(install_key).first("n")).toBe(0);
    expect(await (await installRaw({ install_id, ticket })).json()).toMatchObject({ error: "invalid_ticket" });
    const me = await call(new Request(`${BASE}/v1/installs/me`, { headers: { authorization: `Bearer ${install_key}` } }));
    expect(await me.json()).toMatchObject({ install_id });
    const second = await register(install_id);
    const old = await call(new Request(`${BASE}/v1/installs/me`, { headers: { authorization: `Bearer ${install_key}` } }));
    expect(await old.json()).toMatchObject({ error: "invalid_install_key" });
    expect((await submitRaw(feedback({ install_id }), second)).status).toBe(201);
  });

  it("refuses tickets for another install, forged and expired tickets", async () => {
    const install_id = crypto.randomUUID();
    const other = await ticketFor(crypto.randomUUID());
    expect(await (await installRaw({ install_id, ticket: other })).json()).toMatchObject({ error: "invalid_ticket" });
    const forged = await signToken("wrong-secret", "ticket-v1", { v: 1, p: "install", i: install_id, n: nonce(), exp: Date.now() + 60_000, j: "x" });
    expect(await (await installRaw({ install_id, ticket: forged })).json()).toMatchObject({ error: "invalid_ticket" });
    const expired = await signToken(env.HMAC_SECRET, "ticket-v1", { v: 1, p: "install", i: install_id, n: nonce(), exp: Date.now() - 1, j: "y" });
    expect(await (await installRaw({ install_id, ticket: expired })).json()).toMatchObject({ error: "ticket_expired" });
  });

  it("limits key creation per IP per day", async () => {
    const statuses: number[] = [];
    for (let i = 0; i <= LIMITS.keysPerIpPerDay; i++) {
      const install_id = crypto.randomUUID();
      const ticket = await ticketFor(install_id, `198.18.0.${i}`);
      statuses.push((await installRaw({ install_id, ticket }, "198.18.1.1")).status);
    }
    expect(statuses.slice(0, LIMITS.keysPerIpPerDay).every((s) => s === 201)).toBe(true);
    expect(statuses.at(-1)).toBe(429);
  });

  it("revoking a key in D1 stops submissions", async () => {
    const f = feedback();
    expect((await submit(f)).status).toBe(201);
    await env.DB.prepare("UPDATE install_keys SET revoked_at = datetime('now') WHERE install_id = ?").bind(f.install_id).run();
    const res = await submit(feedback({ install_id: f.install_id }));
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: "invalid_install_key" });
  });
});

describe("submission", () => {
  it("accepts, classifies and exposes an item in the feed", async () => {
    const f = feedback({ scope: "session", screen: "conversation", session_ref: crypto.randomUUID() });
    const res = await submit(f);
    expect(res.status).toBe(201);
    const receipt = (await res.json()) as Record<string, unknown>;
    expect(receipt).toMatchObject({ submission_id: f.submission_id, duplicate: false });
    const [item] = await feedItems();
    expect(item).toMatchObject({ ...f, id: receipt.id, deleted: false, classification_state: "classified", off_topic: false, abusive: false });
    expect(item).not.toHaveProperty("ticket");
    expect(item).not.toHaveProperty("ip_hash");
  });

  it("returns the original receipt for a retry and refuses changed content under the same id", async () => {
    const f = feedback();
    const first = (await (await submit(f)).json()) as Record<string, unknown>;
    const retry = await submit(f);
    expect(retry.status).toBe(200);
    expect(await retry.json()).toEqual({ ...first, duplicate: true });
    const changed = await submit({ ...f, message: "Different text" });
    expect(changed.status).toBe(409);
    expect((await feedItems()).length).toBe(1);
  });

  it("refuses missing, unknown and other installs' keys", async () => {
    const f = feedback();
    expect(await (await submitRaw(f, null)).json()).toMatchObject({ error: "invalid_install_key" });
    expect(await (await submitRaw(f, `lfk_${"0".repeat(64)}`)).json()).toMatchObject({ error: "invalid_install_key" });
    const otherKey = await register(crypto.randomUUID());
    expect(await (await submitRaw(f, otherKey)).json()).toMatchObject({ error: "invalid_install_key" });
    expect(await feedItems()).toEqual([]);
  });

  it("validates fields strictly and never truncates", async () => {
    const f = feedback();
    const key = await register(f.install_id);
    let n = 0;
    const bad = async (body: unknown) => (await submitRaw(body, key, `192.0.2.${++n}`)).status;
    expect(await bad({ ...f, ticket: "t" })).toBe(400);
    expect(await bad({ ...f, message: "   " })).toBe(400);
    expect(await bad({ ...f, message: "x".repeat(6001) })).toBe(400);
    expect(await bad({ ...f, screen: "https://example.com/page" })).toBe(400);
    expect(await bad({ ...f, scope: "session", session_ref: null })).toBe(400);
    expect(await bad({ ...f, session_ref: crypto.randomUUID() })).toBe(400);
    expect(await bad({ ...f, model: "https://api.example.com/v1" })).toBe(400);
    expect(await bad({ ...f, submission_id: f.submission_id.toUpperCase() })).toBe(400);
    expect(await bad({ ...f, message: "é".repeat(6000), pad: "x".repeat(5000) })).toBe(413);
    // 6,000 two-byte characters fit within 16 KiB and are accepted whole.
    const big = feedback({ message: "é".repeat(6000) });
    expect((await submit(big)).status).toBe(201);
    expect((await feedItems())[0].message).toBe(big.message);
  });

  it("refuses submissions when intake is disabled", async () => {
    const res = await submit(feedback(), undefined, testEnv({ INTAKE_DISABLED: "1" }));
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({ error: "intake_disabled" });
  });
});

describe("quotas", () => {
  it("limits one install per hour", async () => {
    const install_id = crypto.randomUUID();
    for (let i = 0; i < LIMITS.perInstallPerHour; i++) expect((await submit(feedback({ install_id }), `198.51.100.${i}`)).status).toBe(201);
    const res = await submit(feedback({ install_id }), "198.51.100.99");
    expect(res.status).toBe(429);
    const body = (await res.json()) as { error: string; retry_after_seconds: number };
    expect(body.error).toBe("rate_limited");
    expect(body.retry_after_seconds).toBeGreaterThan(3500);
  });

  it("limits one install per day even when spread across hours", async () => {
    const install_id = crypto.randomUUID();
    const stmts = [];
    for (let i = 0; i < LIMITS.perInstallPerDay; i++) {
      stmts.push(
        env.DB.prepare("INSERT INTO feedback (id, cursor, submission_id, digest, received_at, received_ms, install_id, message) VALUES (?, ?, ?, 'd', 'x', ?, ?, 'm')").bind(
          crypto.randomUUID(), 200000 + i, crypto.randomUUID(), Date.now() - 2 * 3_600_000 - i * 60_000, install_id,
        ),
      );
    }
    await env.DB.batch(stmts);
    const res = await submit(feedback({ install_id }), "198.51.100.200");
    expect(res.status).toBe(429);
    expect(await res.json()).toMatchObject({ error: "rate_limited" });
  });

  it("limits attempts per IP per minute", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < LIMITS.attemptsPerIpPerMinute + 1; i++) statuses.push((await mintTicket(crypto.randomUUID(), "192.0.2.7")).status);
    expect(statuses.slice(0, LIMITS.attemptsPerIpPerMinute).every((s) => s === 200)).toBe(true);
    expect(statuses.at(-1)).toBe(429);
  });

  it("stops at the global daily cap", async () => {
    const now = Date.now();
    const stmts = [];
    for (let i = 0; i < LIMITS.globalPerDay; i++) {
      stmts.push(
        env.DB.prepare("INSERT INTO feedback (id, cursor, submission_id, digest, received_at, received_ms, install_id, message) VALUES (?, ?, ?, 'd', 'x', ?, ?, 'm')").bind(
          crypto.randomUUID(), 100000 + i, crypto.randomUUID(), now - 1000, crypto.randomUUID(),
        ),
      );
    }
    await env.DB.batch(stmts);
    const res = await submit(feedback());
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({ error: "over_capacity" });
  });
});

describe("classification", () => {
  it("keeps items whose classification fails and marks them failed after the last retry", async () => {
    aiReplies = [new Error("quota exceeded")];
    const f = feedback();
    expect((await submit(f)).status).toBe(201);
    let [item] = await feedItems();
    expect(item).toMatchObject({ classification_state: "pending", off_topic: null, message: f.message });
    await env.DB.prepare("UPDATE feedback SET received_ms = received_ms - 600000").run();
    aiReplies = [{ response: "not json" }, { response: "still not json" }];
    await maintenance(testEnv(), Date.now());
    await maintenance(testEnv(), Date.now());
    [item] = await feedItems();
    expect(item).toMatchObject({ classification_state: "failed", message: f.message });
  });

  it("re-emits reclassified items with a later cursor", async () => {
    aiReplies = [new Error("down")];
    await submit(feedback());
    const [before] = await feedItems();
    await env.DB.prepare("UPDATE feedback SET received_ms = received_ms - 600000").run();
    aiReplies = [{ response: { relevant: false, abusive: true, reason: "Spam." } }];
    await maintenance(testEnv(), Date.now());
    const res = (await (await changes(before.cursor as number)).json()) as { items: Array<Record<string, unknown>> };
    expect(res.items).toHaveLength(1);
    expect(res.items[0]).toMatchObject({ id: before.id, classification_state: "classified", off_topic: true, abusive: true });
  });

  it("parses model verdicts leniently but only with boolean answers", () => {
    expect(parseVerdict('Sure: {"relevant": true, "abusive": false, "reason": "Harsh but real bug report."}')).toEqual({ off_topic: false, abusive: false, reason: "Harsh but real bug report." });
    expect(parseVerdict('{"relevant": "yes", "abusive": false}')).toBeNull();
    expect(parseVerdict("nothing here")).toBeNull();
  });
});

describe("read feed", () => {
  it("requires the read token", async () => {
    expect((await changes(0, 10, null)).status).toBe(401);
    expect((await changes(0, 10, "wrong-token-0123456789")).status).toBe(401);
  });

  it("paginates by cursor", async () => {
    for (let i = 0; i < 3; i++) await submit(feedback(), `198.51.100.${i}`);
    const page1 = (await (await changes(0, 2)).json()) as { items: unknown[]; next_cursor: number; has_more: boolean };
    expect(page1.items).toHaveLength(2);
    expect(page1.has_more).toBe(true);
    const page2 = (await (await changes(page1.next_cursor, 2)).json()) as { items: unknown[]; next_cursor: number; has_more: boolean };
    expect(page2.items).toHaveLength(1);
    expect(page2.has_more).toBe(false);
    const empty = (await (await changes(page2.next_cursor, 2)).json()) as { items: unknown[]; next_cursor: number };
    expect(empty).toMatchObject({ items: [], next_cursor: page2.next_cursor });
  });
});

describe("retention", () => {
  it("forgets IP hashes after 48 hours and tombstones items after 90 days", async () => {
    await submit(feedback());
    const [item] = await feedItems();
    const day = 24 * 3_600_000;
    await maintenance(testEnv(), Date.now() + 3 * day);
    const row = await env.DB.prepare("SELECT ip_hash FROM feedback").first<{ ip_hash: string | null }>();
    expect(row!.ip_hash).toBeNull();
    await maintenance(testEnv(), Date.now() + 91 * day);
    const res = (await (await changes(item.cursor as number)).json()) as { items: unknown[] };
    expect(res.items).toEqual([{ id: item.id, cursor: expect.any(Number), deleted: true }]);
    const stored = await env.DB.prepare("SELECT message FROM feedback").first<{ message: string | null }>();
    expect(stored!.message).toBeNull();
    await maintenance(testEnv(), Date.now() + 181 * day);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM feedback").first("n")).toBe(0);
  });
});
