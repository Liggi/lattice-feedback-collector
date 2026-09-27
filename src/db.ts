import type { Env } from "./env";

export function bumpCursorStatement(env: Env): D1PreparedStatement {
  return env.DB.prepare("UPDATE seq SET value = value + 1 WHERE name = 'cursor'");
}

/** Atomically increments a counter that expires at `expiresMs` and returns the new count. */
export async function incrementCounter(env: Env, key: string, expiresMs: number): Promise<number> {
  const row = await env.DB.prepare(
    `INSERT INTO counters (key, count, expires_ms) VALUES (?, 1, ?)
     ON CONFLICT (key) DO UPDATE SET count = count + 1 RETURNING count`,
  )
    .bind(key, expiresMs)
    .first<{ count: number }>();
  return row!.count;
}
