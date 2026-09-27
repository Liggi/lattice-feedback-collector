export interface Env {
  DB: D1Database;
  AI: Ai;
  TURNSTILE_SITE_KEY: string;
  TURNSTILE_SECRET_KEY: string;
  HMAC_SECRET: string;
  READ_TOKEN_SHA256: string;
  /** Hostname Turnstile must report; defaults to the collector's own hostname. */
  TURNSTILE_HOSTNAME?: string;
  /** "1" accepts Turnstile test-key results (no action field). Local development only. */
  ALLOW_TURNSTILE_TEST_KEYS?: string;
  /** "1" stops accepting new feedback. */
  INTAKE_DISABLED?: string;
}
