import { sha256Hex } from "./crypto";

export const MAX_BODY_BYTES = 16384;
export const MAX_MESSAGE_CHARS = 6000;

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const NONCE_RE = /^[0-9a-f]{32}$/;

const SOURCES = ["human", "agent"] as const;
const CATEGORIES = ["bug", "suggestion", "other"] as const;
const SCOPES = ["app", "session"] as const;
const SCREENS = ["home", "conversation", "settings", "cli", "other"] as const;
const PROVIDERS = ["claude", "codex", "other"] as const;
const VERSION_RE = /^[0-9A-Za-z.+-]{1,64}$/;
const MODEL_RE = /^[A-Za-z0-9._\[\]-]{1,100}$/;

export interface Feedback {
  schema_version: 1;
  submission_id: string;
  install_id: string;
  source: (typeof SOURCES)[number];
  category: (typeof CATEGORIES)[number];
  message: string;
  scope: (typeof SCOPES)[number];
  screen: (typeof SCREENS)[number];
  session_ref: string | null;
  lattice_version: string;
  provider: (typeof PROVIDERS)[number] | null;
  model: string | null;
}

export const FEEDBACK_FIELDS = [
  "schema_version",
  "submission_id",
  "install_id",
  "source",
  "category",
  "message",
  "scope",
  "screen",
  "session_ref",
  "lattice_version",
  "provider",
  "model",
] as const;

export type Validation = { ok: true; feedback: Feedback } | { ok: false; message: string };

function oneOf<T extends readonly string[]>(list: T, v: unknown): v is T[number] {
  return typeof v === "string" && (list as readonly string[]).includes(v);
}

/** Validates a POST /v1/feedback body: exactly the twelve feedback fields. */
export function validateSubmission(body: unknown): Validation {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return { ok: false, message: "The request body must be a JSON object." };
  const b = body as Record<string, unknown>;
  const allowed = new Set<string>(FEEDBACK_FIELDS);
  const unknown = Object.keys(b).filter((k) => !allowed.has(k));
  if (unknown.length) return { ok: false, message: `Unknown fields: ${unknown.join(", ")}.` };
  const missing = FEEDBACK_FIELDS.filter((k) => !(k in b));
  if (missing.length) return { ok: false, message: `Missing fields: ${missing.join(", ")}.` };

  if (b.schema_version !== 1) return { ok: false, message: "schema_version must be 1." };
  if (typeof b.submission_id !== "string" || !UUID_RE.test(b.submission_id)) return { ok: false, message: "submission_id must be a lowercase UUID." };
  if (typeof b.install_id !== "string" || !UUID_RE.test(b.install_id)) return { ok: false, message: "install_id must be a lowercase UUID." };
  if (!oneOf(SOURCES, b.source)) return { ok: false, message: `source must be one of ${SOURCES.join(", ")}.` };
  if (!oneOf(CATEGORIES, b.category)) return { ok: false, message: `category must be one of ${CATEGORIES.join(", ")}.` };
  if (typeof b.message !== "string") return { ok: false, message: "message must be a string." };
  const chars = [...b.message].length;
  if (chars < 1 || b.message.trim() === "") return { ok: false, message: "message must not be empty." };
  if (chars > MAX_MESSAGE_CHARS) return { ok: false, message: `message is ${chars} characters; the limit is ${MAX_MESSAGE_CHARS}.` };
  if (!oneOf(SCOPES, b.scope)) return { ok: false, message: `scope must be one of ${SCOPES.join(", ")}.` };
  if (!oneOf(SCREENS, b.screen)) return { ok: false, message: `screen must be one of ${SCREENS.join(", ")}.` };
  if (b.scope === "session") {
    if (typeof b.session_ref !== "string" || !UUID_RE.test(b.session_ref)) return { ok: false, message: "session_ref must be a lowercase UUID when scope is session." };
  } else if (b.session_ref !== null) {
    return { ok: false, message: "session_ref must be null when scope is app." };
  }
  if (typeof b.lattice_version !== "string" || !VERSION_RE.test(b.lattice_version)) return { ok: false, message: "lattice_version must be 1-64 characters of letters, digits, '.', '+' or '-'." };
  if (b.provider !== null && !oneOf(PROVIDERS, b.provider)) return { ok: false, message: `provider must be null or one of ${PROVIDERS.join(", ")}.` };
  if (b.model !== null && (typeof b.model !== "string" || !MODEL_RE.test(b.model))) return { ok: false, message: "model must be null or a model identifier of 1-100 characters (letters, digits, '.', '_', '-', '[', ']')." };

  const feedback = Object.fromEntries(FEEDBACK_FIELDS.map((k) => [k, b[k]])) as unknown as Feedback;
  return { ok: true, feedback };
}

/** SHA-256 hex of the fixed-order JSON array of the twelve fields. */
export function feedbackDigest(f: Feedback): Promise<string> {
  return sha256Hex(JSON.stringify(FEEDBACK_FIELDS.map((k) => f[k])));
}
