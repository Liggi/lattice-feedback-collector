# Lattice feedback collector

A small Cloudflare Worker that receives feedback from Lattice users and their agents, and serves
it to the maintainer's own Lattice inbox. It uses D1 for storage, Turnstile to check once per Lattice install
that a person in a browser set it up, and Workers AI to flag off-topic or abusive items. It runs on
the free tier at a `workers.dev` address.

```text
 once per install
 ────────────────
 user's browser (Lattice page)            collector (Worker)
   iframe GET /v1/verify?purpose=install ─▶ panel + Turnstile
   ◀── postMessage(ticket) ─────────────── POST /v1/tickets (siteverify)
        │ ticket
        ▼
 user's Lattice server
   POST /v1/installs {install_id, ticket} ─▶ stores sha256(key)
   ◀── {install_key} (kept in a 0600 file) ─

 every submission
 ────────────────
 user's Lattice server
   POST /v1/feedback, Bearer install_key ──▶ validate, quotas, D1 insert
                                            classify (Workers AI, async)
 maintainer's Lattice server
   GET /v1/changes, Bearer read token ─────▶ change feed (pulled every 60 s)
                                            cron: classifier retries, retention
```

The collector never deletes or hides feedback because of its classification. It only sets flags.
Criticism of Lattice, including harsh or profane criticism, is valid feedback.

## HTTP contract (schema_version 1)

Both the collector and Lattice (`~/src/lattice-public`) follow this section.

### 1. Registration panel: `GET /v1/verify`

Once per install, the Lattice page embeds an iframe:

```
{collector}/v1/verify?purpose=install&nonce=<32 lowercase hex>&install_id=<uuid>
    &parent_origin=<exact origin>&theme=<light|dark|auto>
```

- `purpose` is required and must be `install`.
- `parent_origin` is the exact origin of the embedding Lattice page, byte for byte equal to its
  `window.location.origin` (`http://localhost:3045`, `http://mac-mini.tail1234.ts.net:3045`): scheme,
  host, non-default port, no path, no trailing slash. The page's CSP sets `frame-ancestors` to that
  origin only, so a mismatch means the browser will not render the iframe.
- Optional `theme=light|dark|auto` (default `auto`) sets both the Turnstile theme and the page's
  `color-scheme`. Pass the Lattice page's current theme: when the iframe's color scheme differs from
  its parent's, browsers paint the iframe with an opaque background. The page background is
  otherwise transparent.
- Turnstile runs with action `feedback`. The panel then calls `POST /v1/tickets` on its own origin
  (`{turnstile_token, purpose, nonce, install_id}` → `{ticket, expires_at}`) and posts one of these
  messages to `parent_origin` (never `*`):
  - `{type: "lattice-feedback-ticket", nonce, ticket, expires_at}`: `expires_at` is ISO 8601.
  - `{type: "lattice-feedback-verify-error", nonce, error, message}`: `message` is a sentence you
    can show as is.
  - `{type: "lattice-feedback-verify-resize", nonce, height}`: height in CSS pixels.
- The parent must check `event.origin === collector origin`, `event.source === iframe.contentWindow`
  and `event.data.nonce === nonce`.
- Invalid query parameters return 400 with an error shown in the panel (and posted to the parent
  when `parent_origin` itself is valid).

The ticket is an opaque string, signed by the collector, bound to `install_id`, valid for 5 minutes,
and good for one install key.

### 2. Install key: `POST /v1/installs`

Called by the Lattice server (no CORS) with `{install_id, ticket}`; no other fields.

- `201 {install_id, install_key, created_at}`. `install_key` is `lfk_` followed by 64 hex
  characters; treat it as opaque. The collector stores only its SHA-256. Issuing a key revokes any
  earlier key for the same `install_id`.
- Keep the key on the Lattice server only: a mode-0600 file, never sent to the browser, never in an
  agent subprocess environment. Whoever holds it can submit feedback without a person involved.
- Errors: `invalid_request` 400, `invalid_ticket` 403 (forged, for another install, or already
  used), `ticket_expired` 403 (run the check again), `rate_limited` 429 (5 keys per calling IP per
  day, and the per-minute attempt limit; `retry_after_seconds` is set).

`GET /v1/installs/me` with `Authorization: Bearer <install_key>` returns
`200 {install_id, created_at}`, or `401 invalid_install_key`. Use it to check a key without
submitting.

### 3. Submit: `POST /v1/feedback`

`Authorization: Bearer <install_key>`, `Content-Type: application/json`. Called by the Lattice
server, not the browser (no CORS). The body is exactly these fields; unknown or missing fields are
rejected, and nothing is ever truncated.

| field | rule |
|---|---|
| `schema_version` | `1` |
| `submission_id` | lowercase UUID, fixed across retries of the same approved payload |
| `install_id` | lowercase UUID created at opt-in; must be the install the key was issued to |
| `source` | `human` \| `agent` (a client declaration, not verified) |
| `category` | `bug` \| `suggestion` \| `other` |
| `message` | 1–6,000 Unicode code points, not only whitespace |
| `scope` | `app` \| `session` |
| `screen` | `home` \| `conversation` \| `settings` \| `cli` \| `other` |
| `session_ref` | lowercase UUID when `scope` is `session`; `null` when `scope` is `app` |
| `lattice_version` | 1–64 characters of `[0-9A-Za-z.+-]` |
| `provider` | `claude` \| `codex` \| `other` \| `null` |
| `model` | `null` or 1–100 characters of `[A-Za-z0-9._[]-]` (no `:` or `/`, so no URLs) |

The whole body must be at most 16,384 bytes.

Success:

- `201 {id, submission_id, received_at, duplicate: false}`: stored. `received_at` is the
  collector's time and is authoritative.
- `200 {id, submission_id, received_at, duplicate: true}`: the same `submission_id` with identical
  fields was already stored; this is the original receipt.

Errors are `{error, message, retry_after_seconds?}`; `message` is a sentence Lattice can show
verbatim.

| status | `error` | meaning |
|---|---|---|
| 400 | `invalid_request` | bad JSON, content type or field |
| 401 | `invalid_install_key` | key missing, unknown, revoked, or issued to another install; drop it and run the check again |
| 413 | `payload_too_large` | body over 16,384 bytes |
| 409 | `conflict` | `submission_id` already used for different content |
| 429 | `rate_limited` | a quota below was hit; `retry_after_seconds` is set |
| 503 | `intake_disabled` | The maintainer switched intake off |
| 503 | `over_capacity` | global daily cap reached; `retry_after_seconds` is set |
| 500 | `internal_error` | unexpected failure; keep the draft |

### 4. Read feed: `GET /v1/changes?after=<cursor>&limit=<1..200>`

`Authorization: Bearer <read token>`. Start with `after=0`; `limit` defaults to 100. Returns
`401 {error: "unauthorized"}` without a valid token. The collector never redirects.

```json
{ "items": [ ... ], "next_cursor": 42, "has_more": false }
```

Items are ordered by `cursor` ascending; sort for display yourself. Store `next_cursor` and pass it
as `after` next time; while `has_more` is true, fetch again straight away. Each item:

```json
{
  "id": "…", "cursor": 42, "deleted": false, "received_at": "2026-09-27T09:19:15.493Z",
  "schema_version": 1, "submission_id": "…", "install_id": "…", "source": "human",
  "category": "bug", "message": "…", "scope": "app", "screen": "settings", "session_ref": null,
  "lattice_version": "3.2.1", "provider": "claude", "model": "claude-opus-5-5",
  "classification_state": "pending | classified | failed",
  "off_topic": null, "abusive": null, "classification_reason": null, "classifier_version": null
}
```

`pending` and `failed` both mean Unclassified. When classification finishes or an item passes
retention, it is sent again with a new, higher cursor. Deleted items come back as tombstones with no
content: `{id, cursor, deleted: true}`. Remove them from the local cache.

### 5. Health: `GET /v1/health`

`{ok: true, intake: "enabled" | "disabled", schema_version: 1}`.

## Limits and retention

| limit | value | enforced |
|---|---|---|
| ticket, install and submission attempts per IP | 10 per minute | D1 counter |
| install keys issued per calling IP | 5 per day | D1 counter |
| accepted items per install (so per key) | 10 per hour, 30 per 24 hours | same D1 statement as the insert |
| accepted items per submitting IP | 50 per 24 hours | same D1 statement as the insert |
| accepted items, all users | 1,000 per 24 hours | same D1 statement as the insert |
| classifier calls | 1 on accept, then up to 2 retries per item; 200 retries per day | cron |

- IPs are only stored as a keyed hash (HMAC with `HMAC_SECRET`), and that hash is cleared from
  items after 48 hours. Per-minute attempt counters are deleted by the first cron run after they
  expire (2 minutes); the daily retry budget counter after 2 days. IPs never appear in the feed.
- Items are kept 90 days, flagged or not, then become tombstones. Tombstones are purged after 180
  days. D1 Time Travel also keeps restorable history for 7 days on the free plan.
- Logs record item IDs and events, never message text or tokens.
- Classification uses `@cf/meta/llama-3.2-3b-instruct` on the message text only, with no tools.
  If it fails or the free AI quota runs out, the item stays `pending`, the cron (every 10 minutes)
  retries it, and after 3 attempts it becomes `failed`. The item is kept either way.

## Local development

```sh
npm install
cp .dev.vars.example .dev.vars        # Turnstile always-pass test keys, dev read token
npm run db:migrate:local
npm run dev                           # http://localhost:8791 (local only, no Cloudflare account)
npm test                              # vitest in the Workers runtime
npm run typecheck
```

- Local read token: `dev-read-token-local`. It works only with the local `.dev.vars`.
- Test keys: sitekey `1x00000000000000000000AA`, secret `1x0000000000000000000000000000000AA`.
  Their siteverify result reports hostname `example.com` and no action, which is why `.dev.vars`
  sets `TURNSTILE_HOSTNAME=example.com` and `ALLOW_TURNSTILE_TEST_KEYS=1`. Never set either in
  production.
- `wrangler dev --local` cannot reach Workers AI, so local items stay Unclassified.

## Deploy

Needs a Cloudflare account and an API token with Workers Scripts, D1 and Workers AI edit rights.

```sh
set -a; . ~/.config/lattice-feedback/cloudflare.env; set +a   # CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID

npx wrangler d1 create lattice-feedback          # copy database_id into wrangler.jsonc
npx wrangler d1 migrations apply lattice-feedback --remote
npx wrangler deploy                              # prints https://lattice-feedback.<subdomain>.workers.dev
```

Create a Turnstile widget (dashboard: Turnstile → Add widget, managed mode) whose only hostname is
`lattice-feedback.<subdomain>.workers.dev`. Then set the secrets:

```sh
npx wrangler secret put TURNSTILE_SITE_KEY
npx wrangler secret put TURNSTILE_SECRET_KEY
openssl rand -hex 32 | npx wrangler secret put HMAC_SECRET

# Read token: plaintext only in a private file on the maintainer's Lattice host; the Worker stores its hash.
umask 077; openssl rand -hex 32 > ~/.config/lattice-feedback/read-token
tr -d '\n' < ~/.config/lattice-feedback/read-token | shasum -a 256 | cut -d' ' -f1 \
  | npx wrangler secret put READ_TOKEN_SHA256
```

Rotating `HMAC_SECRET` invalidates outstanding tickets and resets per-IP counts. Install keys stay
valid.

Check production:

```sh
curl https://lattice-feedback.<subdomain>.workers.dev/v1/health
curl -H "Authorization: Bearer $(cat ~/.config/lattice-feedback/read-token)" \
  "https://lattice-feedback.<subdomain>.workers.dev/v1/changes?after=0"
```

Revoke an install's key (Lattice then asks that user to run the check once more; their quota
still counts by `install_id`):

```sh
npx wrangler d1 execute lattice-feedback --remote \
  --command "UPDATE install_keys SET revoked_at = datetime('now') WHERE install_id = '<install_id>' AND revoked_at IS NULL"
```

Switch intake off and on (takes effect immediately, no redeploy):

```sh
echo 1 | npx wrangler secret put INTAKE_DISABLED
npx wrangler secret delete INTAKE_DISABLED
```

## License

Apache-2.0. See `LICENSE`.
