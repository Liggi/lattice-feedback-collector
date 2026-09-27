import { randomHex } from "./crypto";

export interface VerifyParams {
  purpose: "install";
  nonce: string;
  install_id: string;
  parent_origin: string;
}

/** Returns the exact origin string when `value` is a bare http(s) origin, otherwise null. */
export function exactOrigin(value: string | null): string | null {
  if (!value) return null;
  try {
    const u = new URL(value);
    if ((u.protocol !== "http:" && u.protocol !== "https:") || u.origin !== value) return null;
    return u.origin;
  } catch {
    return null;
  }
}

function jsonForScript(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026");
}

export type Theme = "light" | "dark" | "auto";

// The panel's color-scheme must match the embedding page, or browsers paint the iframe opaque.
const style = (theme: Theme) => `
  :root { color-scheme: ${theme === "auto" ? "light dark" : theme}; font: 14px/1.4 system-ui, -apple-system, sans-serif; }
  body { margin: 0; padding: 8px; background: transparent; }
  #status { margin: 6px 0 0; color: #888; }
  #status:empty { display: none; }
  #status.error { color: #c0392b; }
`;

/**
 * The verification panel Lattice embeds once per install. After Turnstile passes it obtains a
 * ticket bound to the install ID and posts it to the exact parent origin.
 */
export function verifyPage(siteKey: string, params: VerifyParams | null, invalidReason: string | null, parentOrigin: string | null, theme: Theme): Response {
  const scriptNonce = randomHex(16);
  const config = { siteKey, params, invalidReason, parentOrigin, theme };
  const html = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Verify feedback</title>
<style>${style(theme)}</style>
</head><body>
<div id="widget"></div>
<p id="status" role="status"></p>
<script nonce="${scriptNonce}">
const CONFIG = ${jsonForScript(config)};
const statusEl = document.getElementById("status");
function post(msg) {
  if (!CONFIG.parentOrigin || window.parent === window) return;
  window.parent.postMessage(Object.assign({ nonce: CONFIG.params ? CONFIG.params.nonce : null }, msg), CONFIG.parentOrigin);
}
function fail(error, message) {
  statusEl.textContent = message;
  statusEl.className = "error";
  post({ type: "lattice-feedback-verify-error", error, message });
}
function reportHeight() { post({ type: "lattice-feedback-verify-resize", height: document.documentElement.scrollHeight }); }
new ResizeObserver(reportHeight).observe(document.body);
async function onToken(token) {
  statusEl.textContent = "Verified. Preparing your submission…";
  try {
    const res = await fetch("/v1/tickets", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(Object.assign({ turnstile_token: token }, CONFIG.params)),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return fail(data.error || "verification_failed", data.message || "Verification failed. Try again.");
    statusEl.textContent = "Verified.";
    post({ type: "lattice-feedback-ticket", ticket: data.ticket, expires_at: data.expires_at });
  } catch (e) {
    fail("network_error", "Could not reach the feedback service. Check your connection and try again.");
  }
}
window.onTurnstileLoad = function () {
  turnstile.render("#widget", {
    sitekey: CONFIG.siteKey,
    theme: CONFIG.theme,
    action: "feedback",
    callback: onToken,
    "error-callback": function () { fail("turnstile_error", "The bot check could not run. Reload and try again."); },
    "expired-callback": function () { fail("turnstile_expired", "The bot check expired. Try again."); },
  });
};
if (CONFIG.invalidReason) {
  fail("invalid_request", CONFIG.invalidReason);
} else {
  const s = document.createElement("script");
  s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=onTurnstileLoad";
  s.async = true;
  s.onerror = function () { fail("turnstile_unavailable", "The bot check could not load. Check your connection and try again."); };
  document.head.appendChild(s);
}
</script>
</body></html>`;
  const csp = [
    "default-src 'none'",
    `script-src 'nonce-${scriptNonce}' https://challenges.cloudflare.com`,
    "frame-src https://challenges.cloudflare.com",
    "connect-src 'self'",
    "style-src 'unsafe-inline'",
    "base-uri 'none'",
    "form-action 'none'",
    // Only the declared Lattice page may embed the panel.
    `frame-ancestors ${parentOrigin ?? "'none'"}`,
  ].join("; ");
  return new Response(html, {
    status: params ? 200 : 400,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": csp,
      "referrer-policy": "no-referrer",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}
