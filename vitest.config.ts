import path from "node:path";
import { defineConfig } from "vitest/config";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(import.meta.dirname, "migrations"));
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.jsonc" },
        // Tests replace the AI binding with a fake; no Cloudflare account needed.
        remoteBindings: false,
        miniflare: {
          bindings: {
            TEST_MIGRATIONS: migrations,
            TURNSTILE_SITE_KEY: "1x00000000000000000000AA",
            TURNSTILE_SECRET_KEY: "test-secret",
            HMAC_SECRET: "test-hmac-secret",
            // Override .dev.vars, which is set up for Turnstile test keys.
            TURNSTILE_HOSTNAME: "collector.test",
            ALLOW_TURNSTILE_TEST_KEYS: "0",
            // sha256("test-read-token-0123456789")
            READ_TOKEN_SHA256: "e58e5d4ecea3ef4bb704660ffe8dc741ea8d15375cf8dad64ec0133bb5a30c83",
          },
        },
      }),
    ],
    test: { setupFiles: ["./test/apply-migrations.ts"] },
  };
});
