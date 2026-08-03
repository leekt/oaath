import { defineConfig } from "vitest/config";

// Tests are package-local: each package owns its own suite under `packages/*/test`.
// No suite may contact a paid or shared RPC by default; live-network work is explicit
// opt-in. `scripts/scrub-live-rpc-env.mjs` removes live-provider credentials before
// any test worker starts.
export default defineConfig({
  test: {
    projects: ["packages/*"],
    globalSetup: ["./scripts/scrub-live-rpc-env.mjs"],
  },
});
