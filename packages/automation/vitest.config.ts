import { defineConfig } from "vitest/config";

export default defineConfig({
  ssr: { resolve: { conditions: ["oaath-source", "node", "module", "development|production"] } },
  test: {
    name: "@oaath/automation",
    include: ["test/**/*.test.ts"],
    globalSetup: ["../../scripts/scrub-live-rpc-env.mjs"],
  },
});
