import { defineConfig } from "vitest/config";

export default defineConfig({
  ssr: { resolve: { conditions: ["oaath-source", "node", "module", "development|production"] } },
  test: {
    name: "@oaath/sdk",
    include: ["test/**/*.test.ts", "test/**/*.test.mjs"],
    globalSetup: ["../../scripts/scrub-live-rpc-env.mjs"],
  },
});
