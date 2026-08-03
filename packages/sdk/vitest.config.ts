import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "@oaath/sdk",
    include: ["test/**/*.test.ts", "test/**/*.test.mjs"],
    globalSetup: ["../../scripts/scrub-live-rpc-env.mjs"],
  },
});
