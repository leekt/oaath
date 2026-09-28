import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "@oaath/testing",
    include: ["test/**/*.test.ts"],
    globalSetup: ["../../scripts/scrub-live-rpc-env.mjs"],
  },
});
