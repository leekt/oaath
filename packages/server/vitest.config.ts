import { defineConfig } from "vitest/config";

export default defineConfig({
  ssr: { resolve: { conditions: ["oaath-source", "node", "module", "development|production"] } },
  test: {
    name: "@oaath/server",
    include: ["test/**/*.test.ts"],
  },
});
