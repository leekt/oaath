import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "@oaath/protocol",
    include: ["test/**/*.test.ts"],
  },
});
