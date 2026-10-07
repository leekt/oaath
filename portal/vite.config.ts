import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  // Workspace packages resolve to their sources, so the portal never bundles a stale build.
  resolve: { conditions: ["oaath-source", "browser", "module", "import", "default"] },
  build: { outDir: "dist", assetsDir: "assets", sourcemap: false },
  test: {
    name: "@oaath/portal",
    include: ["test/**/*.test.ts"],
    testTimeout: 60_000,
  },
});
