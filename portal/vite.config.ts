import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  // Workspace packages resolve to their sources, so the portal never bundles a stale build.
  resolve: { conditions: ["oaath-source", "browser", "module", "import", "default"] },
  build: { outDir: "dist", assetsDir: "assets", sourcemap: false },
  test: {
    name: "@oaath/portal",
    // The relay end-to-end builds and runs the Rust relay: `test:e2e` only.
    include: process.env.OAATH_PORTAL_E2E ? ["test/**/*.e2e.ts"] : ["test/**/*.test.ts"],
    testTimeout: 60_000,
    hookTimeout: 180_000,
  },
});
