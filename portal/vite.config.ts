import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  // Workspace packages resolve to their sources, so the portal never bundles a stale build.
  resolve: { conditions: ["oaath-source", "browser", "module", "import", "default"] },
  // Tests run the same workspace sources under Node.
  ssr: { resolve: { conditions: ["oaath-source", "node", "module", "development|production"] } },
  build: { outDir: "dist", assetsDir: "assets", sourcemap: false },
  test: {
    name: "@oaath/portal",
    // The relay end-to-end builds and runs the Rust relay: `test:e2e` only.
    include: process.env.OAATH_PORTAL_E2E ? ["test/**/*.e2e.ts"] : ["test/**/*.test.ts"],
    testTimeout: 60_000,
    // Chrome cold starts on shared CI runners exceed the 10 s hook default.
    hookTimeout: 60_000,
  },
});
