import { defineConfig } from "vitest/config";

export default defineConfig({
  // Workspace packages resolve to their sources, so the demo never bundles a stale build.
  resolve: { conditions: ["oaath-source", "browser", "module", "import", "default"] },
  ssr: { resolve: { conditions: ["oaath-source", "node", "module", "development|production"] } },
  build: {
    outDir: "dist",
    assetsDir: "assets",
    sourcemap: false,
    target: "es2022",
    rollupOptions: { input: { index: "index.html", callback: "callback.html" } },
  },
  test: {
    name: "@oaath/demo",
    // The end-to-end builds and runs the Rust relay: `test:e2e` only.
    include: process.env.OAATH_DEMO_E2E ? ["test/**/*.e2e.ts"] : ["test/**/*.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
