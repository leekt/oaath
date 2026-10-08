import { defineConfig } from "vitest/config";

export default defineConfig({
  // Workspace packages resolve to their sources, so the app never bundles a stale build.
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
    name: "@oaath/dca-app",
    include: ["test/**/*.test.ts"],
  },
});
