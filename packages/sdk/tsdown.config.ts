import { defineConfig } from "tsdown";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    testing: "src/testing.ts",
  },
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  platform: "neutral",
  deps: {
    neverBundle: ["node:sqlite"],
  },
});
