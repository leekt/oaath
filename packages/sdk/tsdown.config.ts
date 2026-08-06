import { defineConfig } from "tsdown";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    kernel: "src/kernel.ts",
    advanced: "src/advanced.ts",
    persistence: "src/persistence.ts",
    testing: "src/testing.ts",
  },
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  platform: "neutral",
});
