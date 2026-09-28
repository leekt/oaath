import { defineConfig } from "tsdown";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    anvil: "src/anvil.ts",
  },
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  platform: "neutral",
  deps: {
    neverBundle: [/^node:/],
  },
});
