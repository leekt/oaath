import { defineConfig } from "tsdown";

// One build, two entries, so the relay entry and the `./postgres` subpath share a
// single chunk — and therefore one `OaathRelayError` class and one record parser.
// Splitting them into two builds duplicates that state and breaks `instanceof`
// across the boundary.
//
// The entries stay platform-separated by what they import, not by bundler target:
// `src/index.ts` imports nothing from Node or `pg`, `src/postgres.ts` owns the
// driver, and the driver is never bundled. `test/package.test.ts` enforces it.
export default defineConfig({
  entry: {
    index: "src/index.ts",
    postgres: "src/postgres.ts",
  },
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  platform: "neutral",
  deps: {
    neverBundle: ["pg"],
  },
});
