import { defineConfig } from "tsdown";

// One build, every entry, so the relay entry, the `./postgres` subpath, and the
// experimental `./native` and `./apns` previews share a single chunk — and
// therefore one `OaathRelayError` class and one record parser. Splitting them
// into separate builds duplicates that state and breaks `instanceof` across the
// boundary.
//
// The entries stay platform-separated by what they import, not by bundler target:
// `src/index.ts` and `src/native.ts` import nothing from Node or `pg`,
// `src/postgres.ts` owns the driver, `src/apns.ts` owns `node:crypto`, and the
// driver is never bundled. `test/package.test.ts` enforces all of it.
export default defineConfig({
  entry: {
    index: "src/index.ts",
    postgres: "src/postgres.ts",
    native: "src/native.ts",
    apns: "src/apns.ts",
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
