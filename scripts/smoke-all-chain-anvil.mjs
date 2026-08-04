// Owns: two local Anvil chains where the second is introduced after owner consent.
// The proof itself is packages/sdk/test/all-chain.anvil.test.ts, so this entry only
// runs it with Anvil required — one owner for the evidence, never two copies.
import { spawnSync } from "node:child_process";

const result = spawnSync(
  "pnpm",
  ["--filter", "@oaath/sdk", "exec", "vitest", "run", "test/all-chain.anvil.test.ts"],
  { stdio: "inherit", env: { ...process.env, OAATH_REQUIRE_ANVIL: "1" } },
);
process.exit(result.status ?? 1);
