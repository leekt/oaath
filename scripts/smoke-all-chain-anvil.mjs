/**
 * Owns: two local Anvil chains where the second is introduced after owner
 * consent.
 *
 * The suite this script was a fail-closed stub for has landed:
 * `packages/sdk/test/all-chain.anvil.test.ts` spins two Anvil instances with
 * different chain ids, takes one replayable owner approval, and materializes it
 * on both — chain B being introduced only after the approval exists. This entry
 * runs exactly that suite with `OAATH_REQUIRE_ANVIL` set, so the proof has one
 * owner rather than a second copy here.
 *
 * Still fail-closed: the suite skips itself without `OAATH_REQUIRE_ANVIL`, so
 * this script always sets it, and a non-zero vitest status is this script's
 * status. A missing proof is never a passing proof.
 *
 * @author taek <leekt216@gmail.com>
 */
import { spawnSync } from "node:child_process";

const result = spawnSync(
  "pnpm",
  ["--filter", "@oaath/sdk", "exec", "vitest", "run", "test/all-chain.anvil.test.ts"],
  { stdio: "inherit", env: { ...process.env, OAATH_REQUIRE_ANVIL: "1" } },
);
process.exit(result.status ?? 1);
