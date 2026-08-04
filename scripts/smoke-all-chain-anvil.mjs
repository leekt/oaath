/**
 * Owns: two local Anvil chains where the second is introduced after owner
 * consent.
 *
 * DELIBERATELY FAIL-CLOSED. The two-chain materialization suite this script
 * would drive does not exist yet: it belongs to the all-chain replayable
 * materialization stream, and `packages/sdk`'s current `test:anvil` suites are
 * single-chain Kernel v4 and composition proofs, not a chain B introduced after
 * approval. Wiring this to them would report an all-chain proof that never ran,
 * which is worse than no script.
 *
 * Not wired into CI for the same reason. When the two-chain suite lands, its own
 * change replaces this body with the `OAATH_REQUIRE_ANVIL` invocation; nothing
 * else here needs to move.
 *
 * @author taek <leekt216@gmail.com>
 */

console.error("smoke-all-chain-anvil: fail-closed stub; the two-chain Anvil suite has not landed.");
console.error("  A missing proof is never a passing proof. This exits 1 by design.");
process.exit(1);
