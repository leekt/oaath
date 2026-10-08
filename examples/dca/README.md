# DCA automation example

Dollar-cost averaging as one declarative automation plus its contracts. The
automation service has no DCA code: it executes
[`dca.automation.ts`](dca.automation.ts) like any other definition.

| File | Role |
| --- | --- |
| `dca.automation.ts` | `dcaAutomation({ chainId, sellToken, dca })`: the `dca.v1` definition |
| `contracts/src/DcaExecutor.sol` | One shared executor per market (sell/buy pair, Uniswap v3 route, two feeds) |
| `contracts/src/fixtures/` | Mintable token and feeds: settable (Anvil and forge tests) and fixed (the Arbitrum Sepolia market) |
| `contracts/artifacts/` | ABI and bytecode of the three contracts |

The plan's setup operation approves the executor for the plan budget and opens
the plan (`open(planId, budget, runs, startAt, interval, grace, maxSlippageBps)`).
Each occurrence calls `execute(planId, slot)`; cancellation calls `cancel(planId)`
and resets the allowance to zero.

## Enforcement

`DcaExecutor` keys plans by `(msg.sender, planId)`, so only the account itself
can run its plan. It buys `budget / runs` per slot, only inside
`[startAt + slot * interval, + grace)`, at most once per slot, never beyond the
budget, and only at an output above the feed-derived minimum (both feeds fresh,
positive and round-consistent) less `maxSlippageBps`.

OAAth 0.3.x Grant policies allow-list a target and selector, not arguments. The
Grant therefore allows the token's `approve` and the executor's
`open`/`execute`/`cancel` with any arguments: the session key could approve
another spender or open another plan. The plan's frozen arguments, and so its
budget, are kept only by the automation service and the executor's own checks.

## End to end

`bun run --filter @oaath/automation-server test:e2e` deploys these contracts
with a Uniswap v3 pool on Anvil, approves a `dca.v1` plan through a local relay,
and lets two automation service replicas run its setup and first purchase.

## Build and test

```sh
cd examples/dca/contracts
forge test
forge build && node export-artifacts.mjs   # refresh artifacts/ after a change
```

OpenZeppelin resolves from `examples/node_modules` (`bun install` at the root).

## Hosted market on Arbitrum Sepolia

The hosted example app [`dca/`](../../dca) runs `dca.v1`-shaped plans on
Arbitrum Sepolia (421614) through the hosted automation service. Its market is a
self-contained fixture on Uniswap's own v3 deployment
([addresses](https://developers.uniswap.org/docs/protocols/v3/deployments/v3-arbitrum-deployments):
factory `0x248AB79Bbb9bC29bB72f7Cd42F17e054Fc40188e`, NonfungiblePositionManager
`0x6b2937Bde17889EDCf8fbD8dE31C3C2a70Bc4d65`, SwapRouter02
`0x101F443B4d1b059569D643917553c771E1b9663E`):

- mintable test tokens tUSD (6 decimals, sold) and tETH (18 decimals, bought);
- two `FixtureFixedFeed`s (1 tUSD = $1, 1 tETH = $2000) that never go stale;
- a full-range 0.3% pool seeded with 100M tUSD and 50k tETH at that price;
- the shared `DcaExecutor`, routing through SwapRouter02.

Testnet WETH, USDC and their pools and Chainlink feeds are not used: a real feed
moves while a thin testnet pool does not, so the executor's oracle bound would
refuse buys, and seeding real WETH would spend the deployer's testnet ETH. The
fixture tokens are free to mint, so each plan's setup also mints its own budget
to the account (`mint($plan.account, $param.budget)`) and users need no funds.

| File | Role |
| --- | --- |
| `contracts/script/DeployArbSep.s.sol` | Deploys the market above and prints its addresses |
| `deploy-arbsep.sh` | Runs it with the Foundry keystore account `TEMP_ACCOUNT`; `--dry-run` simulates only |
| `dca-arbsep.automation.json` | Service definitions `dca.arbsep.{1m,5m,1h}.v1`, with address placeholders |

```sh
examples/dca/deploy-arbsep.sh --dry-run   # simulate against Arbitrum Sepolia, send nothing
examples/dca/deploy-arbsep.sh             # deploy; asks for the keystore password
```

The script refuses any chain other than 421614 and checks the Uniswap
addresses. It prints the addresses and writes `dca-arbsep.deployed.json`: the
definitions with `REPLACE_SELL_TOKEN` (tUSD) and `REPLACE_DCA_EXECUTOR` filled
in. The template's placeholders fail definition validation, so an unfilled file
never loads. Set `DEPLOYER=0x…` to skip the extra password prompt for the
address, and `ARBSEP_RPC_URL` to use another RPC.
