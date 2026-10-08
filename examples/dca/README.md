# DCA automation example

Dollar-cost averaging as one declarative automation plus its contracts. The
automation service has no DCA code: it executes
[`dca.automation.ts`](dca.automation.ts) like any other definition.

| File | Role |
| --- | --- |
| `dca.automation.ts` | `dcaAutomation({ chainId, sellToken, dca })`: the `dca.v1` definition |
| `contracts/src/DcaExecutor.sol` | One shared executor per market (sell/buy pair, Uniswap v3 route, two feeds) |
| `contracts/src/fixtures/` | Mintable token and settable feed, for local Anvil and forge tests only |
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

## Build and test

```sh
cd examples/dca/contracts
forge test
forge build && node export-artifacts.mjs   # refresh artifacts/ after a change
```

OpenZeppelin resolves from `examples/node_modules` (`bun install` at the root).
