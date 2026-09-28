# @oaath/testing

OAAth deterministic fixtures and clean-consumer harnesses. Never a production
dependency. See the [repository README](https://github.com/leekt/oaath#readme).

`@oaath/testing/anvil` exports `createLocalAnvilFixture({ chainIds })` for explicit
local integration tests. It starts one or two loopback Anvil chains with the
pinned EntryPoint and Kernel contracts. `openClient()` returns the public SDK
client and recreates all prior SDK/database handles over retained IndexedDB
test storage. The local test owner approves requested grants; this is not a
production authorization service. `approvalCount` and `submissionCount` support
zero-resubmission assertions. `rpcUrl(chainId)` exposes ordinary chain reads.
Always call `close()` in `finally` to release every local process.

Install Anvil and run `pnpm smoke:local-consumer` to prove the packed two-chain
client path. It uses no shared RPC or external credentials. Revocation and real
browser persistence are outside this fixture's execution/recovery proof.
