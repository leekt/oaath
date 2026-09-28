# @oaath/testing

OAAth deterministic fixtures and clean-consumer harnesses. Never a production
dependency. See the [repository README](https://github.com/leekt/oaath#readme).

`@oaath/testing/anvil` exports `createLocalAnvilFixture({ chainIds, stateDirectory })` for explicit
local integration tests. It starts one or two loopback Anvil chains with the
pinned EntryPoint and Kernel contracts. `openClient()` returns the public SDK
client and recreates all prior SDK/database handles over retained IndexedDB
test storage. The local test owner approves requested grants; this is not a
production authorization service. `approvalCount` and `submissionCount` support
zero-resubmission assertions. `rpcUrl(chainId)` exposes ordinary chain reads.
Always call `close()` in `finally` to release every local process.

With `stateDirectory`, the SDK writes its direct Grant, Operation and client
context to `client.sqlite`. The returned `recovery` descriptor contains only
public identities and loopback endpoints. After client process loss, pass it
and the same directory to `openLocalAnvilRecoveryClient({ recovery,
stateDirectory })`, then use `connect().resume()` and `Grant.getOperation()`.
The recovery client has no signing, authorization, quote or submission
capability. It uses fresh authenticated local relay access and the SDK's
existing durable resume validation. Anvil must still be running; a parent
harness that kills the producing process owns cleanup of `processIds` and the
temporary directory. Normal fixture `close()` stops its own Anvil processes.

`pnpm smoke:process-recovery` packs the public packages, submits once, checks
that the SDK record is still `submitted`, kills that OS process, and opens new
processes over disk and the existing chain. Unreadable receipt evidence remains
unresolved; restored reads recover the same operation and exact finalized calls
with an unchanged transaction count. The durable files contain normal SDK-owned
context and approval state; never copy them into logs or retained test fixtures.
Wallet bundles, prepared calls, keys and cleanup queues are outside this narrow
direct-Grant durability proof and remain in-memory fixture stores.

The root export exposes raw SQLite Grant/Operation adapters for SDK composition,
a context adapter, and validated aggregate Grant/Operation stores for direct
store tests. SQLite test schema `oaath.sqlite-test-store/v2` rejects old files;
recreate disposable state instead of migrating it. These are test-only adapters,
not a production SQLite persistence guarantee.

Install Anvil and run `pnpm smoke:local-consumer` to prove the packed two-chain
client path. It uses no shared RPC or external credentials. Revocation and real
browser persistence are outside this fixture's execution/recovery proof.
