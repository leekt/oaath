# @oaath/testing

OAAth deterministic fixtures and clean-consumer harnesses. Never a production
dependency. See the [repository README](https://github.com/leekt/oaath#readme).

`@oaath/testing/anvil` exports `createLocalAnvilFixture({ chainIds, stateDirectory, kernelVersion })` for explicit
local integration tests. It starts one or two loopback Anvil chains with the
pinned EntryPoint and Kernel contracts. `openClient()` returns the public SDK
client and recreates all prior SDK/database handles over retained IndexedDB
test storage. The local test owner approves requested grants; this is not a
production authorization service. `approvalCount` and `submissionCount` support
zero-resubmission assertions. `rpcUrl(chainId)` exposes ordinary chain reads.
Always call `close()` in `finally` to release every local process.

`kernelVersion: "0.3.3"` deploys the existing ECDSA-root account before creating
the SDK client; the default is `"0.4.0"`. The v3.3 path installs the actual scoped
permission with one all-chain approval, then reuses it silently. Fixed fixture
gas limits prove execution, not production bundler estimation. Recovery descriptor
`oaath.local-anvil-recovery/v2` binds the existing address and rejects old versions.

For existing v3.3 owner and local-session flows, use
`createLocalOwnerAnvilFixture({ chainId, wallet: "browser" })`. Its `wallet`
implements a local EIP-1193 owner and `rpcFetch(Request)` handles POST requests
to `rpcUrl` or `http://owner-bundler.test`. A browser harness can forward its
own loopback HTTP routes to this handler while the browser uses the normal SDK
transport and native storage. The harness owns exact host/origin checks,
request budgets and its HTTP server's cleanup. `rpcFetch` rejects unrelated
origins, non-POST requests and calls after `close()`; it does not start a server.
Signature, submission and RPC counters cover these calls too.
`createLocalOwnerAnvilFixture({ kernelVersion: "0.4.0", owner: "p256" })` roots
the account in a raw P-256 `ownerKey` through the pinned P-256 validator on an
Osaka chain; its signatures count in `signatureCount`. Do not retain
request payloads, signatures, approval data or browser profiles as evidence.

The local stack also deploys the pinned WebAuthn signer and resetting rate-limit
policy so consumers can install and revoke their real passkey approval packages.
These are actual CREATE2 deployments; the fixture never substitutes module code
or permission storage. Authenticator interaction remains the consumer's test.

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

`bun run smoke:process-recovery` packs the public packages, submits once, checks
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

Install Anvil and run `bun run smoke:local-consumer` to prove the packed two-chain
client path. It uses no shared RPC or external credentials. Revocation and real
browser persistence are outside this fixture's execution/recovery proof.
