# @oaath/cli

Node CLI for the canonical Kernel v4 / EntryPoint 0.7 runtime. The package
installs the `oaath` command and belongs to the same fixed release group as
`@oaath/sdk`.

```sh
npx @oaath/cli doctor --chain 143
npx @oaath/cli doctor --chain 143 --rpc https://rpc.monad.xyz --json
```

From a repository checkout, run `bun run --filter @oaath/cli build` and
`node packages/cli/dist/cli.mjs doctor --chain 143`.

`doctor` reads one explicit RPC endpoint. Defaults cover Monad 143, World 480,
MegaETH 4326, Tempo 4217, Robinhood 4663 and Arc 5042. Other chains need `--rpc`.
The command does not read provider environment variables, request signatures or
send transactions. It checks chain ID before contract reads, uses one block
number for the snapshot, and allows at most 32 requests, four concurrently,
five seconds per request and 60 seconds total. There are no retries or fallbacks.

Each row is `verified` (pinned runtime hash), `present` (code at the canonical
CREATE2 address), `missing`, `mismatch` or `unreadable`. Kernel implementation
code contains chain-specific immutables: known-chain hashes are checked where
available; other chains report `present`, consistently with SDK binding. The
hash-pinned factory must also return the canonical implementation from `UUPS()`.
An unreadable endpoint is never reported as an absent contract.

Exit 0 means the ECDSA session module set and its prerequisites are ready;
exit 1 means not ready or unreadable; exit 2 means invalid arguments. JSON uses
the `oaath.runtime-readiness/v2` schema. Readiness is a snapshot, not a guarantee
of later RPC availability, account ownership, bundler/paymaster service or finality.

The owner validator remains application-selected. `passkeySessionsReady` reports
whether WebAuthn (passkey) sessions can bind: the WebAuthn signer and Daimo's
P-256 verifier must both carry their pinned runtime hashes. It never affects
`ready` or the exit code. The P-256 validator row is an optional owner capability;
the pinned P-256 validator requires the chain's native P-256 precompile. No test ECDSA validator is distributed by this CLI.

## Deploy the missing runtime

```sh
npx @oaath/cli deploy-runtime --chain 143 --rpc https://rpc.monad.xyz --dry-run
# Supply OAATH_DEPLOYER_PRIVATE_KEY through your secret manager or environment.
npx @oaath/cli deploy-runtime --chain 143 --rpc https://rpc.monad.xyz
```

The command requires an explicit RPC URL. The endpoint must report the requested
chain and carry the exact EntryPoint 0.7, singleton CREATE2 deployer, ZeroDev
CallPolicy, operation-limit RateLimitPolicy, ECDSASigner and Daimo P-256 verifier runtimes.
It deploys only missing core components: Kernel UUPS, the factory's immutable
ECDSA implementation, factory, OAAth ValidityPolicy, the fixed-window
RateLimitPolicy for windowed operation limits and the passkey-session WebAuthnSigner. Every payload uses the canonical `0x4e59…956C` deployer and zero
salt; addresses are derived from the retained creation code and checked against
SDK bindings. Existing code with a wrong hash or unreadable evidence stops the
command. Externally owned prerequisites and the optional P-256 validator are not deployed.

New transactions use the funded account named by `OAATH_DEPLOYER_PRIVATE_KEY`.
Keys are never accepted as command-line arguments or saved to the journal.
`--dry-run` loads no key, writes no journal and sends no transactions. Without
`--dry-run`, invoking the command authorizes deployment fees using the RPC's gas
and fee estimates; each transaction is limited to ten million gas. This supports
ordinary EIP-1559 and legacy EIP-155 transactions. Chain-specific fee-token
transaction formats are not implemented.

The default journal is `~/.local/state/oaath/runtime.sqlite`; use `--journal <path>`
to choose a persistent file. It records chain, sender, component, creation-input
hash, nonce and transaction hash **before broadcasting once**. It saves no signed
transaction or private key. SQLite schema version 1 admits only one attempted
deployment per chain across concurrent commands sharing this journal.

Keep the same journal when rerunning. A timeout, missing receipt, lost reply or
unavailable provider only resumes observation of the recorded hash, even when
the wallet key is unavailable. The command requires the exact transaction,
canonical finalized receipt block and expected deployed code before confirming
its attempt. A finalized revert stops the command; it never retries automatically.
Do not delete or switch journals to bypass an unresolved transaction. An RPC
without `finalized` block support leaves the attempt pending.

Deployment allows at most 256 RPC requests and 180 seconds per invocation, with
five seconds per request, four concurrent snapshot reads, no transport retries,
and at most 30 receipt-observation attempts one second apart per transaction.
If finality takes longer, rerun later with the same journal. A later invocation
may load the key to deploy the *next* missing component after recovery finishes.
Once all core components verify, rerunning needs no key and sends nothing.
Exit 0 means ready or a successful dry run; exit 1 means incomplete or failed.
`--json` returns `oaath.runtime-deployment/v1` with the plan, readiness snapshot
and pending transaction hash. Production writes are deferred in the current
six-chain rollout; the command has been proved locally on Anvil.
