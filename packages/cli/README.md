# oaath

Node CLI for the canonical Kernel v4 / EntryPoint 0.7 runtime. The `oaath`
package belongs to the same fixed release group as `@oaath/sdk`.

```sh
npx oaath doctor --chain 143
npx oaath doctor --chain 143 --rpc https://rpc.monad.xyz --json
```

Until the package is published, run `pnpm --filter oaath build` and
`node packages/cli/dist/cli.mjs doctor --chain 143` from the repository, or install
the exact packed `oaath`, `@oaath/sdk` and `@oaath/protocol` tarballs together.

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
the `oaath.runtime-readiness/v1` schema. Readiness is a snapshot, not a guarantee
of later RPC availability, account ownership, bundler/paymaster service or finality.

The owner validator remains application-selected. P-256 validator, WebAuthn
signer and P-256 verifier rows are optional capabilities, separate from the core
ECDSA session set. The pinned P-256 validator requires the chain's native
P-256 precompile. No test ECDSA validator is distributed by this CLI.
