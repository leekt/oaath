# Owner-phone integration demo

This private example serves a static vanilla page and a LAN-reachable relay.
Open the printed browser URL on the Mac's **loopback** address and click **Pair
phone** to reveal a transient copyable `oaath-demo://pair?...` link and QR. The
link carries the LAN relay URL and one-shot pairing code for the phone. The
secret endpoint validates the real loopback socket plus the fixed browser
origin; a page opened through the LAN address cannot disclose it. The link is
never stored in browser storage or printed in captured/non-TTY/simulation
output, and it is hidden after pairing or expiry. An interactive TTY may still
render the terminal link/QR as a fallback. Pairing in the app remains an
explicit tap.

```sh
pnpm --filter @oaath/examples example:phone
```

The page has one **Pair phone** action plus four account actions:

1. **Unlock account** reads the paired, chain-independent CREATE2 account
   address. It asks for no owner authorization.
2. **Request permission** creates a secp256k1 session private key in the page
   (`crypto.getRandomValues` through noble), retains it in `localStorage`, and
   sends only its public key/address. The relay may project the legacy Kernel
   enable digest for inspection, but every server decision API refuses to
   approve or release that network-supplied digest.
3. **Send tx with session key** gets the validation nonce from EntryPoint,
   prepares the CallPolicy/value-bounded operation server-side, signs its exact
   UserOperation hash in the page, and submits. In default local mode it is
   repeatable.
4. **Send tx with owner key** prepares a UserOperation and may project its full
   JSON and exact hash for inspection. It cannot submit through owner consent
   until a closed request lets the device derive and verify that hash itself.

The demo owns independent in-memory owner and session operation lanes for its
paired account and chain. Each retains the exact prepared hash, bundler
acceptance, and any discovered transaction hash. An unresolved session therefore
does not block the root authority's independent nonce domain. Within each lane,
`prepared -> submitted -> included | reverted | unresolved`; a submitted or
unresolved operation can only observe the same hash while its EntryPoint nonce
remains occupied. A fresh nonce read that proves the sequence advanced may open
the next session operation without changing the earlier operation's unresolved
outcome. Missing,
unreadable, timed-out, or unproved provider evidence never resubmits. Only the
repository-owned local Anvil evidence path can reach included/reverted and
materialize permission. Reload loses this demo memory, infers no authority, and
submits nothing.

## Default Anvil mode

No credential and no network opt-in starts a repository-owned local Anvil in
Osaka mode (for the RIP-7212 precompile), deploys the reviewed Kernel stack, and
submits through EntryPoint `handleOps`. The stack includes the exact zero-salt
initcode extracted from the verified Arbitrum Sepolia ECDSASigner deployment at
`0x6A6F069E2a08c2468e7724Ab3250CdBFBA14D4FF`, not a substitute local signer.
Its owned transport and local chain
provide the complete strict four-account-action evidence path: transaction membership
and index, the exact EntryPoint event, ancestry, endpoint rebound, and finality.
This is owned local evidence, not Byzantine RPC verification.
`OAATH_PHONE_SIMULATE=1` pairs a noble P-256 test fixture and exercises Pair
plus all four account actions, sending the session action twice with
getNonce-derived sequences, while contacting neither Apple nor ZeroDev. The
fixture supplies owner signatures locally to preserve chain and race evidence;
it does not approve a relay request and is not phone-consent or clear-signing
evidence. `pnpm examples:check` owns this unattended path.

## ZeroDev Arbitrum Sepolia mode (explicit live opt-in)

A `ZERODEV_PROJECT_ID` may be stored in gitignored `examples/.env`, but its
presence is **not consent**. Live access requires both it and the
repository-owned flag:

```sh
OAATH_ZERODEV_LIVE=1 pnpm --filter @oaath/examples example:phone
```

There is no hidden Anvil or self-funded fallback in this mode. Chain `421614`
uses the standard ZeroDev bundler and paymaster because UltraRelay exposes no
supported EntryPoint on Arbitrum Sepolia. The adapter uses
`https://rpc.zerodev.app/api/v3/{projectId}/chain/421614` and ZeroDev SDK's
official one-object `zd_sponsorUserOperation` action. It exact-captures the
returned v0.7 gas and paymaster fields. A live session first signs the retained
unsponsored hash in the browser because ZeroDev rejects first-use Kernel enable
simulation without valid session evidence (`AA23`). Core SDK sponsorship
preparation then re-prepares so every returned field is hash-bound; the browser
signs that distinct final hash, and the relay sends only the final operation through
`eth_sendUserOperation([signedUserOp, entryPoint])`. Acceptance must return the
prepared hash exactly. The owner path applies the same two-hash rule with two
preparation phases internally: a validation-shaped dummy signature obtains the
sponsorship, then the phone sees and signs only the final sponsored hash. Live
calls transfer zero ETH because the paymaster sponsors gas, not call value;
local Anvil mode retains its small value transfers.
At most **four** one-second-spaced transaction-discovery polls may retain the first canonical
transaction hash.

ZeroDev's ordinary receipt, event, block, and `finalized` RPC views are not an
authenticated finalized-header plus receipt-proof source. Therefore they can
never terminalize an operation, materialize permission, or authorize another
session operation, even when every provider field is mutually coherent. The
result remains `unresolved` with code `receipt_proof_unavailable`; the occupied
nonce permits same-hash observation only. Once EntryPoint positively reports a
higher sequence, the demo may submit a new operation on that sequence while the
earlier operation remains unresolved.
This mode cannot complete the live four-account-action flow without such an
authenticated proof source. No provider quorum, attestor, receipt-trie fallback,
or plugin framework is present.

The exact worst-case documented path for the single-submission live sequence
is **17** requests: 10 paid reads across owner/session binding, one fresh
EntryPoint nonce read, one sponsorship, one submission, and at most four
transaction-discovery polls. One process-wide hard cap of **26** leaves
**9** requests of headroom. Every request has a **10 second** timeout;
the viem custom transport sets `retryCount: 0`, so there is no retry and no
hidden fallback. Observation is serial per occupied operation lane. Credential
values and RPC errors are never printed.

## Pull inbox, optional push, and networking

The browser UI is printed and served at `http://127.0.0.1:<port>`. The relay
also binds `0.0.0.0` outside simulation so the link can carry the Mac's LAN
address to the phone. Run only on a trusted network.

The authenticated **pull inbox is the default** Simulator/free-account PoC
path. While paired, the app polls `GET /demo/inbox` about every two seconds and
offers Refresh. The endpoint accepts only the exact active paired-device bearer
and returns at most 20 sorted, undecided, unexpired opaque summaries (operation
id, match code, expiry). Selecting one only fetches the existing full
authenticated projection; Approve/Reject remain explicit. Listing never creates,
decides, submits, observes, or releases anything.

APNs is an optional physical-device enhancement: set `APNS_KEY_PEM` (or
`APNS_KEY_PEM_PATH`), `APNS_KEY_ID`, `APPLE_TEAM_ID`, and `APNS_TOPIC`. Exactly
one opaque notification is attempted per signature request against Apple's
sandbox host with a 10-second timeout. Without those values, use the pull inbox
(or manual operation-id fallback); full consent still travels over the
authenticated projection, never through push.
