# Owner-phone integration demo

This private example serves a static vanilla page and the relay on one LAN URL.
An interactive TTY renders a copyable `oaath-demo://pair?...` link and QR
containing **both** the reachable relay URL and one-shot pairing code. Captured
or non-TTY output and simulation render neither secret. A physical phone never
uses loopback: the app ships with an empty relay field and the link fills it.
Pairing remains an explicit tap.

```sh
pnpm --filter @oaath/examples example:phone
```

The page has exactly four actions:

1. **Unlock account** reads the paired, chain-independent CREATE2 account
   address. It asks for no owner authorization.
2. **Request permission** creates a secp256k1 session private key in the page
   (`crypto.getRandomValues` through noble), retains it in `localStorage`, and
   sends only its public key/address. The relay asks the phone to sign the SDK's
   replayable Kernel enable digest after displaying the full JSON.
3. **Send tx with session key** gets the validation nonce from EntryPoint,
   prepares the CallPolicy/value-bounded operation server-side, signs its exact
   UserOperation hash in the page, and submits. It is repeatable.
4. **Send tx with owner key** prepares a UserOperation, projects its full JSON
   and exact hash to the phone, and submits only the signature released after
   explicit approval.

The demo owns one in-memory operation lane for its paired account and chain.
It retains the exact prepared hash, bundler acceptance, and validated
transaction/receipt evidence. `prepared -> submitted -> included | reverted |
unresolved`; a submitted or unresolved lane can only observe the same hash.
Missing, unreadable, timed-out, or provider evidence never resubmits. Only
included installation materializes permission; reverted never authorizes.
Reload loses this demo memory, infers no authority, and submits nothing.

## Default Anvil mode

No credential and no network opt-in starts a local Anvil in Osaka mode (for the
RIP-7212 precompile), deploys the reviewed Kernel stack, and submits through
EntryPoint `handleOps`. `OAATH_PHONE_SIMULATE=1` pairs a noble P-256 phone,
signs both phone requests, exercises all four actions, sends the session action
twice with getNonce-derived sequences, and contacts neither Apple nor ZeroDev.
`pnpm examples:check` owns this unattended path.

## ZeroDev sponsored mode (explicit live opt-in)

A `ZERODEV_PROJECT_ID` may be stored in gitignored `examples/.env`, but its
presence is **not consent**. Live access requires both it and the
repository-owned flag:

```sh
OAATH_ZERODEV_LIVE=1 pnpm --filter @oaath/examples example:phone
```

There is no hidden Anvil or self-funded fallback in this mode. The adapter uses
`https://rpc.zerodev.app/api/v3/{projectId}/chain/421614`, sends
`zd_sponsorUserOperation([userOp, entryPoint, sponsorshipPolicyData])`, captures
an exact v0.7 response containing gas plus separate paymaster address/gas/data,
re-prepares so those fields are hash-bound, then sends
`eth_sendUserOperation([signedUserOp, entryPoint])`. Acceptance must return the
prepared hash exactly. Inclusion is then observed separately with at most four
one-second-spaced `eth_getUserOperationReceipt` polls. The adapter independently
reads the transaction and receipt, decodes exactly one matching EntryPoint
`UserOperationEvent`, and binds its hash, sender, nonce, success, transaction,
and block. It also reads the finalized head and canonical inclusion block;
outer transaction status and bundler `success` are never sufficient.

The exact worst-case documented path is **45** requests: 12 paid reads across
owner binding, session binding, and one post-deployment account-state refresh
(the adapter caches only successful immutable chain/code/factory evidence),
three fresh EntryPoint nonce reads, three sponsorships, three submissions, and
three times (four receipt polls plus transaction, receipt, finalized-head, and
canonical-block reads). One process-wide hard cap of **54** leaves nine requests
of headroom. Every request has a **10 second** timeout; the
viem custom transport sets `retryCount: 0`, observation concurrency is at most
two evidence reads, and there is no hidden fallback. Credential values and RPC
errors are never printed.

## Push and networking

The relay binds `0.0.0.0` outside simulation and prints the Mac's first LAN IPv4
address. Run only on a trusted network. APNs is optional: set
`APNS_KEY_PEM` (or `APNS_KEY_PEM_PATH`), `APNS_KEY_ID`, `APPLE_TEAM_ID`, and
`APNS_TOPIC`. Exactly one opaque notification is attempted per signature
request against Apple's sandbox host with a 10-second timeout. Without those
values, paste the printed operation id in the app; full consent still travels
over the authenticated projection, never through push.
