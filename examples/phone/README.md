# Phone delegation demo

A local service with one paired P-256 owner phone. The browser uses
`createOAAth({ url })`, canonical permission requests, `sendCalls`, and
`getOperation`. Session keys, submission records and finality belong to the SDK.

```sh
pnpm --filter @oaath/examples example:phone
OAATH_PHONE_SIMULATE=1 pnpm --filter @oaath/examples example:phone
```

Anvil is required. The service starts a local Osaka chain with the pinned Kernel
v4 stack and the P-256 validator. Chain ID 421614 identifies the deployment
profile; this is **local Anvil**, not the public Arbitrum Sepolia network.

Open the printed `http://127.0.0.1:<port>` address. Choose **Pair phone**, scan
its transient QR code with [the iOS demo](../../native/ios/Demo/README.md), then:

1. **Connect account** resolves the enrolled workspace/account through bootstrap.
2. **Request permission** creates one canonical request. Review it in the phone
   inbox and approve. The phone fetches the matching Kernel signing packet and
   returns its P-256 artifact through `/native/decisions/{id}`.
3. **Run a new job** submits one selector-bounded call with 5 wei of native value.
   This grant permits three operations per chain over 30 minutes.
4. **Observe saved job** looks up the returned operation ID and observes it.
   Reload the page before this step to exercise SDK IndexedDB recovery. After
   finalization, run another job under the same permission.
5. **Revoke / check** stops application admission and requests phone consent.
   Approve the chain operation in the phone inbox, then check again. The service
   submits the exact approved operation; the SDK reports `revoked` only after
   finalized permission absence and install-nonce consumption. An unused grant
   burns its install nonce; an installed permission is uninstalled.

The page stores only a versioned operation ID and chain pointer in localStorage.
The SDK owns the key, grant and operation records in IndexedDB. An observation
failure retains the pointer and cannot submit a replacement. Recovery here
requires saving the handle returned by `sendCalls`; a crash before that return
is not covered by this example.

The relay, directory, pairing and local chain are ephemeral. Restarting the
service creates a new account; clear this demo origin's browser data and pair
again. This example configures one personal workspace and one grant per fresh
account. The shared directory also supports teams; there is no team admin UI
here. Each permission request has its own install-nonce namespace. Configured
chains constrain service routing; the replayable approval is not a chain
allowlist. This demo proves revocation on its one configured local chain.

Preparation reads the current module state and owner-operation nonce; gas limits
are fixed for this devnet. Pairing prefunds the local account. The existing SDK
executor and operation store own submission evidence, so repeated phone
decisions and client checks recover the same operation without resubmitting.
The service schedules one bounded execution/observation attempt after approval
or an approved request recovery. Its in-memory operation adapter is explicitly
ephemeral alongside Anvil; a lasting deployment uses the existing PostgreSQL
adapter. A failed attempt remains pending; approval alone is never completion.

The default phone transport is the authenticated pull inbox. The loopback page
alone can reveal its one-time pairing secret. The relay listens on the LAN for
the phone; `OAATH_HOST`, `OAATH_PORT`, and `OAATH_PHONE_WAIT_MS` control its bind
and lifetime (five minutes by default). Optional APNs uses `APNS_KEY_PEM` or
`APNS_KEY_PEM_PATH`, `APNS_KEY_ID`, `APPLE_TEAM_ID`, and `APNS_TOPIC`, with one
bounded notification attempt. An `examples/.env` is loaded if present; existing
environment values win.

`OAATH_PHONE_SIMULATE=1` runs the real local-chain workflow test. A process-local
P-256 fixture pairs over HTTP, rejects a foreign signature, completes the
canonical consent/decision/code/claim path, and executes three jobs through the
URL SDK. It also proves occupied-lane refusal, observation without resubmission,
and refusal of a fourth job. Both the installed permission and an unused
counterfactual grant then complete phone-approved revocation through the actual
Kernel contracts, with no submission before consent and no resend on replay.
It contacts neither Apple nor a live RPC and does
not prove physical phone consent or Secure Enclave user presence. The Swift
host suite separately checks the native consent/signing implementation. CI runs
both the native suite and this local service workflow.

The old manual live sponsorship pipeline has been removed. Setting
`OAATH_ZERODEV_LIVE=1` exits before starting a chain or contacting a provider;
a live deployment needs a chain adapter for the shared SDK.
