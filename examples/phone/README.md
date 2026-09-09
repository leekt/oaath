# Phone delegation demo

A personal or team service with one paired P-256 owner phone and two configured
local chains. The browser uses
`createOAAth({ url })`, canonical permission requests, `sendCalls`, and
`getOperation`. Session keys, submission records and finality belong to the SDK.

```sh
pnpm --filter @oaath/examples example:phone
OAATH_WORKSPACE_KIND=team pnpm --filter @oaath/examples example:phone
OAATH_PHONE_SIMULATE=1 pnpm --filter @oaath/examples example:phone
```

Anvil is required. The service starts two local Osaka chains with the pinned
Kernel v4 stack and P-256 validator. IDs 84532 and 421614 identify the deployment
profiles; both endpoints are **local Anvil**, not public networks.

Open the printed `http://127.0.0.1:<port>` address. Choose **Pair phone**, scan
its transient QR code with [the iOS demo](../../native/ios/Demo/README.md), then:

1. **Connect account** resolves the enrolled workspace/account through bootstrap.
2. **Request permission** creates one canonical request. Review it in the phone
   inbox and approve. The phone fetches the matching Kernel signing packet and
   returns its P-256 artifact through `/native/decisions/{id}`.
3. Select a **Job chain**, then **Run a new job**. Each call is selector-bounded
   with 5 wei of native value. The same permission permits three operations on
   each configured chain over 30 minutes; it does not pool their budgets.
4. **Observe saved job** looks up the returned operation ID and observes it.
   Reload the page before this step to exercise SDK IndexedDB recovery. After
   finalization, run another job under the same permission.
5. **Revoke / check** stops application admission and requests phone consent.
   Approve each chain operation in the phone inbox, then check again. The service
   submits each exact approved operation; the SDK reports `revoked` only after
   finalized permission absence and install-nonce consumption on both chains. An unused grant
   burns its install nonce; an installed permission is uninstalled.

The page stores only a versioned operation ID and chain pointer in localStorage.
The SDK owns the key, grant and operation records in IndexedDB. An observation
failure retains the pointer and cannot submit a replacement. Recovery here
requires saving the handle returned by `sendCalls`; a crash before that return
is not covered by this example.

Personal mode enrolls one demo member. `OAATH_WORKSPACE_KIND=team` enrolls two
members sharing the phone-owned account. The page uses the first member; the
workflow test also authenticates the second member over HTTP and verifies its
separate bootstrap identity, session, grant and budget. There is no team admin
UI. The deployment supplies authentication and directory administration.

The default command keeps relay, directory and phone credentials in memory.
Exiting the command also stops its local chains.
Pairing issues relay access through `createOwnerDeviceAuthentication`; the
credential store owns authentication, separately from the phone-owned account.
Restarting the default command recreates the account; clear this demo origin's browser data and pair
again. Each permission request has its own install-nonce namespace. Configured
chains constrain service routing; the replayable approval is not a chain
allowlist. Revocation status covers the configured chains, not every possible
chain. The demo runs owner revocations for different grants sequentially;
parallel owner nonce allocation is not demonstrated.

Preparation reads the current module state and owner-operation nonce; gas limits
are fixed for this devnet. Pairing prefunds the local account. The existing SDK
executor and operation store own submission evidence, so repeated phone
decisions and client checks recover the same operation without resubmitting.
The service schedules one bounded execution/observation attempt after approval
or an approved request recovery. A failed attempt remains pending; approval
alone is never completion. The service uses the existing operation adapter
for either memory or PostgreSQL persistence.

The default phone transport is the authenticated `GET /native/inbox`. Pending
consent comes from the relay request and decision records, with no separate
inbox map or delivery flag. The loopback page alone can reveal its one-time
pairing secret. The relay listens on the LAN for the phone; `OAATH_HOST`, `OAATH_PORT`, and `OAATH_PHONE_WAIT_MS` control its bind
and lifetime (five minutes by default). Optional APNs uses `APNS_KEY_PEM` or
`APNS_KEY_PEM_PATH`, `APNS_KEY_ID`, `APPLE_TEAM_ID`, and `APNS_TOPIC`, with one
bounded notification attempt per newly created request. Polling or recovering
an existing request does not send another notification. An `examples/.env` is
loaded if present; existing environment values win.

`OAATH_PHONE_SIMULATE=1` runs both personal and team workflows against real
local contracts. A process-local P-256 fixture pairs over HTTP and completes
the canonical consent/decision/code/claim path. One approval executes jobs on
both chains; a second member has a separate budget and recoverable receipts.
The tests cover occupied-lane refusal, partial revocation staying pending,
unused counterfactual grants, and executor recreation without another send.
They contact neither Apple nor a live RPC and do not prove physical phone
consent or Secure Enclave user presence. The Swift host suite separately checks
native consent/signing. CI runs both native and local service workflows.

The old manual live sponsorship pipeline has been removed. Setting
`OAATH_ZERODEV_LIVE=1` exits before starting a chain or contacting a provider;
a live deployment needs a chain adapter for the shared SDK.

### Service restart with PostgreSQL

`startPhoneService({ chains, pool, port, workspaceKind })` borrows configured
chain backends and an optional provisioned PostgreSQL pool. With `pool`, it
composes the existing relay, directory, owner-credential and operation stores.
Provision their four schemas before starting; startup creates the initial
directory only when absent and never overwrites an existing enrollment.
`close()` stops HTTP/workers and closes store handles. The caller owns the pool
and chain lifetimes; `startPhoneDevnet()` is the default command's chain owner.

The phone keeps its original credential and account after service/pool
recreation at the same URL. Its pull inbox recovers pending consent, and
client status checks recover submitted owner work without another send.
The account display reads the enrolled public Kernel profile from the directory.
An enrolled account does not expose another pairing invitation after restart.

Run the local PostgreSQL restart workflow explicitly:

```sh
OAATH_REQUIRE_POSTGRES=1 OAATH_PHONE_SIMULATE=1 pnpm --filter @oaath/examples example:phone
```

It uses `OAATH_POSTGRES_URL` (default `postgres://localhost:5432/postgres`), owns
a disposable schema, and keeps two local Anvil backends alive while recreating
every HTTP service, store, directory, authenticator and PostgreSQL pool. It
restarts after pairing, before phone consent, before observing an application
job, and with an owner revocation recorded as submitted but not finalized.
The original credential and exact operation evidence survive; recovery adds
zero submissions. CI runs this alongside both default memory workflows.

This proves the service lifetime with live external chain backends, not a chain
reset or a browser/phone restart. Pairing invitations and optional push delivery
remain process-local. Interrupted initial enrollment/credential delivery and
hosted-chain deployment configuration are not demonstrated by this example.
