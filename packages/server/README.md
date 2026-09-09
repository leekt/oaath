# @oaath/server

OAAth deployable relay and PostgreSQL boundary. See the
[repository README](https://github.com/leekt/oaath#readme).

The package entry is Fetch-standard and platform-neutral. PostgreSQL is only
reachable through the explicit `@oaath/server/postgres` subpath.

`@oaath/server/native` (phone approval) and `@oaath/server/apns` (Apple push)
are **experimental previews**: unstable and not production qualified. The phone
approval preview is served by the relay handler under `/native/*`.

```ts
import { createRelayHandler } from "@oaath/server";
import { createPostgresRelayStore } from "@oaath/server/postgres";

const handler = createRelayHandler({
  store: createPostgresRelayStore({ connectionString }),
  authentication, // deployment-owned client/device authentication
  ownerRouting, // resolveOwner(caller, request) returns { ownerDeviceId, ownerSubject } or null
  kms, // deployment-owned encrypt/decrypt; plaintext never reaches the store
  clock: { now: () => Date.now() },
});
```

`ownerRouting.resolveOwner(caller, { requestId, requestedScope })` is required.
The relay captures its route once in the immutable request; null refuses creation.
The approving phone authenticates as `ownerSubject`, independently of the requesting
member. Changing the resolver cannot redirect an existing request. Requester
authentication and grant reference verification retain the member's subject.

## Service directory

`createServiceDirectory(store)` owns the records used to select a personal or
team account. Pass the directory as both `bootstrap` and `ownerRouting`:

```ts
import { createServiceDirectory } from "@oaath/server";
import {
  createPostgresServiceDirectorySchema,
  createPostgresServiceDirectoryStore,
} from "@oaath/server/postgres";

// Provision once in a new schema. Existing schemas are not migrated.
await createPostgresServiceDirectorySchema(pool);
const directory = createServiceDirectory(
  createPostgresServiceDirectoryStore({ pool }),
);
await directory.replace({ expectedRevision: null, directory: initialDirectory });
const handler = createRelayHandler({ store, authentication, kms, clock, chains,
  bootstrap: directory, ownerRouting: directory });
```

The `oaath.service-directory/v1` document contains `workspaces`, `applications`,
`memberships`, `accounts`, `ownerDevices`, and `selections`. Membership uses
the authenticated `(clientId, subject)` pair; an account references an owner
device within its workspace. Each account owns its Kernel profile, owner
validator binding, and configured chain IDs. After authenticating pairing, a
deployment calls `enrollOwnerDevice({ expectedRevision, device, accounts })` to
register a phone and its new P-256 Kernel accounts atomically in one workspace.
All accounts must bind that phone's same public owner key. Existing device or
account identities cannot be overwritten; enrollment does not add membership.
The deployment assigns the authenticated owner subject and separately issues
relay credentials. The directory stores public account identity and routing,
not private keys or bearer credentials.

`resolveOwner(caller, request)` admits a canonical permission request only when
its explicit workspace/account context, full account profile, and application
match a current membership and registered account. It returns that account's
owner-device route. Account selection is a preference, so changing it does not
retarget requests from an existing connection. Membership removal refuses new
requests; previously admitted requests retain their stored route.

`read()` returns `{ revision, directory }` or `null`. Deployment administration
replaces the document using that revision; `replace()` returns `false` if a
concurrent writer won. `selectAccount(caller, { workspaceId, accountId })`
checks membership and changes only that caller's selection, also returning
`false` on a concurrent write. The deployment authenticates the caller before
invoking this capability; it is not an open HTTP administration API.

PostgreSQL stores one atomic document for the PoC. Each resolver reads current
durable state; there is no process cache. An ambiguous write throws
`relay_state_ambiguous` and is never retried automatically. The deployment owns
pool shutdown. Membership/account removal can leave old selections behind;
resolution checks current records and returns `null` rather than granting
access through stale preferences. It does not revoke grants or delete operations.

## Endpoints

```text
POST /authorization/requests                       client  create request
GET  /authorization/requests/{requestId}           owner   fetch request
POST /authorization/requests/{requestId}/decision  owner   approve or reject
POST /authorization/codes/consume                  client  one-time code consume
POST /authorization/artifacts/{artifactId}/claim   client  one-time artifact claim
POST /authorization/resume                         client  fresh auth + recovery read
POST /grants/verify                                client  grant reference verification
POST /grants/{grantId}/revocations/{chainId}         client  request or recover phone custody
GET  /grants/{grantId}/revocations/{chainId}         client  read current phone custody status
```

EXPERIMENTAL PREVIEW routes (owner-phone approval):

```text
GET  /native/inbox                                owner   pending consent summaries
GET  /native/projections/{operationId}             owner   consent projection
GET  /native/permission-signing/{operationId}      owner   prepared Kernel signing projection
POST /native/decisions/{operationId}               owner   approve or reject saga
POST /native/revocation-decisions/{operationId}    owner   revocation custody decision
```

`GET /native/inbox` returns `oaath.native-inbox/v1` with `requests`, each containing
only `operationId`, `displayPayload`, and `expiresAt` (epoch milliseconds).
It reads existing permission and revocation requests for the authenticated owner,
excluding expired or decided requests, and returns at most 20 ordered by expiry
then operation ID. There is no separate inbox table or delivery flag to restore.
PostgreSQL readers recover the list after service recreation. Listing does not
prepare, sign, submit, or open an approval artifact; fetching consent checks
current state again. The example phone's inbox transport is not yet switched to
this endpoint.

Canonical phone permission approval requires `RelayHandlerOptions.permissionApprovals`.
Wire its `prepare(request)` to `prepareKernelPhonePermissionApproval` from
`@oaath/sdk/kernel`, supplying the deployment's account reads, chain ID, and
stable install nonce for that request. Return the helper's `signingRequest`
and a `complete(artifact, decidedAt)` that JSON-serializes its completion result.
The approval handler holds no owner key. The phone reviews the permission,
fetches its signing projection, and submits its P-256 artifact to the native
decision route. That route completes the grant through the injected helper and
the existing one-time decision transaction. A committed retry returns the stored
outcome before invoking preparation. An unconfigured deployment cannot approve
canonical permissions through the native route.

URL-mode `grant.revoke()` posts an empty object to the grant/chain revocation
route for each target without complete chain evidence. Configure
`RelayHandlerOptions.revocations` with the service `directory` and a
`prepare({ request, artifact, chainId })` capability. The existing
`requestOwnerPhoneRevocation` entry from `@oaath/server/native` owns admission
and durable custody. It checks the original application/member, resolves the
configured account and phone, and opens the retained approval even after claim
or execution-policy expiry. The deployment selects the effect, root nonce and
gas from chain state and passes them to `prepareKernelPhoneRevocation` from
`@oaath/sdk/kernel`, returning its `signingRequest`. Preparation must not reserve
a lane or nonce, sign, or submit; concurrent preparations may lose admission.

POST returns `201` for new custody or `200` for recovered custody. GET creates
nothing. Both return only `{ grantId, chainId, operationId, expiresAt, status }`,
where status is `pending`, `approved`, `rejected`, or `expired`. Pending and
terminal requests are recovered before preparation or KMS access, including
after a lost response. An explicit POST may replace expired, undecided custody;
approved and rejected requests remain terminal. No uncertain submission or
expired approval authorizes a replacement operation.

The paired phone fetches the shared projection route and posts approve/reject
to `revocation-decisions`. PostgreSQL preserves the exact request and sealed
phone artifact across restart. A repeated decision answers the stored outcome,
even after expiry or a conflicting command. Approval acknowledges custody;
the operation journal owns submission and finality. The client remains
`revoking` until every saved target has finalized chain-effect evidence. The
deployment still owns phone delivery and the execution worker. No OAuth code
or artifact is released by revocation.

Failures are `{"error":{"code":"relay_*"}}` with the status from
`RELAY_ERROR_STATUS`. A response never carries message text, provider output, or
internal detail.

## Owner revocation execution

`@oaath/server/kernel` composes approved phone custody with the SDK's existing
OperationRunner, OperationStore and OperationObserver. Use
`createOwnerPhoneRevocationExecutor({ store, kms, clock, operationId, operations,
observation, submission })` in a deployment worker. `operations` is an SDK
OperationStoreAdapter; `createPostgresOperationSchema` and
`createPostgresOperationStoreAdapter({ pool })` from `@oaath/server/postgres`
provide its durable implementation. Create the current operation tables once
alongside the relay schema. The deployment owns the pool.

`start(timeoutMs)` commits submission evidence before opening the deployment's
`submission.openSubmission(prepared, signature)` capability. Opening returns
`{ submit(), close() }` and must not send; the zero-argument submit sends only that
snapshot. `observe(timeoutMs)` uses the existing observer's chain evidence.
Recreating the executor preserves factory bytes, nonce, gas, calls and hash.
An attempted or terminal operation is never submitted again; recovery works
without KMS or submission access. Expired consent prevents a fresh attempt but
never hides existing operation evidence. `close()` releases runner resources
and can be retried after cleanup failure.

Finalized operation success is evidence about that exact operation. The client separately observes permission absence and consumed install nonces
on every saved revocation target. Automatic worker scheduling and replacement
planning remain separate work. This subpath introduces the server's explicit
SDK dependency; the relay root imports no runtime or PostgreSQL driver.

## Grant reference verification

`POST /grants/verify` lets an integrating application bind an immutable
artifact of its own (for example a reviewed deployment run) to the exact
authority revision that approved a Grant. The body is a
`VerifyGrantRevisionInput` and the `200` response is a
`GrantVerificationResult`, both owned by `@oaath/protocol`
(`parseGrantVerificationResult` must parse every response before it is acted
on). Every field in the body is an assertion compared against the relay's
durable authorization evidence — never trusted as identity — and the result is
`authorized` (with the immutable `OaathGrantRef`), `denied`, or `unknown`,
each with a typed code. Unreadable or absent evidence answers `unknown` and
never authorizes. Verification is a pure read: it is replay-safe and mutates
nothing.

How an application organization/audience maps to the OAAth client/realm:

- One deployed relay URL can serve multiple personal and team workspaces.
  `bootstrap.resolve(caller)` selects the caller's workspace, logical account,
  and configured chains on each request. The SDK keeps local realms separate
  by caller, workspace/account context, and complete account profile. The service
  directory provides the versioned membership and account selection records.
- `clientId`, the pairwise `subject`, and the `organizationAudience` are all
  asserted by the deployment's `RelayAuthentication` port. An application
  backend with its own cookie session obtains an authenticated OAAth caller by
  implementing that port — its handler reads its own session and returns the
  `RelayCaller` bindings — so no session policy is ever copied out of the
  deployment.
- The audience is captured onto the authorization request when the Grant is
  requested. Verification denies any audience assertion that does not match
  the captured value; a deployment that declares no audiences therefore never
  verifies one.
- `revision` is the approved authority revision. OAAth Grant authority is
  immutable per Grant (an authority change is a revocation plus a new Grant),
  so the single approval is revision `1`; anything else denies.
- `requiredCallsDigest` is `hashGrantPolicyCalls` over the reviewed call set
  and must equal the sealed approval's exact approved call set. `policyDigest`
  is `hashGrantPolicy(approvedPolicy)`, which may differ from the requested
  policy in the Grant identity. The approved expiry also bounds verification.
- Verification reads the retained encrypted artifact by request ID and checks
  its permission decision's request binding and policy attenuation. An approved
  OAuth outcome alone is insufficient; missing or unreadable approval evidence,
  including unavailable KMS, returns `unknown/grant_unreadable`. Reading never
  consumes a code or claims/releases an artifact, including after client claim
  and process restart. This verifies service-approved authority; it does not
  prove onchain installation or replace the Kernel runtime's capability checks.

## Security notes

- The approving decision, the authorization code, and the encrypted artifact are
  each terminal and transition exactly once under a row lock.
- `relay_state_ambiguous` means the store could not prove whether a transition
  committed. It authorizes neither a retry nor an assumption that it applied.
- A failed PKCE or redirect binding burns the code and voids its artifact.
  Every redemption failure returns the single `relay_code_invalid` code and
  status, so the endpoint never confirms that a guessed code was correct.
- `clientId` and the pairwise `subject` come only from the authentication port
  and the stored authorization request, never from wire input. A decision body
  that merely *names* a subject is rejected as an unknown field.
- A code may only be requested for a redirect URI the deployment registered for
  the authenticated client.
- Artifact plaintext is sealed by the KMS port before any write; the store holds
  only the opaque reference.
- `redactForLog` and `redactUrl` exist for diagnostics only.

## Schema

`createPostgresRelaySchema` creates the one current schema
(`oaath.relay-postgres-schema/v4`). There is no migration runner: an obsolete
database is dropped and recreated.

## Tests

Ordinary local `pnpm test` never contacts a database. The default repository CI
runs the PostgreSQL and restart proofs against its job-local service. Reproduce
that gate locally with an explicit opt-in:

```sh
OAATH_REQUIRE_POSTGRES=1 OAATH_POSTGRES_URL=postgres://localhost:5432/postgres pnpm test:postgres
```
