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
```

EXPERIMENTAL PREVIEW routes (owner-phone approval; wire shapes pinned by the
strict Swift decoders in `native/ios/Sources/OwnerPhone/`):

```text
GET  /native/projections/{operationId}             owner   consent projection
GET  /native/permission-signing/{operationId}      owner   prepared Kernel signing projection
POST /native/decisions/{operationId}               owner   approve or reject saga
POST /native/revocation-decisions/{operationId}    owner   revocation custody decision
```

Canonical phone permission approval requires `RelayHandlerOptions.permissionApprovals`.
Wire its `prepare(request)` to `prepareKernelPhonePermissionApproval` from
`@oaath/sdk/kernel`, supplying the deployment's account reads, chain ID, and
stable install nonce for that request. Return the helper's `signingRequest`
and a `complete(artifact, decidedAt)` that JSON-serializes its completion result.
The server has no SDK dependency or owner key. The phone reviews the permission,
fetches its signing projection, and submits its P-256 artifact to the native
decision route. That route completes the grant through the injected helper and
the existing one-time decision transaction. A committed retry returns the stored
outcome before invoking preparation. An unconfigured deployment cannot approve
canonical permissions through the native route.

`requestOwnerPhoneRevocation` from `@oaath/server/native` is the deployment
entry for revoking an approved permission on one configured chain. It admits
the original authenticated application/member through `ServiceDirectory`, opens
the retained approval (including after client claim or execution-policy expiry),
and calls the deployment's `prepare({ request, artifact, chainId })` capability.
Use `prepareKernelPhoneRevocation` from `@oaath/sdk/kernel` there to validate the
Kernel capability and select the effect, root nonce and gas from chain state;
return its `signingRequest`. Preparation must not sign or submit.

The returned `operationId` and `expiresAt` identify an immutable stored request.
The paired phone fetches the shared projection route and posts approve/reject
to `revocation-decisions`. PostgreSQL preserves the exact request and sealed
phone artifact across restart. A repeated decision answers the stored outcome,
even after expiry or a conflicting command. Approval acknowledges custody;
submission, finality, configured-chain orchestration and a client enqueue HTTP
endpoint remain separate work. No OAuth code or artifact is released.

Failures are `{"error":{"code":"relay_*"}}` with the status from
`RELAY_ERROR_STATUS`. A response never carries message text, provider output, or
internal detail.

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
(`oaath.relay-postgres-schema/v3`). There is no migration runner: an obsolete
database is dropped and recreated.

## Tests

Ordinary local `pnpm test` never contacts a database. The default repository CI
runs the PostgreSQL and restart proofs against its job-local service. Reproduce
that gate locally with an explicit opt-in:

```sh
OAATH_REQUIRE_POSTGRES=1 OAATH_POSTGRES_URL=postgres://localhost:5432/postgres pnpm test:postgres
```
