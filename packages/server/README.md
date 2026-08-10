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
  kms, // deployment-owned encrypt/decrypt; plaintext never reaches the store
  clock: { now: () => Date.now() },
});
```

## Endpoints

```text
POST /authorization/requests                       client  create request
GET  /authorization/requests/{requestId}           owner   fetch request
POST /authorization/requests/{requestId}/decision  owner   approve or reject
POST /authorization/codes/consume                  client  one-time code consume
POST /authorization/artifacts/{artifactId}/claim   client  one-time artifact claim
POST /authorization/resume                         client  fresh auth + recovery read
```

EXPERIMENTAL PREVIEW routes (owner-phone approval; wire shapes pinned by the
strict Swift decoders in `native/ios/Sources/OwnerPhone/`):

```text
GET  /native/projections/{operationId}             owner   consent projection
POST /native/decisions/{operationId}               owner   approve or reject saga
```

Failures are `{"error":{"code":"relay_*"}}` with the status from
`RELAY_ERROR_STATUS`. A response never carries message text, provider output, or
internal detail.

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
(`oaath.relay-postgres-schema/v1`). There is no migration runner: an obsolete
database is dropped and recreated.

## Tests

Ordinary local `pnpm test` never contacts a database. The default repository CI
runs the PostgreSQL and restart proofs against its job-local service. Reproduce
that gate locally with an explicit opt-in:

```sh
OAATH_REQUIRE_POSTGRES=1 OAATH_POSTGRES_URL=postgres://localhost:5432/postgres pnpm test:postgres
```
