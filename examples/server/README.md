# Server example — Fetch relay, PostgreSQL, auth and KMS ports

`createRelayHandler` is a `(Request) => Promise<Response>` function, so the only
server-specific code in [run.mjs](run.mjs) is a ~25 line `node:http` adapter.
Everything else in the file is what a deployment owns.

```sh
pnpm --filter @oaath/examples example:server            # memory store, port 8787
OAATH_SMOKE=1 pnpm --filter @oaath/examples example:server  # drive the round-trip and exit
```

| Variable | Effect |
| --- | --- |
| `OAATH_PORT` | Listen port. `0` picks a free one. Default `8787`. |
| `OAATH_POSTGRES_URL` | Switches the durable store to `@oaath/server/postgres`. |
| `OAATH_POSTGRES_CREATE_SCHEMA` | `1` creates the current schema first. It is not a migration and fails if the objects already exist. |
| `OAATH_SMOKE` | `1` runs the walkthrough below against itself, asserts every step, and exits non-zero on failure. |

```sh
createdb oaath_relay
OAATH_POSTGRES_URL=postgres://localhost/oaath_relay \
OAATH_POSTGRES_CREATE_SCHEMA=1 \
  pnpm --filter @oaath/examples example:server
```

## The four ports a deployment owns

- **store** — memory or PostgreSQL. The relay's state machine holds row locks and
  treats commit uncertainty as uncertainty; the store never decides transitions.
- **authentication** — decides who is a `client` and who is the `owner`, and
  returns the redirect URIs registered for that client. The relay refuses any
  redirect URI this port did not vouch for, and `null` is a refusal.
- **kms** — the decision artifact is sealed by this port before it reaches the
  store, so plaintext never touches the database.
- **clock** — milliseconds.

Both port implementations in this example are stubs and say so: every line a
deployment must replace carries a `REPLACE` comment. In particular the KMS stub is
a reversible encoding, **not** encryption; it exists to prove the port is wired.
No rate limiter is wired: there is no default one, and a deployment that needs it
injects `rateLimit` keyed on the authenticated `clientId`.

## curl walkthrough

Start the server, then run these against it. Every response is `cache-control:
no-store`, and every failure carries a structured `error.code` and nothing else.

```sh
RELAY=http://127.0.0.1:8787
CLIENT='authorization: Bearer demo-client-token'
OWNER='authorization: Bearer demo-owner-token'
JSON='content-type: application/json'
```

**1. The client creates an authorization request.** `codeChallenge` is the S256
PKCE challenge; the client keeps the verifier. The server prints both at startup.

```sh
curl -s -X POST $RELAY/authorization/requests -H "$CLIENT" -H "$JSON" -d '{
  "redirectUri": "https://app.example/callback",
  "codeChallenge": "rzIqQ2KxRJ5ve6FCu99ha1woowqIcgvINFZjQDPPtz4",
  "requestedScope": "{\"chainScope\":\"all\"}"
}'
# {"requestId":"ECdLnW2ydoVhfWJywrosinpkRKuDHxj27gFP0NxMDeA","expiresAt":1785810279241}
export REQUEST_ID=ECdLnW2ydoVhfWJywrosinpkRKuDHxj27gFP0NxMDeA
```

**2. The owner reads the request.** This route is the owner's, not the client's:
the same call with `$CLIENT` returns `403 relay_forbidden`.

```sh
curl -s $RELAY/authorization/requests/$REQUEST_ID -H "$OWNER"
# {"requestId":"…","clientId":"demo-client","requestedScope":"{\"chainScope\":\"all\"}",
#  "expiresAt":1785810279241,"expired":false,"decision":null}
```

**3. The owner decides.** Terminal: a second decision on the same request is
refused. `artifact` is whatever the owner's device sealed — the relay treats it as
opaque and never parses it.

```sh
curl -s -X POST $RELAY/authorization/requests/$REQUEST_ID/decision -H "$OWNER" -H "$JSON" -d '{
  "outcome": "approved",
  "artifact": "{\"approvedBy\":\"owner-console\"}"
}'
# {"outcome":"approved","code":"SYxT6R4l…","artifactId":"jaIydsT9…","codeExpiresAt":1785810045813}
export CODE=SYxT6R4lynOmZihuaaWu9Zp9H-oejgBjsTlyKHZOc1I
export ARTIFACT_ID=jaIydsT9Ol_uSOFAz4QPF3pcmvgieKiKm0O3W3tzFUE
```

**4. The client consumes the one-time code** with the verifier for the challenge
it sent, and the redirect URI it registered.

```sh
curl -s -X POST $RELAY/authorization/codes/consume -H "$CLIENT" -H "$JSON" -d '{
  "code": "'$CODE'",
  "codeVerifier": "demo-code-verifier-that-is-long-enough-0123456789",
  "redirectUri": "https://app.example/callback"
}'
# {"requestId":"ECdLnW2y…","artifactId":"jaIydsT9…"}
```

**5. The client claims the artifact — once.**

```sh
curl -s -X POST $RELAY/authorization/artifacts/$ARTIFACT_ID/claim -H "$CLIENT"
# {"requestId":"ECdLnW2y…","artifact":"{\"approvedBy\":\"owner-console\"}"}
```

**6. The replay fails closed** with a code and no disclosure. This is the
one-time release the whole relay exists for.

```sh
curl -s -i -X POST $RELAY/authorization/artifacts/$ARTIFACT_ID/claim -H "$CLIENT"
# HTTP/1.1 409 Conflict
# {"error":{"code":"relay_artifact_already_claimed"}}
```

`POST /authorization/resume` with `{"requestId":"…"}` is the seventh route: it
returns the same state body after fresh relay authentication, for a client that
lost its local state.

## Evidence limits

This example proves the wiring, not the deployment. It never claims durability
across a process restart, concurrent claim safety, or KMS behaviour;
`packages/server/test/postgres.test.ts` and `restart.test.ts` own those behind
`OAATH_REQUIRE_POSTGRES`, and `pnpm smoke:server` owns the packed-consumer claim.
