# Browser example — connect, grant, execute, revoke

The supported browser journey, end to end, in one file.

```sh
pnpm --filter @oaath/examples example:browser                       # injected chain facts
OAATH_REQUIRE_ANVIL=1 pnpm --filter @oaath/examples example:browser # real local chain
```

## What it demonstrates

1. **connect** — `oaath.connect()` binds issuer, client, origin, device, user, and
   the logical account once. `connection.resume()` returns `null`: no authority
   exists and nothing is persisted before consent.
2. **one all-chain grant** — `requestPermission({ chainScope: "all", … })` sends the
   reviewed scope to the relay, the owner console approves it once, and the client
   receives an active Grant. One review covers every supported chain, including
   chains that do not exist yet.
3. **execute** — `grant.sendCalls({ chain, calls })` diagnoses the chain, decides the
   signer and route *before* signing, prepares and durably records the exact
   operation identity, submits it once, and finalizes that same identity from
   observation. `operation.wait()` returns the outcome.
4. **revoke** — `grant.revoke()` invalidates the replayable approval capability
   through the deployment's own port and drives the Grant to `revoked`. It submits
   nothing new: the assertion that the transport still holds exactly one snapshot
   is in the file.

The application code touches `state`, `expiresAt`, `sendCalls`, `revoke`, and
`close`. No permission id, enable envelope, journal revision, or nonce appears
anywhere in it.

## What is real and what is injected

Real: the issuer. `createRelayHandler` from `@oaath/server` runs in this process
over its in-memory store, so the client speaks the actual wire contract —
authorization request, owner decision, one-time code, sealed artifact claim — and
not a mock of it. The owner console is a separate actor here too: it reads the
scope back from the relay and posts the decision, exactly as an owner device does.

Injected: the chain, and only the chain.

- **default** ([fake-chain.mjs](fake-chain.mjs)) — the five chain ports answered
  from fixtures. Runs anywhere, needs no network. The submission transport records
  the exact snapshot it was handed and the observation evidence is derived from
  that snapshot, so the identity that finalizes is the identity that was
  submitted.
- **`OAATH_REQUIRE_ANVIL=1`** ([anvil-chain.mjs](anvil-chain.mjs)) — the same five
  ports over a local Anvil with the real Kernel v4 stack deployed. The devnet has
  no bundler, so the probe reports `absent` and the routing decision falls back to
  direct `EntryPoint.handleOps` with an EOA fee payer — same prepared operation,
  same hash, same signature, different outer transaction. The observation port then
  rebuilds the bundler-shaped receipt from the EntryPoint's own
  `UserOperationEvent`, which is what a deployment without a bundler must do.

Swapping those two files changes nothing else: `run.mjs` is byte-identical for
both. That boundary is the point.

## Persistence

The example uses the in-memory stores. A browser passes the `createIndexedDb*`
adapters from the same entry instead — same five names, same journey — and gets
non-extractable key custody plus a Grant that survives a reload.
`pnpm smoke:browser` owns the full realm-recreation proof.
