# OAAth owner-phone iOS app — EXPERIMENTAL PREVIEW

A SwiftUI owner-phone approval app for the OAAth relay's native preview
surfaces. Preview means: no stability guarantee and no production
qualification. It is **not** part of the fixed npm release group and is never
published to npm.

## What it does

- Decodes the OAAth APNs payload exactly as
  `packages/server/src/apns/sender.ts` serializes it: the localization keys,
  the 8-character match code as the single `loc-args` element, and
  `{version, operationId, expiresAt}` under `oaath`. Nothing else exists in
  the payload by design, and nothing else is accepted — any unknown field at
  any level fails closed, so authority material can never ride a notification.
- Polls the example-owned authenticated pull inbox by default while paired
  (about every two seconds, plus manual Refresh). The inbox is a strict closed
  versioned list of at most 20 immutable operation-id/match-code/expiry
  summaries. Selecting one only opens the full projection; poll and tap never
  approve or reject. This is the Simulator/free-account path; APNs remains an
  optional physical-device enhancement.
- Fetches the full owner-phone consent projection
  (`packages/server/src/native/projection.ts`) and renders it exactly as the
  relay sends it: match code, the requesting client and its redirect target,
  the structured permission scope, or the full current-version owner-signing
  request. Every structured-permission fact carries one closed evidence label:
  relay-bound client/redirect facts are visually distinct from requested scope
  and requested constraints. The projection contains no materialization,
  onchain-install, or simulation evidence, so it labels no constraint
  guaranteed. Structured permission requests expose explicit Approve/Reject
  actions. Owner-signing requests expose every captured purpose, signer,
  versioned credential, typed-data, expected digest, replay, and request-hash
  fact. Only an exact Kernel/P-256 request with a current local pairing exposes
  Approve; every other owner-signing request remains reject-only.
  The push and the authenticated projection must agree exactly or the review
  fails closed. The push payload itself stays opaque; the consent detail
  travels only the authenticated channel.
- Submits approve/reject keyed by the stable `operationId` and renders the
  replayed-outcome semantics of `packages/server/src/native/decision.ts`
  honestly: a retry answers the **stored** outcome (which may differ from the
  retried command, and the UI says so), and one-time release material goes
  only to the deciding call — a replay carries none.
- Keeps an ambiguous submission as an explicit unresolved intent. Nothing is
  ever auto-resubmitted; an explicit retry is safe only because the server
  saga is replay-only.

## EIP-712 derivation and Kernel approval

`OwnerPhone` uses a package-internal, non-authorizing EIP-712 primitive to
capture the projection's already-parsed canonical typed-data value and compare
its device-derived Ethereum Keccak-256 digest with the request's expected
digest. The UI renders a match or mismatch from that same immutable capture.
Shared protocol/viem/Swift vectors cover the official Mail example, nested
fixed and dynamic arrays, signed and unsigned integers, fixed and dynamic
bytes, strings, booleans, addresses, and domain subsets.

The live v4 exact Kernel/P-256 branch creates a sealed
`VerifiedSignableDigest` only after the current pending review, expiry,
foreground state, paired account/key, Kernel semantics, and device-derived
digest all agree. `requestHash` is authenticated server/protocol evidence and
is not independently re-derived by this build; the server recomputes it before
accepting the signed artifact. Other EIP-712 purposes and protocol raw-digest
requests remain reject-only. The semantic decoder does not claim preservation
of raw JSON bytes; the relay owns canonical protocol capture before projection.

## Transport is deployment-wired

The relay serves the preview routes `GET /native/projections/{operationId}`
and `POST /native/decisions/{operationId}`
(`packages/server/src/relay/handler.ts`). `TransportRelayClient` stays defined
against the documented projection/decision shapes, and a deployment injects
one closure that moves bytes and carries the authenticated owner credential.
Nothing in the `OwnerPhone` library reads configuration or holds credentials;
the demo wiring (URLSession transport, pairing, bound endpoint/credential
custody, example-owned `GET /demo/inbox`, code delivery) lives in the
`OwnerPhoneDemo` target.

## App wiring

The package builds headlessly as plain SPM libraries. The runnable demo app —
pairing screen, consent screen, push registration, ATS/dev-signing notes —
lives in [Demo/](Demo) as a thin Xcode target over `OwnerPhoneDemo`:

```swift
import OwnerPhone
import OwnerPhoneDemo
import SwiftUI

@main
struct OwnerPhoneDemoApp: App {
    @UIApplicationDelegateAdaptor(PushRegistrationDelegate.self) private var pushDelegate
    @StateObject private var model = DemoModel(pairings: KeychainPairingStore())

    var body: some Scene {
        WindowGroup {
            DemoRootView(model: model)
                .task {
                    pushDelegate.onDeviceToken = { token in Task { @MainActor in model.deviceToken = token } }
                    // A tap only opens the consent screen; deciding stays an explicit button.
                    pushDelegate.onPush = { push in Task { await model.receive(push: push) } }
                }
        }
    }
}
```

## Key custody

On physical iOS, the demo exclusively creates or loads a persistent P-256
Secure Enclave key with `kSecAttrTokenIDSecureEnclave`, `.privateKeyUsage`,
and `.userPresence`.
An Enclave failure leaves the owner key unavailable; it never authorizes
software custody. Simulator and macOS host builds instead select a separately
tagged, non-synchronizable keychain P-256 key with
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and display an explicit
simulator/fallback banner. The app registers 64-byte `x ‖ y` public material,
and custody accepts only the library's sealed verified-signable type. An exact
Kernel replayable-install request can reach artifact generation only from a
current authenticated review whose account, P-256 key, locally derived
EIP-712 digest, pairing, foreground state, and expiry all agree. Raw network
digests and every other owner-signing request remain reject-only and reach
neither custody nor an approval POST.
Host tests pin the software attributes, Enclave creation flags, and
platform-selection policy and prove the pure DER conversion, low-S arithmetic
and real CryptoKit verification; they do not prove a physical user-presence
prompt, Enclave custody, or live clear signing.

## Provenance

Reference material: `leekt/deployer` (master @ 3b732ff98b87),
`experimental/smart-account-oauth/ios-demo/` — a dependency-free SwiftUI demo
(~5,100 lines). It was mined for shape only; per AGENTS.md nothing from
`leekt/deployer` is preserved. Rebuilt against oaath's live wire contracts
(`packages/server/src/apns/sender.ts`, `native/{projection,decision}.ts`):
the push/projection/decision codecs, the review state machine's
ambiguous-submission discipline, and the custody seam. Deliberately discarded:
the retired `wallet.oauth.*` wire names and `/v1/...` routes, the old signature
codec (the current DER→raw low-S implementation was rebuilt against the SDK's
P-256 rule), the UserDefaults inbox persistence, and the blocklist-style payload
parsing (replaced by closed exact-key capture). The thin current Xcode project
is provenance-cross-referenced in [`Demo/README.md`](Demo/README.md#provenance);
no retired project was copied. A future reader re-mining that demo should treat
this list as the record of what was rejected on purpose.

## Gates

```sh
swift build   # macOS host, no simulator or device required
swift test    # unit tests over the pure parts of both targets
```

The tests cover the closed pull-inbox and push decodes, authenticated inbox
endpoint/model ownership, the consent projection decode
(structured and raw scope) and match-code rendering, decision decode with
one-shot/replay consistency, the review state machine including forbidden
transitions, the transport-injected client, and the demo wiring (routes,
pairing, credential custody, code delivery). The relay pins the same
envelopes from its side in `packages/server/test/native.test.ts`.

Evidence explicitly **not** available from these gates: real APNs delivery,
Apple provisioning and entitlements, physical Secure Enclave key creation,
hosted relay interoperability, a simulator run, or any
signed physical-device install/run (see [Demo/README.md](Demo/README.md)). The unsigned
generic simulator build is a compile/link proof only.

## Dependency acknowledgment

Ethereum Keccak-256 is provided by
[CryptoSwift 1.10.0](https://github.com/krzyzanowskim/CryptoSwift/releases/tag/1.10.0),
pinned exactly in `Package.swift`. This product includes software developed by
Marcin Krzyżanowski (`https://krzyzanowskim.com/`). OAAth does not use
CryptoSwift for key custody or signing.
