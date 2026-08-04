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
- Fetches the full owner-phone consent projection
  (`packages/server/src/native/projection.ts`) and renders it exactly as the
  relay sends it: match code, the requesting client and its redirect target,
  the structured scope (permitted calls with value limits, operation limit,
  expiry) — or an explicit "unstructured scope, review the raw text" state.
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

## Transport is deployment-wired

The relay serves the preview routes `GET /native/projections/{operationId}`
and `POST /native/decisions/{operationId}`
(`packages/server/src/relay/handler.ts`). `TransportRelayClient` stays defined
against the documented projection/decision shapes, and a deployment injects
one closure that moves bytes and carries the authenticated owner credential.
Nothing in the `OwnerPhone` library reads configuration or holds credentials;
the demo wiring (URLSession transport, pairing, credential custody, code
delivery) lives in the `OwnerPhoneDemo` target.

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
    @StateObject private var model = DemoModel(credentials: KeychainCredentialStore())

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

`OwnerPhoneKeyCustody` plus `KeychainKeyCustodyStub` scaffold the owner
credential seam. No physical Secure Enclave behavior is proven anywhere in
this repository: `useSecureEnclave` defaults to `false`, simulators and macOS
test hosts prove nothing, and signature normalization belongs to the future
consumer of the signature. Apple provisioning and physical-device
qualification remain later work, per the program plan.

## Provenance

Reference material: `leekt/deployer` (master @ 3b732ff98b87),
`experimental/smart-account-oauth/ios-demo/` — a dependency-free SwiftUI demo
(~5,100 lines). It was mined for shape only; per AGENTS.md nothing from
`leekt/deployer` is preserved. Rebuilt against oaath's live wire contracts
(`packages/server/src/apns/sender.ts`, `native/{projection,decision}.ts`):
the push/projection/decision codecs, the review state machine's
ambiguous-submission discipline, and the custody seam. Deliberately discarded:
the retired `wallet.oauth.*` wire names and `/v1/...` routes, the
DER→P1363/low-S signature conversion (no oaath signature consumer exists yet),
the UserDefaults inbox persistence, the blocklist-style payload parsing
(replaced by closed exact-key capture), and the Xcode project (plain SPM
builds headlessly). A future reader re-mining that demo should treat this list
as the record of what was rejected on purpose.

## Gates

```sh
swift build   # macOS host, no simulator or device required
swift test    # unit tests over the pure parts of both targets
```

The tests cover the closed push decode, the consent projection decode
(structured and raw scope) and match-code rendering, decision decode with
one-shot/replay consistency, the review state machine including forbidden
transitions, the transport-injected client, and the demo wiring (routes,
pairing, credential custody, code delivery). The relay pins the same
envelopes from its side in `packages/server/test/native.test.ts`.

Evidence explicitly **not** available from these gates: real APNs delivery,
Apple provisioning and entitlements, physical Secure Enclave key creation and
user-presence prompts, hosted relay interoperability, and any simulator or
device run (see [Demo/README.md](Demo/README.md) for the human-owned steps).
