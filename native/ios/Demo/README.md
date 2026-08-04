# OAAth owner-phone demo app — EXPERIMENTAL PREVIEW

A runnable SwiftUI app over the `OwnerPhone` + `OwnerPhoneDemo` package
targets. It pairs with the demo relay (`examples/phone`), receives the real
APNs approval push, shows the full consent screen, and delivers the released
one-time code back to the waiting web example. Preview means: no stability
guarantee and no production qualification.

## Run on a physical iPhone (primary target)

1. Start the web half on your Mac: `pnpm --filter @oaath/examples example:phone`
   (see `examples/phone/README.md`). It prints the Mac's LAN IP, a one-shot
   **pairing code**, and later an operation id + match code. macOS will ask to
   allow incoming connections for `node` — allow it, or the phone cannot reach
   the relay.
2. Open `native/ios/Demo/Demo.xcodeproj` in Xcode (it references the package
   in `native/ios` automatically).
3. Signing & Capabilities → select your personal team (a free Apple account
   works; the app is then provisioned for 7 days) and set a **unique** bundle
   identifier (replace `org.oaath.owner-phone-demo`).
4. Select your iPhone as the destination. On iOS 16+ enable Developer Mode
   first: Settings → Privacy & Security → Developer Mode, then reboot.
5. Run. The app ships with an **empty** relay field: a phone can never use the
   Mac's loopback address. Scan/tap the terminal's QR/link (it carries both the
   reachable LAN relay URL and pairing code), review the filled fields, then tap
   "Pair this device". The phone and Mac must be on the same network.

The device keeps the normalized relay endpoint and its issued credential as one
versioned Keychain value after pairing; neither can be loaded or used apart.
While paired, new pairing links are ignored until **Clear pairing** explicitly
forgets that bound identity. The pairing code is one-shot and expires. If the
bound relay refuses the credential (after an example restart — its state is
in-memory), the app clears the whole pairing and returns to the pairing screen:
pair again with the freshly printed code.

## Push notifications (optional, paid account required)

The push entitlement (`aps-environment`) requires a **paid Apple Developer
membership** — free personal teams cannot use it. Without one: remove the Push
Notifications capability (and ignore the entitlements file) and use the manual
operation-id entry in the app; everything else works.

With a paid membership:

1. developer.apple.com → Certificates, Identifiers & Profiles → Keys → create
   an APNs key; download the `.p8` once and note the **Key ID**.
2. Note your **Team ID** (Membership page) and use your app's **bundle id**
   as the topic.
3. Hand all four to the example (`APNS_KEY_PEM_PATH`, `APNS_KEY_ID`,
   `APPLE_TEAM_ID`, `APNS_TOPIC` — see `examples/phone/README.md`). The
   example pushes to **api.sandbox.push.apple.com**: dev-signed installs
   receive SANDBOX device tokens, and pushing the production host instead is
   the classic silent failure.
4. Tapping the notification only **opens** the consent screen. Nothing is ever
   decided by a tap: Approve and Reject are explicit buttons, always.

## Simulator fallback

Any iOS simulator runs the app without signing (Xcode → Demo scheme → a
simulator destination). Tests may fill a loopback relay URL. The simulator
receives no APNs pushes and uses manual operation-id entry. It cannot create a
Secure Enclave key, so the app uses a distinct non-extractable keychain P-256
key available only while this device is unlocked
(`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) and shows an explicit
**SIMULATOR FALLBACK** banner.

## Dev-only ATS exception

`Support/Info.plist` sets `NSAllowsArbitraryLoads` because the demo relay
serves plain http on the LAN. That is a development-only setting: a real
deployment serves https and deletes the key.

## Owner key and signing boundary

First launch generates a persistent P-256 key in the Secure Enclave on a
physical iPhone (`kSecAttrTokenIDSecureEnclave`, `.privateKeyUsage`, no biometry
requirement because Approve is already the explicit consent gate). Pairing
registers its `x ‖ y` public material. The web half derives the chain-independent
CREATE2 account and returns it; the phone labels the server-side derivation
honestly. For both the replayable enable digest and owner UserOperation hash,
Approve signs the exact projected 32 bytes, converts platform DER to raw
`r ‖ s`, low-S normalizes, and releases that signature once. Reject signs
nothing. Push/tap only opens review.

## Provenance

The Xcode target in `Demo/Demo.xcodeproj` is a thin current wrapper around the
local Swift package. Its provenance owner and discarded-retired-source record
is the parent [`native/ios/README.md`](../README.md#provenance); this cross-link
is intentional so the project cannot imply a second provenance authority.

## Build evidence and limits

`swift build` + `swift test` (macOS host) cover every testable part:
`OwnerPhone` (wire decoders, review machine) and `OwnerPhoneDemo` (routes,
pairing, credential store, code delivery, screens compile). The Demo app also
builds unsigned for the generic iOS Simulator with `xcodebuild -sdk
iphonesimulator -destination 'generic/platform=iOS Simulator'
CODE_SIGNING_ALLOWED=NO build`. Not proven headlessly: a physical-device build,
APNs delivery, provisioning, and physical Secure Enclave/keychain behavior — a
human with Xcode and an iPhone owns those steps above.
