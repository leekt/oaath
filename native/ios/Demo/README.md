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
5. Run. On first launch, enter the relay URL (`http://<your-mac-lan-ip>:8787`,
   exactly as the example printed it) and the pairing code, then tap
   "Pair this device". The phone and the Mac must be on the same network.

The device keeps its own relay credential (keychain) after pairing; the
pairing code is one-shot and expires. If the relay refuses the credential
(after an example restart — its state is in-memory), the app returns to the
pairing screen: pair again with the freshly printed code.

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
simulator destination). The simulator reaches the Mac at `127.0.0.1`, receives
no APNs pushes, and uses manual operation-id entry.

## Dev-only ATS exception

`Support/Info.plist` sets `NSAllowsArbitraryLoads` because the demo relay
serves plain http on the LAN. That is a development-only setting: a real
deployment serves https and deletes the key.

## Honest signing boundary

In this demo the phone AUTHORIZES via the relay's one-shot decision. The
approve artifact is an opaque placeholder (`demoApprovalArtifact()`): a real
deployment seals owner-device material behind that seam. The on-device
owner-key signature of the Kernel enable digest is NOT cryptographically real
here — and cannot be on-chain-real yet, because no reviewed Kernel v4
P-256/WebAuthn validator is pinned (the recorded release blocker). What the
phone displays IS what the relay's decision authorizes: the consent screen
renders the projection exactly as the relay serves it.

## Build evidence and limits

`swift build` + `swift test` (macOS host) cover every testable part:
`OwnerPhone` (wire decoders, review machine) and `OwnerPhoneDemo` (routes,
pairing, credential store, code delivery, screens compile). The app target was
validated as far as a CLI without the iOS platform allows: `xcodebuild -list`
parses the project, resolves the local package, and generates the Demo scheme.
Not proven headlessly: a simulator/device build (requires the iOS platform in
Xcode), APNs delivery, provisioning, and on-device keychain behavior — a human
with Xcode and an iPhone owns those steps above.
