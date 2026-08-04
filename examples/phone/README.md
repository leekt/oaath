# Owner-phone approval demo (web half)

The full "web app asks, your iPhone approves" loop:

1. this file starts the relay on your Mac's LAN address and a tiny callback
   listener (the "web app" waiting for its authorization code);
2. it prints a **one-shot pairing code** — the iPhone app
   ([native/ios/Demo](../../native/ios/Demo)) trades it (plus its APNs device
   token) for a device-scoped owner credential;
3. it creates a PKCE authorization request whose scope is a real
   `@oaath/protocol` permission request, so the phone renders full structured
   consent (client, permitted calls, value limits, operation limit, expiry);
4. optionally it pushes the real APNs notification (see below);
5. the owner approves on the phone; the phone delivers the released one-time
   code to the callback; this file consumes it (PKCE verifier), claims the
   sealed artifact once, and proves every replay is refused.

```sh
pnpm --filter @oaath/examples example:phone      # then follow the printed steps
```

The run exits non-zero if the loop does not complete within five minutes.

## Networking

A physical iPhone cannot reach your Mac's `127.0.0.1`, so the relay and the
callback bind `0.0.0.0` by default (`OAATH_HOST` overrides) and the printed
URLs use the Mac's first non-internal IPv4 address. **This is a demo binding
with fixed demo tokens on a trusted network only** — anyone on the network can
hit the relay. macOS will ask to allow incoming connections for `node`; allow
it. The phone and the Mac must be on the same network.

## Real push (optional)

With APNs credentials the example sends the real notification after the phone
pairs — built by `createApnsSender` and sent once through the settle-once
HTTP/2 transport to **`api.sandbox.push.apple.com`**. Dev-signed apps receive
SANDBOX device tokens; pushing the production host instead is the classic
silent failure. Requires a paid Apple Developer membership (push entitlement);
see [native/ios/Demo/README.md](../../native/ios/Demo/README.md).

```sh
APNS_KEY_PEM_PATH=~/AuthKey_ABC1234567.p8 \
APNS_KEY_ID=ABC1234567 APPLE_TEAM_ID=TEAM123456 \
APNS_TOPIC=org.oaath.owner-phone-demo \
pnpm --filter @oaath/examples example:phone
```

These variables (and `APNS_KEY_PEM` as an inline alternative) may also live in
`examples/.env`, which is git-ignored and loaded when present — the real
environment wins over the file. They are deliberately scrubbed from every
test/gate environment; this example reads them **at runtime only** and is not
a gate. Without them the push is skipped and the printed operation id is
pasted into the app instead — the demo works without any Apple account.

## Pairing honesty

The pairing code printed to this terminal is the demo's trust root: single
use, ten-minute expiry, hash-compared, on a trusted LAN. The issued device
credential and the paired APNs token live in a module-level `Map` in this
process on purpose — the relay's store contract is not widened for a preview,
and restarting the example forgets the pairing (the app returns to its pairing
screen on the resulting 401). A production deployment owns pairing UX (QR,
attestation) through its authentication port.

## Unattended check

`OAATH_PHONE_SIMULATE=1` makes the example drive the phone's half itself over
plain HTTP — pairing (and its one-shot replay refusal), projection, approval,
decision replay, and code delivery — so `pnpm examples:check` covers the whole
loop with no phone, no LAN binding, and no Apple contact.
