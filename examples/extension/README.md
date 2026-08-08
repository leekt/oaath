# OAAth Chrome extension

Any existing dapp already speaks EIP-1193/EIP-6963 to whatever wallet announces
itself. This MV3 extension runs the URL-mode OAAth realm in its service worker
and announces the Grant provider to every page, so a dapp with **zero OAAth
integration** executes through scoped session authority: the user pairs once
per origin, the owner approves the scope on their own device, and
`eth_sendTransaction` becomes a session-signed, scope-checked operation.

## Trust boundaries

- **`injected.js` (page world)** holds nothing: no keys, no Grant, no
  transport. It announces the EIP-6963 provider (`rdns: "app.oaath"`) and
  forwards `request()` over `postMessage`.
- **`content.js`** is an untrusted relay. It interprets nothing.
- **`worker.js`** owns the realms. The page's identity is `sender.origin` as
  Chrome reports it — never anything a message claims. One Grant per origin,
  in that origin's own IndexedDB database, keyed by service URL, so no dapp
  can reach another's authority and a service change starts fresh.
- Every `wallet_sendCalls` request waits on an extension-owned confirmation tab
  showing that browser-bound origin, the exact account and chain, and every
  ordered call. When the request uses the supported ERC-7902 validity range,
  the same page also shows both inclusive endpoints as exact Unix seconds and
  UTC. Approval exists only in the current worker's one-use memory; rejection
  or closing the tab returns `4001`, while a worker restart cannot recover an
  approval or start the operation.
- **URL mode never holds owner authority.** Pairing routes the owner's review
  through the service's authorization flow (the phone); revocation from the
  extension invalidates the capability and leaves the Grant durably `revoking`
  until the owner's console removes the chain permission (through the relay's
  owner lane) — the extension then completes to `revoked` by observing the
  chain's own evidence that the permission is absent.

## Build and load

```sh
node examples/extension/build.mjs   # bundles worker + copies static files to dist/
```

Then `chrome://extensions` → Developer mode → **Load unpacked** →
`examples/extension/dist`.

## Pair a dapp

1. Run an OAAth service (e.g. `pnpm --filter @oaath/examples example:service`,
   or your own deployment) and set its URL + chain id in the popup.
2. The service must register a redirect URI on the dapp's origin — a Grant is
   only issued to origins the deployment knows.
3. Open the dapp, open the popup, fill the scope (target, selector, value
   limit), and request permission. The owner approves on their device.
4. The dapp's unchanged EIP-6963 discovery now finds "OAAth":
   `eth_requestAccounts` answers the Grant's derived smart account, and
   `eth_sendTransaction` / `wallet_sendCalls` execute through the session —
   denied with a scope error when the calls are outside the approved Grant.

## Provider surface

Exactly `@oaath/sdk/viem`: `eth_chainId`, `eth_accounts`,
`eth_requestAccounts`, `eth_sendTransaction`, and EIP-5792
`wallet_sendCalls` / `wallet_getCallsStatus` / `wallet_showCallsStatus` /
`wallet_getCapabilities`. `wallet_showCallsStatus` opens a read-only extension
page backed by the same durable bundle lookup as `wallet_getCallsStatus`.
`wallet_sendCalls` reserves no bundle and performs no quote, signature, or send
until its extension-owned confirmation returns `approved`.
Everything else is refused with code 4200 — this provider is a Grant, not a
general-purpose RPC node.
