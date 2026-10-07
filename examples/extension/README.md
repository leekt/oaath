# OAAth Chrome extension

Any existing dapp already speaks EIP-1193/EIP-6963 to whatever wallet announces
itself. This MV3 extension runs the portal-approved OAAth realm (`approvals: { kind: "oauth" }`)
in its service worker and announces the Grant provider to every page, so a dapp
with **zero OAAth integration** executes through scoped session authority: the
user pairs once per origin, the account root approves the scope in the OAAth
portal, and `eth_sendTransaction` becomes a session-signed, scope-checked
operation.

## Trust boundaries

- **`injected.js` (page world)** holds nothing: no keys, no Grant, no
  transport. It announces the EIP-6963 provider (`rdns: "app.oaath"`) and
  forwards `request()` over `postMessage`.
- **`content.js`** is an untrusted relay. It interprets nothing.
- **`worker.js`** owns the realms. The page's identity is `sender.origin` as
  Chrome reports it — never anything a message claims. One Grant per origin,
  in that origin's own IndexedDB database, keyed by issuer, so no dapp can
  reach another's authority and an issuer change starts fresh.
- Every `wallet_sendCalls` request waits on an extension-owned confirmation tab
  showing that browser-bound origin, the exact account and chain, and every
  ordered call. When the request uses the supported ERC-7902 validity range,
  the same page also shows both inclusive endpoints as exact Unix seconds and
  UTC. Before session display state is written or a tab opens, the SDK durably
  reserves the bundle ID with an exclusive five-minute confirmation deadline.
  Approval exists only in the current worker's one-use memory; rejection,
  expiry, or closing the tab returns `4001`, while a worker restart cannot
  recover an approval or start the operation. Rejected and expired explicit IDs
  remain durable tombstones and cannot be reused.
- **The extension never holds owner authority.** Pairing opens the issuer's
  portal with `chrome.identity.launchWebAuthFlow` (the SDK's `approvals.launch`);
  the account root reviews and signs there, and the redirect to
  `chrome.identity.getRedirectURL("oaath")` returns the code. The issuer binds
  the Grant to that redirect origin, the extension itself; the extension keeps
  each page origin's Grant separate. Revocation from the extension stops the
  site at once and leaves the Grant durably `revoking` until the account owner
  removes the chain permission; the extension then completes to `revoked` by
  observing the chain's own evidence that the permission is absent.

## Build and load

```sh
node examples/extension/build.mjs   # bundles worker + copies static files to dist/
```

Then `chrome://extensions` → Developer mode → **Load unpacked** →
`examples/extension/dist`.

## Pair a dapp

1. In the popup's settings, set the issuer (default `https://oaath.taek.tech`),
   the chain ID, its RPC URL, and a bundler URL. The extension registers itself
   with the issuer once, for its own redirect URI.
2. Open the dapp, open the popup, fill the scope (target, selector, value
   limit), and request permission. An OAAth window opens; the account root
   reviews and signs there.
3. The dapp's unchanged EIP-6963 discovery now finds "OAAth":
   `eth_requestAccounts` answers the Grant's derived smart account, and
   `eth_sendTransaction` / `wallet_sendCalls` execute through the session —
   denied with a scope error when the calls are outside the approved Grant.

## Provider surface

Exactly `@oaath/sdk/cetane`: `eth_chainId`, `eth_accounts`,
`eth_requestAccounts`, `eth_sendTransaction`, and EIP-5792
`wallet_sendCalls` / `wallet_getCallsStatus` / `wallet_showCallsStatus` /
`wallet_getCapabilities`. `wallet_showCallsStatus` opens a read-only extension
page backed by the same durable bundle lookup as `wallet_getCallsStatus`.
`wallet_sendCalls` CAS-reserves its bundle before presentation, but performs no
quote, signature, or send until its extension-owned confirmation returns
`approved`. Approval receives a fresh 30-second operation-publication lease;
the presentation deadline never consumes that lease.
Everything else is refused with code 4200 — this provider is a Grant, not a
general-purpose RPC node.
