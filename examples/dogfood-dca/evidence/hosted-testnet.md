# Hosted testnet deployment — 8 October 2026

The explicitly authorized example is hosted at <https://dca.taek.tech> on
Arbitrum Sepolia (421614). Cloudflare Worker version
`38e1c8ae-7acc-4f22-bbff-3ff7faca31e8` serves exactly three public assets.
The dedicated `dca-api` VPC service reaches the owned OCI host through its
existing tunnel. The Rust API, TypeScript runtime and example gateway run as
three separate loopback-only `dca-*` systemd services. This deployment works
independently of the development Mac.

The DCA factory is `0x6d2186dc7f7e973b9bc11235dadbf0147f76133e`, deployed in
transaction `0x671aad6538c6cce57e4913cd9ddfb433fe69e7b29a8ca9fb6a6b5fb315973f81`.
Its runtime bytecode matches the pinned artifact and was read at finalized
state. The deployment command used 11 of its 100 permitted RPC methods. The
profile pins Kernel v4, EntryPoint 0.9, test USDC/WETH, SwapRouter02 and two
Chainlink feeds. No owner or service private key is shipped to the browser.

Verified public behavior:

- A real owner signature logs in; the same challenge cannot be replayed.
- Unauthenticated API access is refused, foreign POST origins are refused,
  and private paths, source maps and local fixture-owner routes return 404.
- The proof wallet created its Kernel account and funded it with test assets.
- The browser displays exact plan review and signs both consent payloads.
- After replacing the deployed binaries and restarting every DCA service,
  all three services are active; the retained session still accesses the same
  four plans (three awaiting consent, one draft). This check sends no operation.

Local evidence for the deployment stack: 20 contract tests, 39 product tests,
SDK typecheck/lint/build and the packed wallet proof passed. The local real
Kernel v4 / EntryPoint 0.9 / SwapRouter02 purchase finalized successfully.
The latest OAAth estimation guard additionally passed 25 focused tests and
the same packed local owner-operation proof. No viem production dependency
was found by the packed dependency check.

The hosted UI proof uses controlled API fixtures to test pending account setup,
reload retention, prevention of duplicate setup requests, and keyboard focus.
Desktop and mobile captures were reviewed; the Impeccable reviewer returned
SHIP after pending-state and focus fixes. Those captures are UI evidence only.

Public execution remains incomplete. ZeroDev returned inconsistent verification
gas estimates and rejected a zero-gas submission with -32602. The retained
operation is unresolved; neither its missing receipt nor a service restart
caused a replacement send. OAAth now rejects zero effective verification gas
before publication. No finalized public purchase or confirmed public
cancellation is claimed. See [gas evidence](verification-gas.md).

This is a testnet compatibility proof, not production readiness or an RPC
performance benchmark. No package was published, and unrelated tunnel,
Tailscale, database and application services were left in place.
