---
"@oaath/sdk": minor
"@oaath/testing": patch
---

`OaathChainCapability` describes the submission routes a chain offers as an
optional, ordered `routes` list (`{ kind: "erc4337-bundler", bundler }`,
`{ kind: "erc4337-handleops", feePayer }`). It replaces the required `bundler`
probe and the `feePayer` field. Routing picks the first route that is
conclusively usable, and only a configured bundler route is ever probed. A
chain with no routes fails with `oaath_client_route_unavailable` and the
`route_none_configured` reason. `createViemChainPorts`, service mode and the
`@oaath/testing` Anvil fixtures fill `routes` in, so normal callers never name a
transport.

Breaking advanced API change: custom chain capabilities pass `routes` instead
of `bundler` and `feePayer`. The relay wire, the selected-route evidence and
persisted records do not change.
