---
"@oaath/sdk": minor
---

Routing decides over an ordered list of submission routes. `decideExecution`
and `captureRoutingCapabilities` take `routes` (`erc4337-bundler` with its
probe classification, `erc4337-handleops` with its fee payer) instead of
separate `bundler` and `feePayer` facts. The first conclusively usable route
wins, an unreadable bundler still forbids every later route, and an empty list
returns `route: "none"` with `route_none_configured`.

Breaking advanced API change: route reasons are per route
(`route_available`, `route_absent`, `route_unsupported`, `route_unreadable`,
each suffixed with `:<route kind>`) and replace the `bundler_*` and
`fee_payer_*` codes. The selected route in review and execution evidence is
unchanged. The EntryPoint 0.7 bundler, prefund and handleOps helpers now live
under `routing/erc4337/`; their exports are unchanged.
