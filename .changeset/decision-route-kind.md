---
"@oaath/sdk": minor
---

The routing decision selects a route kind: `OaathExecutionRoute` is
`"erc4337-bundler" | "erc4337-handleops" | "none"`, and `decideExecution`
returns the kind of the route it picked. The submission request, call reviews
and the connected-EOA fallback review use the same values, so one route has one
name from chain configuration through retained evidence.

Breaking change: the `bundler` / `entrypoint-handleops` route literals are
removed. Custom submission capabilities must read `erc4337-bundler` and
`erc4337-handleops`.
