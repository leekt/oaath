---
"@oaath/protocol": minor
"@oaath/sdk": minor
"@oaath/server": patch
---

Grant policies can refill their per-chain operation limit once per fixed window.
`requestPermission` accepts `perChainOperationLimit: { count, intervalSeconds }`
alongside a bare lifetime count. The canonical policy is now
`oaath.grant-policy/v2` and always carries
`perChainOperationLimit: { count, intervalSeconds }`, with `null` as the only
lifetime representation; v1 policies, requests and Grants are rejected. The
interval is part of the policy hash.

Approval may lower the count but must keep the requested window exactly. A
shorter window refills sooner and widens authority. A longer window, or a
lifetime cap for a windowed request, is rejected as the issue specifies.

A windowed limit installs the pinned fixed-window rate-limit policy in place of
the lifetime count cap. Usage evidence reads that module at the finalized block
and reports a refill only once finalized chain time reaches the window end. A
reverted operation still consumes its slot. `OaathUsageRequest` carries
`intervalSeconds`. Phone consent refuses windowed requests until the native
projection can display the window.
