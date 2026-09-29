---
"@oaath/server": minor
---

The native projection is `oaath.native-projection/v7`. Permission scopes carry
`perChainOperationIntervalSeconds`, which is null for a lifetime cap. Phone
consent shows "Up to N operations per chain per <interval>" and a refill fact.
Windowed requests are no longer refused. The phone rejects v6 projections.
