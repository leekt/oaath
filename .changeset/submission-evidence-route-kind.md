---
"@oaath/protocol": minor
"@oaath/sdk": minor
"@oaath/testing": patch
---

Submission evidence names its route by the route kind a chain configures:
`{ route: "erc4337-bundler", transactionHash: null }` or
`{ route: "erc4337-handleops", transactionHash }`. The protocol exports the
`OperationSubmissionRoute` type, and `OaathSubmissionRouteKind` is that type.
`OaathOperationExecution.route` reports the same values.

Breaking change: Operation records move to `oaath.operation/v5` and IndexedDB
schema 16. Older records are rejected; browser state is wiped and recreated
without migration. Custom submission sessions must return the new route values.
