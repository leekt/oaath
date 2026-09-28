---
"@oaath/sdk": patch
---

Expose `grant.reviewCalls({ chain, calls })` with immutable account, signer,
route, exact calls, and policy enforcement facts. Review shares the execution
checks but does not quote, sign, submit, or write durable Grant/Operation state.
