---
"@oaath/testing": patch
---

Expose the existing local owner fixture RPC handler as `rpcFetch(Request)` so
browser harnesses can use the ordinary SDK HTTP transport with native browser
storage. The caller owns loopback hosting and request budgets. Requests to
unrelated origins, non-POST requests and use after fixture closure are rejected.
