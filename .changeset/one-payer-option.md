---
"@oaath/sdk": minor
---

Plain Grant and owner `sendCalls`/`reviewCalls` take one optional `payer`
setting in place of separate `feePayer` and `paymasterService` fields:
`{ kind: "paymaster-service", url, context }` (`OaathPaymasterServicePayer`) or
`{ kind: "connected-eoa", wallet }` (`OaathConnectedEoaPayer`). Omitting it
keeps the chain's configured routes. Routing, sponsorship, fallback, and the
`oaath-calls-review-v1` review contract are unchanged. `OaathPaymasterServiceInput`
and `OaathConnectedEoaFeePayer` are removed without aliases.
