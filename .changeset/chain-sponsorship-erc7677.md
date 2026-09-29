---
"@oaath/sdk": minor
"@oaath/testing": minor
---

The chain `sponsorship` setting also carries ERC-7677:
`{ kind: "erc7677", url, request, estimate }` replaces
`OaathChainCapability.paymasterService`, and `OaathRegisteredPaymasterService` is
removed without an alias. A chain holds at most one sponsorship kind, so a service
bootstrap chain that advertises both ERC-7677 and an ERC-7902 static commitment
is rejected with `oaath_client_capability_invalid`. Viem chain ports with
`paymasterUrl` produce the `erc7677` setting. The per-call `payer` option, routes,
and the EIP-5792 `paymasterService` wire capability are unchanged.
