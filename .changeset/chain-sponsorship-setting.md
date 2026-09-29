---
"@oaath/sdk": minor
"@oaath/testing": minor
---

`OaathChainCapability` gains one optional `sponsorship` setting
(`OaathChainSponsorship`), defaulting to none. The ERC-7902 static paymaster
commitment moves from `staticPaymasterConfigurationHash` to
`sponsorship: { kind: "erc7902-static", configurationHash }`, where the hash
still comes from `hashErc7902StaticPaymasterConfiguration`. The old field is
removed without an alias. `@oaath/sdk/advanced` no longer exports
`captureErc7902StaticPaymasterConfiguration`, `Erc7902StaticPaymasterConfiguration`,
`createErc7677SponsorshipCapability`, or `CreateErc7677SponsorshipCapabilityInput`;
the chain setting and the per-call `payer` own sponsorship selection.
