---
"@oaath/sdk": patch
---

`requestPermissionApproval` accepts up to `OAATH_MAX_GRANT_CHAINS` (256, was 32 at the relay) chain IDs and refuses more as `oaath_client_input_invalid` before opening anything. An issuer refusal now carries the issuer's `error_description` in the message (`issuer refused the request: chains: at most 256 chain IDs`), with the OAuth `error` as `source`. `expiresAt` is documented as the exclusive Grant expiry: a non-null `policy.validUntil` must be earlier.
