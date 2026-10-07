---
"@oaath/sdk": patch
---

Add `loginWithOAAth` and `completeOAAthLogin`: Login with OAAth through the issuer's portal popup (PAR + PKCE, RFC 9207 issuer check, ES256 id_token verified against the issuer's JWKS), returning the chosen account and its proven member signer with `verified: true`.
