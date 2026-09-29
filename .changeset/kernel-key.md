---
"@oaath/sdk": minor
"@oaath/testing": patch
---

Add `kernelKey({ kind?, ... })`, the one public key constructor on
`@oaath/sdk/kernel`. The credential kind is optional and checked, never
converted. The signing source comes from the input: `account` for a local
ECDSA account, `wallet` for a connected wallet, `sign` for a P-256
credential, `authenticate` for a WebAuthn credential, or `credential` alone
for a public-only key that cannot sign.

Breaking: `ecdsaKey`, `ecdsaWalletKey`, `p256Key`, `webauthnKey` and
`credentialKey` are no longer exported; pass the same input to `kernelKey`.
The `EcdsaKeyInput`, `EcdsaWalletKeyInput`, `P256KeyInput` and
`WebAuthnKeyInput` types stay exported as the members of `KernelKeyInput`, and
`CredentialKeyInput` is replaced by `KernelPublicKeyInput`, whose `validator`
is optional.
