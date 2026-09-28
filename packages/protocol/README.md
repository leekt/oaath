# @oaath/protocol

IO-free OAAth wire and durable contracts, including the concrete Kernel v4
signing profiles. See the
[repository README](https://github.com/leekt/oaath#readme).

The shared contracts cover caller/account bindings, service bootstrap, permission
requests and decisions, grants, operations, and owner signing. `deriveCodeChallenge`
owns PKCE S256 challenge derivation. Authorization request/code storage, decision
transactions, code consumption, and HTTP responses belong to `@oaath/server`.

`oaath.operation/v3` retains nullable `submission` evidence: a bundler
acknowledgement or an EntryPoint `handleOps` transaction hash. The closed
`OperationSubmissionEvidence` type and `parseOperationSubmissionEvidence` own
that shape. It is transport evidence only; authoritative observation still owns
inclusion, finality, and lane release. Retired record versions are rejected.

`captureBundlerRejection` captures only an allowlisted ERC-4337 pre-acceptance
refusal code. `readRpcBundlerRejection` reads that code from structured SDK RPC
error fields without inspecting prose or accessors. Relays may forward this
evidence for a failed submission; HTTP errors alone never prove non-acceptance.

`parseKernelV4RevocationSigningRequest` captures the self-funded Kernel 0.4.0 /
EntryPoint 0.7 owner-phone revocation profile. Its packed operation must contain
only the declared install-nonce invalidation or permission-uninstall calls.
`hashKernelV4RevocationSigningRequest` binds review metadata and the chain-bound
operation into the returned owner artifact. The owner device still verifies its
paired account, current consent and configured chain before signing. This is
separate from generic owner-signing requests; raw digests remain reject-only.
