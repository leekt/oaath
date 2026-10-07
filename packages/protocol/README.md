# @oaath/protocol

IO-free OAAth wire and durable contracts, including the concrete Kernel v4
signing profiles. See the
[repository README](https://github.com/leekt/oaath#readme).

The shared contracts cover caller/account bindings, workspace account context, permission
requests and decisions, grants, operations, and owner signing. `deriveCodeChallenge`
owns PKCE S256 challenge derivation. Authorization request/code storage, decision
transactions, code consumption, and HTTP responses belong to the Rust relay.

`KernelAccountProfile` distinguishes derived Kernel v4 accounts from existing
accounts. The latter use `oaath.kernel-existing-account-profile/v3` with the
detected `kernelVersion` (`"0.3.3"` or `"0.4.0"`), an
`address`, EntryPoint `0.7` for Kernel `0.3.3` or `0.9` for Kernel `0.4.0`, and an ECDSA `ownerCredential`
(or, on `"0.4.0"`, a raw P-256 one); a WebAuthn owner, factory indices and
routes are rejected. Permission hashes and Grant identity bind that existing
address and owner. Parsing the profile does not prove deployment or ownership;
the runtime checks those facts on each action chain.

`oaath.operation/v5` names its lane and retains nullable `submission` evidence: an
`erc4337-bundler` acknowledgement or an `erc4337-handleops` EntryPoint transaction hash. The closed
`OperationSubmissionEvidence` type and `parseOperationSubmissionEvidence` own
that shape. It is transport evidence only; authoritative observation still owns
inclusion, finality, and lane release. Retired record versions are rejected.

`captureBundlerRejection` captures only an allowlisted ERC-4337 pre-acceptance
refusal code. `readRpcBundlerRejection` reads that code from structured SDK RPC
error fields without inspecting prose or accessors. Relays may forward this
evidence for a failed submission; HTTP errors alone never prove non-acceptance.

`parseKernelRevocationSigningRequest` captures the Kernel 0.4.0 / EntryPoint
0.9 owner-phone revocation profile, self-funded (`paymasterAndData: "0x"`) or
sponsored by a packed paymaster the digest covers. Its packed operation must
contain only the declared install-nonce invalidation or permission-uninstall calls.
`hashKernelRevocationSigningRequest` binds review metadata and the chain-bound
operation into the returned owner artifact. The owner device still verifies its
paired account, current consent and configured chain before signing. This is
separate from generic owner-signing requests; raw digests remain reject-only.

Address inputs accept lowercase, uppercase hex digits, or a valid EIP-55 checksum.
Mixed-case input with an invalid checksum is rejected with the field name. All
captured addresses, serialized artifacts, and hash inputs use lowercase.
`captureAddress` owns this rule for protocol and SDK input boundaries; domain
owners retain their error codes and zero-address rules.

Ethereum encoding and hashing use the exact Cetane version pinned in this repository.
`entryPointAbi` owns the shared packed-operation ABI for EntryPoint 0.7 and 0.9.
Run `bun run smoke:protocol` from the repository root to verify packed protocol
vectors without viem installed. Viem is a development-only reference oracle.
