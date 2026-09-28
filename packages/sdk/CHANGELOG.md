# @oaath/sdk

## 0.2.0

### Patch Changes

- ae7b016: Derive a separate Kernel install nonce namespace for each canonical permission
  request. Phone approval preparation no longer takes a caller-selected nonce;
  the same request recreates the same signing packet without an allocation store.
  Expose kernelPermissionInstallNonce for other owner integrations. Sequence-zero
  allocation requires Kernel's global minimum nonce to remain zero on each chain.
- bcf1498: Expose Kernel install nonce read and invalidation codecs for owner integrations.
  An owner self-call can invalidate one unused approval on a destination chain
  without advancing other install keys or the account's global minimum. These
  codecs do not replace installed-permission removal or revocation observation.
- 8720b76: Add `prepareKernelPhonePermissionApproval` to derive the existing phone signing request and complete a P-256 signature into the canonical permission decision and replayable install approval. Share policy mapping and public credential profiles between the owner integration and application runtime. Phone transport and install-nonce allocation remain caller-owned.
- 8ee17d3: Bind the selected workspace/account context into PermissionRequest v2 and its
  approval hash. SDK requests retain their connection's context, and resume rejects
  a stored request from another context. Requests use one current encoding with
  explicit null for frontend session custody. Previous request versions are rejected
  and require fresh authorization; operation evidence is not migrated or deleted.
- 138440f: Add a closed, versioned Kernel owner-phone revocation request and SDK preparation
  helper. Requests bind the canonical permission, install scope and exact
  chain-bound owner operation to an install-invalidation or permission-uninstall
  effect. Completion verifies the phone signature without submitting anything.
  The shared removal-call encoders now live in protocol and report
  signing_request_invalid; SDK exports retain the current codec names.
- 5fa5e2f: Expose read-only `Operation.execution()` with finalized sender and exact ordered calls decoded from the containing EntryPoint transaction and bound to the retained operation hash. Observation adapters supply the new `transaction_execution` read. Unsupported or mismatched evidence fails closed; no signature or provider lifecycle state is exposed.
- b090f68: Expose `grant.reviewCalls({ chain, calls })` with immutable account, signer,
  route, exact calls, and policy enforcement facts. Review shares the execution
  checks but does not quote, sign, submit, or write durable Grant/Operation state.
- 439f120: Expose stable operation IDs and exact local operation recovery through
  `grant.getOperation({ chain, id })`, including observation after grant expiry.
  `sendCalls` now starts fresh calls without waiting for inclusion and rejects an
  occupied lane instead of returning an older unresolved operation.
- b8b1c94: Include the selected Kernel validation and mode in deployment quote requests so
  quotes can read the correct EntryPoint nonce for repeated session operations.
- 7a3c96a: Make bootstrap caller-dependent and add a versioned personal/team workspace and
  account context. Deployments now provide `bootstrap.resolve(caller)`; static
  bootstrap configuration is removed. Local realm and session identities include
  the selected context and complete account profile, so context switching and
  cleanup stay isolated. The bootstrap v4 and local binding/session v2 formats
  replace their predecessors without migration; existing clients must reapprove.
- Updated dependencies [8ee17d3]
- Updated dependencies [138440f]
- Updated dependencies [f3ea421]
- Updated dependencies [353a37d]
- Updated dependencies [7a3c96a]
  - @oaath/protocol@0.2.0

## 0.1.0

### Minor Changes

- Publish the first public OAAth proof-of-concept release: runtime-neutral protocol
  contracts, the Kernel v4 browser SDK, the relay/PostgreSQL server, and
  deterministic test support.

### Patch Changes

- Updated dependencies
  - @oaath/protocol@0.1.0
