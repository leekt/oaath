# @oaath/protocol

## 0.2.0

### Patch Changes

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
- f3ea421: Accept canonical selector-prefixed raw calldata in Grant policy coverage without requiring ABI word alignment. CREATE2 factory salt-plus-bytecode calls can now use a covered session policy. Selector, target, value, validity, usage, and complete constrained argument words remain enforced. Calldata shorter than four bytes remains unsupported by this coverage boundary.
- 353a37d: Add a service-owned directory for personal/team workspaces, application-member
  bindings, accounts, owner-device references, and account selections. Memory and
  PostgreSQL stores use revision-checked document replacement. Bootstrap resolves
  current membership on every request; stale selections confer no access. Reuse
  the protocol's account/owner-validator capture in directory and bootstrap records.
- 7a3c96a: Make bootstrap caller-dependent and add a versioned personal/team workspace and
  account context. Deployments now provide `bootstrap.resolve(caller)`; static
  bootstrap configuration is removed. Local realm and session identities include
  the selected context and complete account profile, so context switching and
  cleanup stay isolated. The bootstrap v4 and local binding/session v2 formats
  replace their predecessors without migration; existing clients must reapprove.

## 0.1.0

### Minor Changes

- Publish the first public OAAth proof-of-concept release: runtime-neutral protocol
  contracts, the Kernel v4 browser SDK, the relay/PostgreSQL server, and
  deterministic test support.
