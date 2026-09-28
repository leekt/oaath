# @oaath/server

## 0.2.0

### Patch Changes

- f185d49: Verify grant references against the retained permission approval's policy,
  calls and expiry instead of the originally requested policy. Missing, unbound,
  widened or unreadable approval evidence returns unknown. Verification reads the
  existing sealed artifact without claiming or releasing it, including after
  client claim and restart. Custom RelayTransaction adapters must implement the
  request-indexed artifact read; no stored schema changes.
- 5205bc7: Let the service directory admit permission requests and resolve the registered
  account's owner device. Admission checks current membership, workspace/account
  context, application identity, and the complete account profile. Selection changes
  do not retarget requests; membership removal refuses new requests without changing
  previously admitted routes or revoking existing grants.
- 8ee17d3: Bind the selected workspace/account context into PermissionRequest v2 and its
  approval hash. SDK requests retain their connection's context, and resume rejects
  a stored request from another context. Requests use one current encoding with
  explicit null for frontend session custody. Previous request versions are rejected
  and require fresh authorization; operation evidence is not migrated or deleted.
- 8240e65: Add atomic enrollment of a phone and its P-256 Kernel accounts in a personal or team workspace. Enrollment preserves existing identities and membership and uses the current directory revision for one non-retried write.
- 8e69b53: Add the native v6 revocation consent projection and separate no-code decision
  contract. The phone reviews exact removal operations, checks its paired account
  and configured chain, and signs through the existing consent and retry flow.
  Update relay and phone together; refetch earlier consent. This adds no revocation
  queue, HTTP decision handler, operation submission, or finality claim.
- 1d3e985: Carry the permission request's workspace and account context into owner-phone consent. The Swift app displays the workspace ID, personal/team kind, and account ID. Native projection v5 is required; earlier projection versions must be refetched from a matching relay.
- 98aebeb: Require explicit owner routing when creating authorization requests. Store the
  approving device and its authenticated subject separately from the requesting
  member, and preserve that route through approval and restart. Request records
  and the relay PostgreSQL schema advance to v2 with no old reader or migration.
  Directory admission and phone enrollment remain separate integration work.
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
- Updated dependencies [ae7b016]
- Updated dependencies [bcf1498]
- Updated dependencies [8720b76]
- Updated dependencies [8ee17d3]
- Updated dependencies [138440f]
- Updated dependencies [5fa5e2f]
- Updated dependencies [b090f68]
- Updated dependencies [439f120]
- Updated dependencies [b8b1c94]
- Updated dependencies [f3ea421]
- Updated dependencies [353a37d]
- Updated dependencies [7a3c96a]
  - @oaath/sdk@0.2.0
  - @oaath/protocol@0.2.0

## 0.1.0

### Minor Changes

- Publish the first public OAAth proof-of-concept release: runtime-neutral protocol
  contracts, the Kernel v4 browser SDK, the relay/PostgreSQL server, and
  deterministic test support.

### Patch Changes

- Updated dependencies
  - @oaath/protocol@0.1.0
