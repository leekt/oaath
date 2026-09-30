# @oaath/server

## 0.3.1

### Patch Changes

- cfe6f19: Kernel `0.3.3` ECDSA-owned accounts can be derived and activated without
  ZeroDev's SDK. `deriveKernelAccount({ deployment, owner, accountIndex })`
  returns the account address and the EntryPoint 0.7 `factory` / `factoryData`
  of ZeroDev's MetaFactory route, byte for byte what ZeroDev's
  `createKernelAccount` derives. `bindKernelAccount({ chainId, reads, deployment,
owner, accountIndex })` and an owner runtime's `bindAccount({ accountIndex })`
  bind that account: a deployed one exactly as an existing account, a
  counterfactual one only after the pinned factory and MetaFactory code and the
  factory approval are proven. Its first prepared operation carries the
  MetaFactory deployment.
- 8f6b0e7: A session runtime now checks every call against the exact CallPolicy payload it installs, and refuses a call the chain would reject (an unnamed target or selector, a partial selector, or native value above the permission's limit) with the new `kernel_runtime_call_forbidden` code before any key is asked to sign. `prepareOperation`, `signOperation`, and `encodeVerifiedSignature` all refuse; client calls map the code to `oaath_client_scope_denied`.
- 6db1c58: Support sponsored Kernel 0.4.0 revocation consent in the iOS owner phone, with locally verified paymaster fields and shared relay digest fixtures.
- Updated dependencies [6597aab]
- Updated dependencies [c07566c]
- Updated dependencies [cfe6f19]
- Updated dependencies [91cf5fb]
- Updated dependencies [08d4350]
- Updated dependencies [0adee13]
- Updated dependencies [6aa26c3]
- Updated dependencies [0d7c164]
- Updated dependencies [a229ab4]
- Updated dependencies [8f6b0e7]
- Updated dependencies [7084540]
- Updated dependencies [ff14e39]
- Updated dependencies [0fc7149]
- Updated dependencies [b8d8ae7]
- Updated dependencies [849c519]
- Updated dependencies [9baf4bc]
- Updated dependencies [e838a47]
- Updated dependencies [250e66a]
  - @oaath/sdk@0.3.1
  - @oaath/protocol@0.3.1

## 0.3.0

### Minor Changes

- 990b316: Key the Operation journal per caller-reserved lane. `oaath.operation/v4` records
  name their `lane` (`null` for the default lane, or an exact `{ id, key }`
  execution lane), and `OperationStoreKey` gains an optional `lane` key. Each
  (Grant, chain, kind, lane) slot keeps its own current record, archive and
  one-unresolved-Operation rule; a record never lands under another lane's key.
  No public API sends on a non-default lane yet.

  Breaking persisted-state change: `oaath.operation/v3` records and
  `oaath.operation-store-record/v2` envelopes are rejected without migration.
  IndexedDB schema 15 recreates older local state. PostgreSQL uses new
  `oaath_operation_lane_v2` and `oaath_operation_archive_v2` tables, and the
  SQLite test store uses schema `oaath.sqlite-test-store/v3`; recreate them.

- bb6ecf0: `OperationStore.list(scope)` returns the current record of every lane in one
  (Grant, chain, kind) scope, including the default lane. It fails closed when a
  listed record belongs to another scope, repeats a lane, or is malformed.

  Breaking advanced API change: `OperationStoreAdapter` requires
  `list(scope)`, and `OperationStoreScope` is exported. The memory, IndexedDB,
  PostgreSQL and SQLite test adapters implement it. Custom adapters must return
  every current lane record for the exact scope.

- 7213d87: Preserve closed bundler pre-acceptance rejection evidence across relay submission
  errors so URL-only Grant clients can use the connected EOA fallback. One protocol
  owner captures the allowlisted numeric code; the relay forwards no provider prose
  or raw data. Only the submission endpoint can authorize this fallback. Generic
  HTTP failures, unknown codes and malformed evidence remain observation-only.
- 14150b9: Report ABI-proven AA23 empty validation reverts with a closed likely-out-of-gas
  diagnostic and the requested verification gas limit. Preserve that hint through
  direct and relayed preparation, sponsorship, provider errors and uncertain
  submission outcomes without retaining raw provider errors or enabling retries.
  Forward configured enable gas floors through service bootstrap.
  Keep the paymaster's public service identity canonical while retaining the exact
  configured transport endpoint.
- 71769bc: The native projection is `oaath.native-projection/v7`. Permission scopes carry
  `perChainOperationIntervalSeconds`, which is null for a lifetime cap. Phone
  consent shows "Up to N operations per chain per <interval>" and a refill fact.
  Windowed requests are no longer refused. The phone rejects v6 projections.

### Patch Changes

- 5f20fc4: Add a distinct existing-account identity profile for Kernel 0.3.3, binding its
  address and ECDSA owner without a factory index. Permission request hashes,
  Grant identity comparisons, and browser bindings include the existing address.
  Phone approval and enrollment remain scoped to their supported v4 profiles.
  High-level v3.3 Grant execution is still pending its runtime integration.
- 4a4c984: Breaking: `@oaath/sdk/kernel` exports no `Phone` names. Where the owner key
  lives is expressed by who signs, not by the function name.

  - `prepareKernelPhonePermissionApproval` becomes `prepareKernelPermissionApproval`.
    Its preparation gains `sign(ownerKey, decidedAt)`, which takes the one owner
    signature from a key profile. `complete(artifact, decidedAt)` still accepts
    an owner device's signing artifact. `KernelPhonePermissionArtifact` becomes
    `KernelPermissionDecision`. A request this preparation does not support (a
    Kernel `0.3.3` or existing account, or a non-P-256 owner) now fails with
    `kernel_runtime_unsupported` before any signing.
  - `prepareKernelPhoneRevocation` and `restoreKernelPhoneRevocation` are
    deleted. `prepareKernelPermissionRevocation` now prepares a Kernel `0.4.0`
    owner revocation when given the optional `request` and `effect` settings,
    instead of failing with `kernel_runtime_unsupported`.
    `restoreKernelPermissionRevocation({ preparation })` accepts that
    revocation's `signingRequest`, and `reads` is required only for a recorded
    Kernel `0.3.3` preparation. Every preparation offers `sign(ownerKey)`; the
    Kernel `0.4.0` kind also offers `complete(artifact)` for an owner device.
  - The `@oaath/server/kernel` revocation executor restores through
    `restoreKernelPermissionRevocation`.

  No wire or persisted artifact version changes.

- f17694a: Breaking: the existing-account profile is now
  `oaath.kernel-existing-account-profile/v2`. It admits any supported deployment,
  with a `kernelVersion` of `"0.3.3"` or `"0.4.0"` detected from the account. `v1`
  profiles are rejected and must be recreated. `KernelV33AccountProfile` becomes
  `KernelExistingAccountProfile`, and `isKernelExistingAccountProfile` tells it
  apart from a derived profile.

  Local mode now accepts an existing Kernel v4 account. It detects the
  account's deployment on every configured chain, and chains that disagree fail
  with `local_account_deployment_mismatch`. The wallet approval uses the selected
  deployment's approval artifact.

- f08038a: Expose the phone's non-secret match code to requesting applications through the authorization request response and requestPermission's onPending callback.
- 6291c3c: Breaking: no `@oaath/protocol` export names a Kernel version, and
  `check:public-surface` now bans `V33`/`V4` export names on every published
  `@oaath/protocol`, `@oaath/server` and `@oaath/testing` entry as well as
  `@oaath/sdk`. Wire and persisted version strings are unchanged.

  - `KERNEL_INSTALL_COMPONENTS`, `parseKernelInstallPackages`,
    `createKernelReplayableInstallTypedData` and
    `parseKernelReplayableInstallOwnerSigningRequest` replace their `KernelV4`
    forms.
  - The types `KernelModuleType`, `KernelReplayableInstallPackage`,
    `KernelReplayableInstallTypedData`, `KernelReplayableInstallTypedDataInput`
    and `KernelReplayableInstallOwnerSigningRequest` replace their `KernelV4`
    forms.
  - `KernelDerivedAccountProfile` replaces `KernelV4AccountProfile`, the derived
    counterpart of `KernelExistingAccountProfile`.

- be3b095: Breaking: the `@oaath/protocol` Kernel revocation exports no longer name a
  Kernel version. The signing request's own `version` discriminant
  (`oaath.kernel-revocation-signing-request/v1`, unchanged) carries the version.

  - `OAATH_KERNEL_REVOCATION_SIGNING_REQUEST_VERSION` replaces
    `OAATH_KERNEL_V4_REVOCATION_SIGNING_REQUEST_VERSION`.
  - `parseKernelRevocationSigningRequest` and `hashKernelRevocationSigningRequest`
    replace their `KernelV4` forms.
  - `encodeKernelInstallNonceInvalidationCall` and
    `encodeKernelPermissionUninstallCalls` replace their `KernelV4` forms.
  - The types `KernelRevocationEffect`, `KernelRevocationOperation` and
    `KernelRevocationSigningRequest` replace their `KernelV4` forms.

- c37834a: Grant policies can refill their per-chain operation limit once per fixed window.
  `requestPermission` accepts `perChainOperationLimit: { count, intervalSeconds }`
  alongside a bare lifetime count. The canonical policy is now
  `oaath.grant-policy/v2` and always carries
  `perChainOperationLimit: { count, intervalSeconds }`, with `null` as the only
  lifetime representation; v1 policies, requests and Grants are rejected. The
  interval is part of the policy hash.

  Approval may lower the count but must keep the requested window exactly. A
  shorter window refills sooner and widens authority. A longer window, or a
  lifetime cap for a windowed request, is rejected as the issue specifies.

  A windowed limit installs the pinned fixed-window rate-limit policy in place of
  the lifetime count cap. Usage evidence reads that module at the finalized block
  and reports a refill only once finalized chain time reaches the window end. A
  reverted operation still consumes its slot. `OaathUsageRequest` carries
  `intervalSeconds`. Phone consent refuses windowed requests until the native
  projection can display the window.

- Updated dependencies [e3cbd75]
- Updated dependencies [1d78c79]
- Updated dependencies [16951ae]
- Updated dependencies [40d1712]
- Updated dependencies [190be5c]
- Updated dependencies [1d78c79]
- Updated dependencies [9d95b6c]
- Updated dependencies [6f317e1]
- Updated dependencies [48569de]
- Updated dependencies [e7982a6]
- Updated dependencies [e71ae7c]
- Updated dependencies [5f20fc4]
- Updated dependencies [e342540]
- Updated dependencies [257390f]
- Updated dependencies [ad0dcab]
- Updated dependencies [19f8f19]
- Updated dependencies [7f39057]
- Updated dependencies [e1f0c9f]
- Updated dependencies [dfbb17c]
- Updated dependencies [84593a9]
- Updated dependencies [023c505]
- Updated dependencies [1957183]
- Updated dependencies [4a4c984]
- Updated dependencies [c907cac]
- Updated dependencies [650577c]
- Updated dependencies [1d78c79]
- Updated dependencies [4661b21]
- Updated dependencies [887bb87]
- Updated dependencies [5091579]
- Updated dependencies [bdf3360]
- Updated dependencies [1d78c79]
- Updated dependencies [1d78c79]
- Updated dependencies [f17694a]
- Updated dependencies [1d78c79]
- Updated dependencies [db63ded]
- Updated dependencies [87af134]
- Updated dependencies [1d78c79]
- Updated dependencies [a6b6cdb]
- Updated dependencies [01a8d8c]
- Updated dependencies [80c56fb]
- Updated dependencies [990b316]
- Updated dependencies [bb6ecf0]
- Updated dependencies [2331dd8]
- Updated dependencies [672b133]
- Updated dependencies [3feaadc]
- Updated dependencies [1d78c79]
- Updated dependencies [7a6afe1]
- Updated dependencies [f08038a]
- Updated dependencies [6271afc]
- Updated dependencies [46e0d88]
- Updated dependencies [9a5be93]
- Updated dependencies [6291c3c]
- Updated dependencies [be3b095]
- Updated dependencies [1d78c79]
- Updated dependencies [1d78c79]
- Updated dependencies [1d78c79]
- Updated dependencies [7213d87]
- Updated dependencies [17db987]
- Updated dependencies [366e92f]
- Updated dependencies [1d78c79]
- Updated dependencies [5cf6a39]
- Updated dependencies [f855156]
- Updated dependencies [73f14ca]
- Updated dependencies [79a163f]
- Updated dependencies [3458e4a]
- Updated dependencies [28e0b56]
- Updated dependencies [14150b9]
- Updated dependencies [05d7f9a]
- Updated dependencies [83f5010]
- Updated dependencies [09fe1c8]
- Updated dependencies [c37834a]
  - @oaath/sdk@0.3.0
  - @oaath/protocol@0.3.0

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
