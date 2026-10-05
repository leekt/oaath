# @oaath/protocol

## 0.3.4

### Patch Changes

- 62e7e73: Pin Kernel v4 to upstream PR #152 at c960b42d2ed4adb0d5328f6e762962debdf8e57a,
  with reproducible runtime artifacts and new CREATE2 addresses bound to EntryPoint
  0.7. Update validator and signer install data for the scoped-hook contract:
  remove the inline hook argument, reject module type 4, and accept type 11 in the
  shared and native approval parsers. Remove per-chain implementation hash pins;
  all chains use canonical CREATE2 code presence and exact factory/account
  implementation bindings. Chain-independent factory and module hashes remain checked.

  Prior v4 deployments and grants require fresh setup. The existing Kernel 0.3.3
  profile remains supported. No public deployment or OAAth audit is claimed.

## 0.3.3

### Patch Changes

- 760fdd2: Accept and normalize valid EIP-55 addresses in public UserOperation references. Reject invalid checksums with a specific structured error before observation reads; persisted operation records remain canonical.

## 0.3.2

### Patch Changes

- 94116ac: Own shared UserOperation failure classification and wire capture in the protocol package so relay roots retain their SDK-free dependency boundary.

## 0.3.1

### Patch Changes

- c07566c: ECDSA owner and operator credential profiles (and existing Kernel account addresses) now accept a valid EIP-55 checksummed address and capture it in canonical lowercase, so canonical encodings and hashes match the lowercase spelling. Mixed-case addresses with an invalid checksum are still rejected.
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
- 0fc7149: `prepareKernelPermissionRevocation` accepts an optional caller-supplied EntryPoint 0.7
  `paymaster` (`address`, `verificationGasLimit`, `postOpGasLimit`, `data`) for Kernel `0.3.3`
  and `0.4.0`; it defaults to `null` (self-funded) and is part of the hashed operation identity.
  The Kernel `0.3.3` record is now `oaath.kernel-permission-revocation/v2` with a top-level
  `paymaster`; `v1` records are rejected and must be prepared again. The Kernel `0.4.0`
  revocation signing request accepts a packed `paymasterAndData`, and restore reproduces the
  exact sponsored operation.

## 0.3.0

### Minor Changes

- 5f20fc4: Add a distinct existing-account identity profile for Kernel 0.3.3, binding its
  address and ECDSA owner without a factory index. Permission request hashes,
  Grant identity comparisons, and browser bindings include the existing address.
  Phone approval and enrollment remain scoped to their supported v4 profiles.
  High-level v3.3 Grant execution is still pending its runtime integration.
- 84593a9: Breaking: `@oaath/protocol` renames `KernelV4Install` to `KernelInstall`. The
  SDK's shared Kernel shapes (`KernelCall`, `KernelInstall`,
  `KernelUserOperationGas`, `KernelValidation`, `KernelValidityTimeRange`) are
  now the owner types themselves instead of aliases of version-named shapes.
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

- 2331dd8: Send independent jobs on caller-reserved lanes:
  `grant.sendCalls({ chain, calls, lane: { id, nonceKey } })`. Each lane keeps
  its own journal, its own "never resubmit on timeout" rule, and its own single
  unresolved operation. `grant.getOperation({ chain, id, lane })` recovers the
  exact operation on that lane. Lanes are never allocated for the caller; the
  default lane is unchanged.

  - A lane key must be one the runtime can represent (Kernel: 1 to 65535).
    Anything else fails with `oaath_client_input_invalid`.
  - A lane is refused with `oaath_client_state_conflict` and source
    `operation_lane_permission_not_installed` until the permission is observed
    installed on that chain. Only the default lane enables on first use, so two
    lanes never race the install.
  - `revoke()` leaves the Grant `revoking` while any execution lane on a target
    chain is unresolved or unreadable. Observe that operation to a terminal
    state, then call `revoke()` again.

  Breaking advanced API change: `OaathQuoteRequest` carries `nonceKey`. Custom
  quote ports must quote exactly that namespace and return it unchanged.
  `createLocalAnvilFixture` accepts a test-only `submission` interposer.
  `parseOperationLane` is exported from `@oaath/protocol`.

- 3feaadc: The owner key is an optional setting in owner and wallet-approved modes.

  - `account(address).owner(owner)` and `approvals: { kind: "wallet", owner }`
    take a connected viem wallet (the ECDSA default, unchanged) or any
    `kernelKey(...)` signing profile, such as a raw P-256 key. A wallet approves a
    Grant with one typed-data prompt; a key profile signs the same approval digest.
    New types: `OaathOwnerKey` and `OaathApprovalOwner`.
  - The existing-account profile is `oaath.kernel-existing-account-profile/v3`. It
    admits an ECDSA owner, or a raw P-256 owner on Kernel `0.4.0`. The `v2`
    profile has no reader; recreate stored bindings and Grants.
  - A WebAuthn owner key fails with `oaath_client_capability_unsupported`
    (`source: "owner_key_kind_unsupported"`) before it signs, because no WebAuthn
    root validator is pinned.
  - `createLocalOwnerAnvilFixture({ kernelVersion: "0.4.0", owner: "p256" })`
    roots the fixture account in a raw P-256 `ownerKey`.

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

- 1d78c79: Expose an exact immutable UserOperation reference codec and a read-only observer
  for applications that own their operation journals. The observer shares OAAth's
  receipt, transaction, canonical block and finality verification, including saved
  direct transaction hints. It neither creates Grants or Operations nor signs,
  submits, checks replacements, or authorizes a retry. Pending and unreadable
  evidence keep the saved identity unresolved.
- 7213d87: Preserve closed bundler pre-acceptance rejection evidence across relay submission
  errors so URL-only Grant clients can use the connected EOA fallback. One protocol
  owner captures the allowlisted numeric code; the relay forwards no provider prose
  or raw data. Only the submission endpoint can authorize this fallback. Generic
  HTTP failures, unknown codes and malformed evidence remain observation-only.
- 17db987: Retain the acknowledged submission route and direct transaction hash in operation
  records, and expose a matching route from finalized `operation.execution()`.
  Acknowledgement never authorizes resubmission or proves inclusion. Custom adapters
  can omit route evidence when it is unknown; default viem ports report bundler
  acknowledgements.

  Operation records advance to `oaath.operation/v3`, rejecting older records.
  IndexedDB schema 14 recreates older local state without migration, deleting
  retained keys, Grants, and operation history. Reconnect and authorize fresh
  permissions; resetting local storage does not revoke onchain authority.

- 73f14ca: Submission evidence names its route by the route kind a chain configures:
  `{ route: "erc4337-bundler", transactionHash: null }` or
  `{ route: "erc4337-handleops", transactionHash }`. The protocol exports the
  `OperationSubmissionRoute` type, and `OaathSubmissionRouteKind` is that type.
  `OaathOperationExecution.route` reports the same values.

  Breaking change: Operation records move to `oaath.operation/v5` and IndexedDB
  schema 16. Older records are rejected; browser state is wiped and recreated
  without migration. Custom submission sessions must return the new route values.

- 14150b9: Report ABI-proven AA23 empty validation reverts with a closed likely-out-of-gas
  diagnostic and the requested verification gas limit. Preserve that hint through
  direct and relayed preparation, sponsorship, provider errors and uncertain
  submission outcomes without retaining raw provider errors or enabling retries.
  Forward configured enable gas floors through service bootstrap.
  Keep the paymaster's public service identity canonical while retaining the exact
  configured transport endpoint.
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
