# @oaath/testing

## 0.3.4

### Patch Changes

- 62e7e73: Pin Kernel v4 to upstream PR #152 at c960b42d2ed4adb0d5328f6e762962debdf8e57a,
  with reproducible runtime artifacts and new CREATE2 addresses bound to EntryPoint
  0.9. Update validator and signer install data for the scoped-hook contract:
  remove the inline hook argument, reject module type 4, and accept type 11 in the
  shared and native approval parsers. Remove per-chain implementation hash pins;
  all chains use canonical CREATE2 code presence and exact factory/account
  implementation bindings. EntryPoint 0.9 uses EIP-712 operation hashes in both SDK and phone verification; prior EntryPoint 0.7 v4 profiles are rejected. Chain-independent factory and module hashes remain checked.

  Prior v4 deployments and grants require fresh setup. The existing Kernel 0.3.3
  profile remains supported. No public deployment or OAAth audit is claimed.

- Updated dependencies [62e7e73]
  - @oaath/protocol@0.3.4
  - @oaath/sdk@0.3.4
  - @oaath/server@0.3.4

## 0.3.3

### Patch Changes

- Updated dependencies [540788b]
- Updated dependencies [760fdd2]
- Updated dependencies [7d7e196]
- Updated dependencies [c07ce18]
- Updated dependencies [ef7875c]
  - @oaath/sdk@0.3.3
  - @oaath/protocol@0.3.3
  - @oaath/server@0.3.3

## 0.3.2

### Patch Changes

- Updated dependencies [08604f3]
- Updated dependencies [ee3371f]
- Updated dependencies [b990767]
- Updated dependencies [a7f02e6]
- Updated dependencies [a2cf1e0]
- Updated dependencies [94116ac]
- Updated dependencies [d9fd974]
- Updated dependencies [651e58d]
  - @oaath/sdk@0.3.2
  - @oaath/server@0.3.2
  - @oaath/protocol@0.3.2

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
- Updated dependencies [6db1c58]
- Updated dependencies [b8d8ae7]
- Updated dependencies [849c519]
- Updated dependencies [9baf4bc]
- Updated dependencies [e838a47]
- Updated dependencies [250e66a]
  - @oaath/sdk@0.3.1
  - @oaath/protocol@0.3.1
  - @oaath/server@0.3.1

## 0.3.0

### Minor Changes

- 16951ae: The chain `sponsorship` setting also carries ERC-7677:
  `{ kind: "erc7677", url, request, estimate }` replaces
  `OaathChainCapability.paymasterService`, and `OaathRegisteredPaymasterService` is
  removed without an alias. A chain holds at most one sponsorship kind, so a service
  bootstrap chain that advertises both ERC-7677 and an ERC-7902 static commitment
  is rejected with `oaath_client_capability_invalid`. Viem chain ports with
  `paymasterUrl` produce the `erc7677` setting. The per-call `payer` option, routes,
  and the EIP-5792 `paymasterService` wire capability are unchanged.
- 40d1712: `OaathChainCapability` gains one optional `sponsorship` setting
  (`OaathChainSponsorship`), defaulting to none. The ERC-7902 static paymaster
  commitment moves from `staticPaymasterConfigurationHash` to
  `sponsorship: { kind: "erc7902-static", configurationHash }`, where the hash
  still comes from `hashErc7902StaticPaymasterConfiguration`. The old field is
  removed without an alias. `@oaath/sdk/advanced` no longer exports
  `captureErc7902StaticPaymasterConfiguration`, `Erc7902StaticPaymasterConfiguration`,
  `createErc7677SponsorshipCapability`, or `CreateErc7677SponsorshipCapabilityInput`;
  the chain setting and the per-call `payer` own sponsorship selection.
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

- 1d78c79: The public local-chain fixture can now use an existing Kernel v3.3 account on
  each chain, approve one all-chain permission, and recover retained operations
  without credentials. Its explicit recovery descriptor is v2 and carries the
  existing account address. Older fixture descriptors are rejected and recreated.
  Both owner and session fixtures share the same real account deployment.

### Patch Changes

- e3cbd75: Breaking: no `@oaath/sdk` entry exports a name that includes a Kernel version
  (`V33`/`V4`). This now covers `@oaath/sdk/advanced` too, and
  `check:public-surface` enforces it for every published entry.

  - Deployment addresses and code hashes come from `kernelDeployment(...)`
    fields. The `KERNEL_V4_*` constants are removed.
  - `encodeKernelNonceKey({ deployment, ... })` replaces `encodeKernelV4NonceKey`
    and `encodeKernelV33NonceKey`.
  - `kernelOperationSigningHash({ deployment, operation })` replaces
    `kernelV33OperationSigningHash`.
  - The other version-named encoders keep their generic names:
    `encodeKernelNonceRead`, `encodeKernelFactoryImplementationRead`,
    `encodeKernelInstallNonceRead`, `encodeKernelInstallNonceInvalidationCall`
    and `kernelReplayableInstallDigest`.
  - `OAATH_KERNEL_VALIDITY_POLICY` and its code hash replace the
    `OAATH_KERNEL_V4_*` names.
  - `OAATH_KERNEL_PERMISSION_ENABLE_APPROVAL_VERSION` on `@oaath/sdk/kernel`
    replaces `OAATH_KERNEL_V33_APPROVAL_VERSION`.
  - The Kernel v3.3 permission-state helpers and
    `kernelV33PermissionEnableTypedData` become internal.
    `prepareKernelPermissionRevocation`, `verifyKernelPermissionRevocation` and
    `kernelPermissionEnableTypedData` replace them.
  - The CLI and the testing fixtures use the generic forms.

- ae59775: The local Anvil fixture starts its chain clock one second ahead of wall time.
  Anvil's implicit genesis timestamp could leave every block a second behind,
  so a Grant whose validity starts at the current wall-clock second was
  occasionally rejected as not yet due on its first operation.
- 1d78c79: Recover old UserOperation receipts within a fixed RPC request budget. The shared
  observer checks canonical inclusion against the configured RPC's finalized head,
  then rebinds that head by number. It no longer reads every intervening block.
  Missing, inconsistent or insufficient finality stays unresolved and never
  authorizes resubmission. RPC chain evidence is not a local consensus proof.

  Breaking advanced API change: remove the unused `block_by_hash` observation
  request. Custom adapters must answer `canonical_block` by canonical height and
  `finalized_block` with the actual finalized tag. No persisted record shape or
  version changes.

- 190be5c: `OaathChainCapability` describes the submission routes a chain offers as an
  optional, ordered `routes` list (`{ kind: "erc4337-bundler", bundler }`,
  `{ kind: "erc4337-handleops", feePayer }`). It replaces the required `bundler`
  probe and the `feePayer` field. Routing picks the first route that is
  conclusively usable, and only a configured bundler route is ever probed. A
  chain with no routes fails with `oaath_client_route_unavailable` and the
  `route_none_configured` reason. `createViemChainPorts`, service mode and the
  `@oaath/testing` Anvil fixtures fill `routes` in, so normal callers never name a
  transport.

  Breaking advanced API change: custom chain capabilities pass `routes` instead
  of `bundler` and `feePayer`. The relay wire, the selected-route evidence and
  persisted records do not change.

- 257390f: Service approvals accept the same optional `session` setting as wallet approvals:
  `createOAAth({ approvals: { kind: "service", url }, session: { kind: "webauthn", ...webauthnKeyInput } })`. The
  shared type is now `OaathSession` (was `OaathLocalSession`). The owner reviews and
  installs the passkey as the operator credential; no session key is generated or
  stored, and a deployment declaring backend or hosted session custody refuses it
  with `oaath_client_capability_unsupported`. The server and phone consent already
  carry a WebAuthn operator credential unchanged.

  `oaath doctor` reports `passkeySessionsReady` (schema
  `oaath.runtime-readiness/v2`): the WebAuthn signer and P-256 verifier with their
  pinned runtime hashes. It never affects `ready` or the exit code.
  `deploy-runtime` now also deploys both when missing.

  `@oaath/testing`'s `createLocalAnvilFixture` serves `GET /bootstrap` and adds
  `openServiceClient({ session? })`; its owner derives permission packages from the
  reviewed operator credential.

- 19f8f19: Breaking: `@oaath/sdk/kernel` no longer exports the version-named deployment,
  read, bind and prepare entry points or their types. Use the generic entry
  points instead:

  - `kernelDeployment({ chainId, kernelVersion? })` replaces
    `kernelV4Deployment` and `kernelV33Deployment`.
  - `createKernelReads` replaces `createKernelV4Reads` and
    `createKernelV33Reads`.
  - `bindKernelAccount` replaces `bindKernelV4Account`.
  - `prepareKernelUserOperation` replaces `prepareKernelV4UserOperation`.
  - `KernelDeployment`, `KernelReads`, `KernelReadRequest`, `KernelReadClient`
    and `KernelAccountDescriptor` replace the version-named types.

  `createKernelRuntime` returns one `KernelRuntime` type for every deployment.

- 7f39057: Add version-agnostic Kernel account entry points to `@oaath/sdk/kernel`.
  Kernel version and EntryPoint version are optional settings.

  - `kernelDeployment({ chainId, kernelVersion?, entryPoint? })` selects a
    deployment and defaults to Kernel `0.4.0` on EntryPoint `0.7`.
  - `createKernelReads(publicClient)` is one read capability for every supported
    deployment.
  - `bindKernelAccount({ chainId, reads, address })` detects an existing
    account's deployment from its onchain implementation. That includes
    deployed Kernel `0.4.0` accounts, bound by address. Pass `initialPackages`
    and `accountIndex` instead to derive a Kernel `0.4.0` account.
    `kernelAccountDeployment(account)` returns the detected deployment.
  - `prepareKernelUserOperation` prepares for any bound account.
  - `createKernelRuntime` accepts any `KernelDeployment`, and
    `runtime.bindAccount({ address })` binds an existing account of that
    deployment.

  An explicit `deployment` that disagrees with the account fails with
  `kernel_runtime_deployment_mismatch` before any signing. It never switches
  versions.

  Owner mode is no longer Kernel `0.3.3`-only: `review.kernelVersion` reports
  the detected version. The owner operation lane label no longer includes a
  version, so owner operations saved by an earlier release are not recovered.

  Breaking: `bindKernelAccount` no longer takes `version`.
  `@oaath/testing`'s owner fixture accepts `kernelVersion`.

- dfbb17c: Add version-agnostic permission approval entry points to `@oaath/sdk/kernel`.
  Each one uses the session runtime's deployment:

  - `approveKernelPermission({ owner, runtime, account, nonce })`
  - `kernelPermissionNonce({ runtime, account, reads, requestHash })`
  - `kernelPermissionEnableTypedData({ runtime, account, nonce })`
  - `materializeKernelPermission`
  - `parseKernelPermissionApproval`
  - `kernelPermissionCapabilityHash`

  The matching types are `KernelPermissionApproval`, `KernelExpectedPermission`,
  `KernelApprovalMismatchField` and `KernelApprovalMismatchReason`.

  Local mode's approval review and `signTypedData` request are typed as
  `KernelPermissionEnableTypedData`. The review comes from the account's selected
  deployment, not a Kernel `0.3.3` literal.

  Breaking: `approveKernelPermissionAllChain`, `approveKernelV33Permission`,
  `parseKernelAllChainApproval`, `parseKernelV33PermissionApproval`,
  `kernelAllChainCapabilityHash`, `kernelV33CapabilityHash`,
  `kernelPermissionInstallNonce`, `kernelV33PermissionInstallNonce`,
  `kernelV33PermissionEnableTypedData` and `materializeKernelV33Permission` are no
  longer exported from `@oaath/sdk/kernel`. `kernelV33PermissionEnableTypedData`
  moves to `@oaath/sdk/advanced`.

- 023c505: Add `kernelKey({ kind?, ... })`, the one public key constructor on
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

- 1957183: Breaking: `@oaath/sdk` and `@oaath/sdk/kernel` no longer export any symbol
  whose name includes a Kernel version (`V33`/`V4`). Kernel and EntryPoint
  versions are optional settings of their entry points. `check:public-surface`
  enforces this for values and types.

  - These move to `@oaath/sdk/advanced`, because custom deployments, fixtures
    and the CLI need them:
    - the Kernel v4 deployment constants (`KERNEL_V4_*`)
    - `OAATH_KERNEL_V4_VALIDITY_POLICY` and its code hash
    - `OAATH_KERNEL_V33_APPROVAL_VERSION`
    - the nonce and install-nonce encoders
    - `encodeKernelV4FactoryImplementationRead`
    - `kernelV4ReplayableInstallDigest`
    - `kernelV33OperationSigningHash`
    - the Kernel v3.3 permission-state helpers
  - The other version-named encoders and their input types become internal.
  - Generic types replace the shared version-named shapes: `KernelCall`,
    `KernelInstall`, `KernelUserOperationGas`, `KernelValidation` and
    `KernelValidityTimeRange`.

- 1d78c79: Expose the existing local owner fixture RPC handler as `rpcFetch(Request)` so
  browser harnesses can use the ordinary SDK HTTP transport with native browser
  storage. The caller owns loopback hosting and request budgets. Requests to
  unrelated origins, non-POST requests and use after fixture closure are rejected.
- 1d78c79: Allow enough verification gas in the local v3.3 fixture to install a multi-call
  session permission on ordinary EVM chain IDs. The regression executes an owner
  operation, installs a larger permission, then reopens the SDK and reuses it
  without another approval. Production bundler estimation is unchanged.
- db63ded: Wallet-approved Grants accept a caller-supplied passkey session:
  `createOAAth({ chains, account, approvals: { kind: "wallet", owner }, session: { kind: "webauthn", ...webauthnKeyInput } })`.
  Omitting `session` (or `{ kind: "ecdsa" }`) keeps the generated, wrapped ECDSA
  session key. The ECDSA owner approves once; enable-on-first-use, the operation
  journal, `resume()` and `revoke()` are unchanged. No private material is
  persisted for a passkey: the device identity derives from its public credential,
  and the Grant record's operator credential is the only stored session fact.

  The pinned WebAuthn signer verifies with `usePrecompiled = false` through Daimo's
  P256Verifier at `0xc2b78104907f722dabac4c69f826a522b2754de4`, so RIP-7212 does
  not change the path. A WebAuthn session bind now requires that verifier's exact
  runtime code hash and fails closed with `kernel_runtime_signer_unavailable`
  (`oaath_client_capability_unsupported` with wallet approvals) before owner review or any
  signature. The Anvil Kernel stack fixture now deploys the verifier.

- 1d78c79: Add issuer-free local mode for existing Kernel v3.3 accounts with browser or local
  viem wallets. Persist an encrypted session before one typed-data approval, then
  reuse the scoped Grant and recover operations after reopening. The same client
  supports owner execution. Local disconnect revokes installed and unused approvals
  before deleting key custody; close cancels pending authority publication and keeps
  failed resource cleanup retryable.

  Refresh the Grant revision after admitting an unused-approval revocation operation,
  so its finalized evidence commits without a false concurrent-writer conflict.

  Expose fresh chain ports and typed-data wallet signing in the public local owner
  fixture for adopter tests. The fixture uses local Anvil and fixed gas estimates.

- a6b6cdb: `createOAAth` takes one options shape for owner and wallet-approved execution;
  the approval source is the optional `approvals` setting. `mode` is removed with
  no alias.

  - `createOAAth({ mode: "owner", chains, operations })` is now
    `createOAAth({ chains, account?, stores?: { operations } })`. With `account`
    set, `oaath.account(address)` refuses every other address.
  - `createOAAth({ mode: "local", owner, onApproval, account, chains, ... })` is
    now `createOAAth({ chains, account, approvals: { kind: "wallet", owner, onApproval? }, ... })`.
  - The result type follows the options: without `approvals` it is
    `OaathOwnerClient`; wallet approvals return `OaathWalletApprovalClient`.
  - Renamed types: `OaathLocalConfiguration` and `OaathOwnerConfiguration` become
    `OaathWalletOptions` and `OaathOwnerOptions`; `OaathLocalClient`,
    `OaathLocalWallet` and `OaathLocalApprovalReview` become
    `OaathWalletApprovalClient`, `OaathApprovalWallet` and
    `OaathWalletApprovalReview`.

- 01a8d8c: Service-approved Grants join the one `createOAAth` options shape.
  `createOAAth({ url, fetch?, authorization?, origin?, stores?, now?, session? })`
  is now `createOAAth({ approvals: { kind: "service", url?, fetch?, authorization? }, origin?, stores?, now?, session? })`.
  Top-level `url` is removed with no alias. `createOAAth()` no longer defaults to
  the local development service, but `approvals: { kind: "service" }` without a
  `url` still does. The new `OaathServiceOptions` and `OaathServiceApprovals`
  types describe the shape, and service approvals return `Oaath`. The catch-all
  `unknown` overload is gone, so a misspelled option is now a type error. The
  injected `binding` composition is unchanged.
- 1d78c79: Expose `createLocalOwnerAnvilFixture` from `@oaath/testing/anvil` for clean
  consumers of existing Kernel v3.3 owner execution. The fixture uses real local
  contracts and public SDK APIs with browser/local wallets, a bounded bundler
  fixture, and recreated SQLite operation storage. Its gas estimates are fixed
  fixture limits; EntryPoint validation and execution run on Anvil. No hosted
  RPC or bundler is contacted.
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

- 1d78c79: Deploy the pinned WebAuthn signer and resetting rate-limit policy in local Anvil
  fixtures, allowing clean consumers to execute real passkey permission installation
  and revocation with their public SDK approval packages.
- 46e0d88: `createOAAth` accepts plain `chains` descriptors keyed by chain ID, for example
  `{ 143: { publicRpcUrls, bundlerUrl, paymasterUrl?, gas? } }`
  (`OaathChainDescriptor`, the `createViemChainPorts` input), and builds the
  default viem chain ports internally with the default request budget. The quick
  starts no longer import `@oaath/sdk/viem`. An `OaathChainCapability[]`
  (including an explicit `createViemChainPorts(...)` result with custom budget,
  retry, or `fetch` options) is still accepted as the override. An invalid
  descriptor fails with `oaath_client_input_invalid` (source
  `oaath_rpc_config_invalid`). The testing Anvil owner fixture adds
  `chainDescriptors()`, which serves its bundler over loopback HTTP.
- 1d78c79: Grant `reviewCalls` accepts `estimate: true` and reports whether the exact session
  operation was estimated or received a conclusive account-validation rejection.
  The check creates no durable operation, signature or submission. Only a canonical
  EntryPoint account-validation error captured during estimation produces the
  rejection result; provider prose, diagnostics, caller-created errors, timeouts and
  submission failures do not. Default reviews report `not-estimated`.
- 5cf6a39: Breaking: each store backend has one public factory that returns the full
  store set. `@oaath/sdk/persistence` exports
  `openIndexedDbStores({ factory?, name? })`, which returns `{ stores, close }`,
  in place of `openOaathDatabase` and the seven `createIndexedDb*` adapters.
  `@oaath/sdk/testing` exports `createMemoryStores()` in place of the seven
  `createMemory*` adapters. Both are for the injected `binding` composition.
  `createOAAth` options keep naming a backend in `stores`.
- f855156: Breaking: `createOAAth`'s `stores` option names a backend instead of taking
  seven adapters. `{ kind: "indexeddb" }` is the default (optionally with
  `factory` and `name`), and `{ kind: "memory" }` runs tests and non-browser
  development with no per-store wiring. Either backend accepts individual adapter
  overrides, e.g. `{ kind: "memory", operations: postgresJournal }`; the backend
  fills only the stores that are not overridden. Owner-only execution takes the
  same shape and uses only `operations`.

  Memory is never a fallback: service-approved clients no longer drop to memory
  where IndexedDB is missing, and every mode fails with
  `oaath_client_store_unavailable` instead. A memory restart forgets operation
  IDs, and a forgotten operation is never resubmitted.

- 73f14ca: Submission evidence names its route by the route kind a chain configures:
  `{ route: "erc4337-bundler", transactionHash: null }` or
  `{ route: "erc4337-handleops", transactionHash }`. The protocol exports the
  `OperationSubmissionRoute` type, and `OaathSubmissionRouteKind` is that type.
  `OaathOperationExecution.route` reports the same values.

  Breaking change: Operation records move to `oaath.operation/v5` and IndexedDB
  schema 16. Older records are rejected; browser state is wiped and recreated
  without migration. Custom submission sessions must return the new route values.

- 3e62ffb: Adapt the v4 Anvil recovery fixture to the SDK's versioned chain-read interface.
  Unsupported version-specific reads remain unavailable.
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
- Updated dependencies [71769bc]
  - @oaath/sdk@0.3.0
  - @oaath/protocol@0.3.0
  - @oaath/server@0.3.0

## 0.2.0

### Minor Changes

- 399ae1a: Add durable direct-Grant local Anvil fixtures and a read-only recovery client
  that reopens SDK state after OS process loss without credentials or resubmission.
  Receipt discovery now reads actual EntryPoint logs instead of process-local
  transaction lookup. Expose SQLite adapters for SDK composition and bump the
  disposable test database schema to v2; old files must be recreated.

### Patch Changes

- 25335ee: Expose a Node-only `@oaath/testing/anvil` fixture that owns real local Kernel/EntryPoint chains, test authorization, reopenable client storage, and cleanup. External consumers can prove all-chain execution and operation recovery from public packed packages without copying OAAth transports or credentials. Requires the local Anvil executable; never a production dependency.
- Updated dependencies [f185d49]
- Updated dependencies [5205bc7]
- Updated dependencies [ae7b016]
- Updated dependencies [bcf1498]
- Updated dependencies [8720b76]
- Updated dependencies [8ee17d3]
- Updated dependencies [8240e65]
- Updated dependencies [8e69b53]
- Updated dependencies [138440f]
- Updated dependencies [1d3e985]
- Updated dependencies [5fa5e2f]
- Updated dependencies [b090f68]
- Updated dependencies [439f120]
- Updated dependencies [b8b1c94]
- Updated dependencies [f3ea421]
- Updated dependencies [98aebeb]
- Updated dependencies [353a37d]
- Updated dependencies [7a3c96a]
  - @oaath/server@0.2.0
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
  - @oaath/sdk@0.1.0
