# @oaath/cli

## 0.3.5

### Patch Changes

- 44878a5: Pin Cetane 0.0.4, including complete Kernel inventory coverage when all installation contexts can be reconciled with confirmed state.
- be78f87: Use the published Cetane 0.0.3 release and remove the local snapshot tarball.
- a43611c: Reset every protocol and SDK wire, profile and record version to `v1`, and rename `service_bootstrap_invalid` to `workspace_account_context_invalid`. Records written under the old versions are rejected; recreate them.
- Updated dependencies [44878a5]
- Updated dependencies [5fbe1fd]
- Updated dependencies [5cde641]
- Updated dependencies [5f2e106]
- Updated dependencies [5996a53]
- Updated dependencies [083cbff]
- Updated dependencies [97881b8]
- Updated dependencies [79edd1b]
- Updated dependencies [1f41810]
- Updated dependencies [37e3124]
- Updated dependencies [40c002d]
- Updated dependencies [cf3db5e]
- Updated dependencies [3dc1c6f]
- Updated dependencies [1d87914]
- Updated dependencies [56a9aeb]
- Updated dependencies [60ef4e1]
- Updated dependencies [81001d1]
- Updated dependencies [c407a2e]
- Updated dependencies [be78f87]
- Updated dependencies [f5fb6fe]
- Updated dependencies [a43611c]
- Updated dependencies [f0dedb6]
- Updated dependencies [59b50c8]
- Updated dependencies [f49022f]
  - @oaath/sdk@0.3.5

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
  - @oaath/sdk@0.3.4

## 0.3.3

### Patch Changes

- ef7875c: Mark ZeroDev CallPolicy, operation-limit policy, ECDSA signer and Daimo P-256 verifier as externally deployed. `prepareRuntimeModuleDeployment` returns null for these modules. The CLI requires their pinned runtimes before deploying OAAth-owned modules.
- Updated dependencies [540788b]
- Updated dependencies [760fdd2]
- Updated dependencies [7d7e196]
- Updated dependencies [c07ce18]
- Updated dependencies [ef7875c]
  - @oaath/sdk@0.3.3

## 0.3.2

### Patch Changes

- ee3371f: Include CallPolicy, the operation-limit policy, and ECDSA signer in runtime readiness. Every row declares deployment support, and all seven modules have pinned SDK deployment transactions shared with the CLI.
- Updated dependencies [08604f3]
- Updated dependencies [ee3371f]
- Updated dependencies [b990767]
- Updated dependencies [a7f02e6]
- Updated dependencies [a2cf1e0]
- Updated dependencies [94116ac]
- Updated dependencies [d9fd974]
- Updated dependencies [651e58d]
  - @oaath/sdk@0.3.2

## 0.3.1

### Patch Changes

- 6597aab: License the OAAth-owned validity policy and its embedded bytecode under Apache-2.0. Declare the CC0 ERC-4337 ABI locally, removing the GPL source import without changing bytecode or deployment addresses.
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
- a229ab4: `@oaath/sdk/kernel` exports `kernelRuntimeReadiness({ chainId, reads })`,
  which reports each OAAth runtime module (WebAuthn signer, RateLimit policy,
  validity policy, P-256 verifier) as `present`, `missing`, `mismatch` (other
  code occupies the address, so deploying cannot fix it) or `unreadable`, and
  `prepareRuntimeModuleDeployment({ chainId, module })`, which returns the exact
  CREATE2 deployer transaction `{ module, address, to, data, value,
expectedRuntimeCodeHash }`. `oaath deploy-runtime` now sends these prepared
  transactions instead of keeping its own copy.
- 8f6b0e7: A session runtime now checks every call against the exact CallPolicy payload it installs, and refuses a call the chain would reject (an unnamed target or selector, a partial selector, or native value above the permission's limit) with the new `kernel_runtime_call_forbidden` code before any key is asked to sign. `prepareOperation`, `signOperation`, and `encodeVerifiedSignature` all refuse; client calls map the code to `oaath_client_scope_denied`.
- Updated dependencies [6597aab]
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

## 0.3.0

### Minor Changes

- First npm release, published as `@oaath/cli` (npm rejects the unscoped `oaath` name). The installed command is still `oaath`: `npx @oaath/cli doctor --chain 143`.
- 0f6afe4: Add `oaath deploy-runtime` with deterministic missing-contract deployment, prerequisite checks, dry-run planning and durable observation-only recovery after an uncertain broadcast.
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

- bb2c7ea: Add a bounded, read-only `oaath doctor` command for the canonical Kernel v4 runtime and session modules. Report missing, mismatched and unreadable deployments separately and verify the factory binding.
- ffe8d00: `doctor` reports and `deploy-runtime` deploys the pinned fixed-window
  RateLimitPolicy (`resettingRateLimitPolicy`). Windowed Grant operation limits
  require it. Its runtime hash is the SDK pin.

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
