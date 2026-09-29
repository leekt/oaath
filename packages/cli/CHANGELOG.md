# oaath

## 0.3.0

### Minor Changes

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
