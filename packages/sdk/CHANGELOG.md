# @oaath/sdk

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
- 91cf5fb: `@oaath/sdk/kernel` exports `bindKernelPermissionEnable({ runtime, account,
approval })`. It prepares a session's enable-mode first execution without
  signing, and returns a `simulationSignature` for `eth_estimateUserOperationGas`:
  the exact enable envelope around the session key's placeholder. After
  estimating, `signOperation` asks the session key once. The ECDSA placeholder
  signature is now a recoverable low-s signature, so an ECDSA signer module
  reports a signature failure during estimation instead of reverting.
- 08d4350: `createKernelReads` serves an `entry_point_lane_nonce` read (EntryPoint 0.7
  `getNonce(account, key)`), and `@oaath/sdk/advanced` exports
  `readKernelLaneSequence({ account, key, reads })` next to
  `encodeKernelNonceKey`. It returns a nonce lane's next sequence for
  `prepareOperation`. An unreadable result fails with
  `kernel_runtime_read_unavailable`; a result for another key or a malformed one
  fails with `kernel_runtime_evidence_invalid`.
- 0adee13: `@oaath/sdk/kernel` exports `prepareExistingAccountPermissionApproval({
account, owner, operator, chains, requestHash, kernelVersion? })`. For an
  existing Kernel account it binds the account on every given chain, proves the
  owner key is the onchain root owner on each one, and returns the one approval's
  `nonce`, `typedData` and `digest`. It needs no `PermissionRequest`. Chains whose
  effective enable nonces differ fail with the new
  `kernel_runtime_nonce_mismatch` code.
- 6aa26c3: `@oaath/sdk/kernel` exports `kernelPermissionNonceAlignmentCalls({ runtime,
account, reads, nonce })`. It returns the owner calls that raise one chain's
  Kernel 0.3.3 enable nonce for a not-yet-installed permission to a target, so
  one approval covers chains whose nonces differed. The calls install and remove
  a throwaway permission that never validates. They never raise
  `validNonceFrom`, so installed permissions keep working.
- 0d7c164: `readKernelPermissionStatus` on `@oaath/sdk/kernel` reads one approval's
  permission status from plain `KernelReads` (for example `createKernelReads`) at
  a named block, `latest` or `finalized`: `installed`, `approval-replayable`,
  `revoked` or `unreadable`. It classifies with the same owner as
  `verifyKernelPermissionRevocation`. Kernel `0.4.0` presence and install-nonce reads are pinned to one block and
  rebound by hash. The `kernel_v33_permission_state` read accepts an optional
  `blockTag`, which `createKernelReads` forwards to every `eth_call`.
- a229ab4: `@oaath/sdk/kernel` exports `kernelRuntimeReadiness({ chainId, reads })`,
  which reports each OAAth runtime module (WebAuthn signer, RateLimit policy,
  validity policy, P-256 verifier) as `present`, `missing`, `mismatch` (other
  code occupies the address, so deploying cannot fix it) or `unreadable`, and
  `prepareRuntimeModuleDeployment({ chainId, module })`, which returns the exact
  CREATE2 deployer transaction `{ module, address, to, data, value,
expectedRuntimeCodeHash }`. `oaath deploy-runtime` now sends these prepared
  transactions instead of keeping its own copy.
- 8f6b0e7: A session runtime now checks every call against the exact CallPolicy payload it installs, and refuses a call the chain would reject (an unnamed target or selector, a partial selector, or native value above the permission's limit) with the new `kernel_runtime_call_forbidden` code before any key is asked to sign. `prepareOperation`, `signOperation`, and `encodeVerifiedSignature` all refuse; client calls map the code to `oaath_client_scope_denied`.
- 7084540: `@oaath/sdk/kernel` exports `signedKernelPermissionApproval({ runtime, account,
nonce, owner, typedData, signature })`. It assembles a Kernel permission
  approval from an enable typed-data signature taken elsewhere, such as a browser
  wallet's `eth_signTypedData_v4`. The typed data must hash to the permission's
  enable digest (`kernel_runtime_binding_mismatch`), and the signature must
  recover to the owner (`kernel_runtime_signature_invalid`). The approval entry
  points also accept a Kernel 0.3.3 runtime without a cast.
- ff14e39: A failed signing capability (wallet `signMessage`, `account.sign`, P-256, WebAuthn, or a wallet approval prompt) now keeps the wallet's own error as the standard `cause` on the thrown OAAth error, so callers can read an EIP-1193 code such as 4001 without OAAth copying provider text into its message. Error codes are unchanged.
- 0fc7149: `prepareKernelPermissionRevocation` accepts an optional caller-supplied EntryPoint 0.7
  `paymaster` (`address`, `verificationGasLimit`, `postOpGasLimit`, `data`) for Kernel `0.3.3`
  and `0.4.0`; it defaults to `null` (self-funded) and is part of the hashed operation identity.
  The Kernel `0.3.3` record is now `oaath.kernel-permission-revocation/v2` with a top-level
  `paymaster`; `v1` records are rejected and must be prepared again. The Kernel `0.4.0`
  revocation signing request accepts a packed `paymasterAndData`, and restore reproduces the
  exact sponsored operation.
- b8d8ae7: `verifyKernelPermissionApproval` accepts a Kernel v3.3 enable signature over
  the EIP-191 hash of the digest, which is what `kernelKey({ wallet })`
  produces with `personal_sign`, as well as the raw-digest `signTypedData`
  form. These are the two forms Kernel v3.3's ECDSA validator accepts, so the
  offline check agrees with the chain.
- 849c519: Classify Kernel 0.4.0 permissions through plain KernelReads, pinning presence and nonce reads to one block and rejecting changed or contradictory evidence.
- 9baf4bc: `@oaath/sdk/kernel`'s `KernelDeployment`, `KernelRuntime` and
  `CreateKernelRuntimeInput` take an optional Kernel version argument, selected
  by the deployment's own `kernelVersion` discriminant. For example,
  `KernelRuntime<"0.3.3">` names the Kernel 0.3.3 runtime, with its v3.3
  deployment fields, account descriptor and `enable` mode, and needs no cast.
  With no argument, each type still covers either version. No export name
  carries a version.
- e838a47: `kernelKey` WebAuthn input accepts `http://localhost` and `http://*.localhost`
  origins, with an optional port, alongside https. Browsers treat these as secure
  contexts for WebAuthn, so local development and virtual-authenticator suites
  can build and sign an OAAth session.
- 250e66a: `kernelKey` WebAuthn signing input accepts the operator credential profile
  (`oaath.operator-credential-profile/v1`) as well as the owner profile, as the
  public `credential` input already does. The profile's role does not change the
  key's public material or signing.
- Updated dependencies [c07566c]
- Updated dependencies [cfe6f19]
- Updated dependencies [8f6b0e7]
- Updated dependencies [0fc7149]
  - @oaath/protocol@0.3.1

## 0.3.0

### Minor Changes

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

- 1d78c79: Recover old UserOperation receipts within a fixed RPC request budget. The shared
  observer checks canonical inclusion against the configured RPC's finalized head,
  then rebinds that head by number. It no longer reads every intervening block.
  Missing, inconsistent or insufficient finality stays unresolved and never
  authorizes resubmission. RPC chain evidence is not a local consensus proof.

  Breaking advanced API change: remove the unused `block_by_hash` observation
  request. Custom adapters must answer `canonical_block` by canonical height and
  `finalized_block` with the actual finalized tag. No persisted record shape or
  version changes.

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

- 9d95b6c: Add optional `payer: { kind: "connected-eoa", wallet }` to plain Grant and
  owner calls. A conclusive bundler RPC rejection permits one connected-wallet
  EntryPoint `handleOps` transaction containing the same signed UserOperation.
  Review exposes its conditional route and address; acknowledged direct execution
  remains recoverable through public RPC after reload.

  Ambiguous failures, acceptance, late responses after close, and wallet failures
  never retry or trigger another submission. The option cannot be combined with
  sponsorship.

- 6f317e1: The routing decision selects a route kind: `OaathExecutionRoute` is
  `"erc4337-bundler" | "erc4337-handleops" | "none"`, and `decideExecution`
  returns the kind of the route it picked. The submission request, call reviews
  and the connected-EOA fallback review use the same values, so one route has one
  name from chain configuration through retained evidence.

  Breaking change: the `bundler` / `entrypoint-handleops` route literals are
  removed. Custom submission capabilities must read `erc4337-bundler` and
  `erc4337-handleops`.

- 48569de: Add createViemChainPorts for public-RPC account reads, finalized policy usage,
  nonce/fee quotes and observation, with bounded retry/failover. Configure bundler
  and optional paymaster URLs separately. Submissions and sponsorship stages are
  single-attempt; every request shares an explicit finite instance budget.
- e7982a6: Observe acknowledged direct EntryPoint transactions through public RPC after
  reload without a connected wallet or bundler receipt index. A transaction hint
  only locates the exact UserOperation event; the existing observer still verifies
  inclusion and finality. Missing or failed transactions never authorize another
  submission. Receipt and execution projections also use the known inclusion
  transaction instead of requiring a bundler index.
- e71ae7c: Apply a configurable per-chain verification gas floor before signing session-enable operations, defaulting to 2,000,000 on Monad. Expose the applicable floor in execution review and preserve it through ERC-7677 paymaster authorization.
- 5f20fc4: Add a distinct existing-account identity profile for Kernel 0.3.3, binding its
  address and ECDSA owner without a factory index. Permission request hashes,
  Grant identity comparisons, and browser bindings include the existing address.
  Phone approval and enrollment remain scoped to their supported v4 profiles.
  High-level v3.3 Grant execution is still pending its runtime integration.
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

- ad0dcab: `runtime.bindAccount({ address })` proves a raw P-256 root owner on an existing
  Kernel 0.4.0 account. It reads the public key stored in the pinned P-256
  validator and compares it with the key's public material. Any other root
  validator, including WebAuthn, still fails with `kernel_runtime_binding_mismatch`.
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

- e1f0c9f: `@oaath/sdk/advanced` gains version-agnostic forms of its Kernel encoders:

  - `encodeKernelNonceKey({ deployment, mode, validation, nonceKey })` encodes
    the EntryPoint nonce key for the deployment's Kernel version.
  - `kernelOperationSigningHash({ deployment, operation })` returns the digest
    an external signer signs for that Kernel version.
  - `encodeKernelNonceRead`, `encodeKernelFactoryImplementationRead`,
    `encodeKernelInstallNonceRead`, `encodeKernelInstallNonceInvalidationCall`,
    `kernelReplayableInstallDigest`, `OAATH_KERNEL_VALIDITY_POLICY` and
    `OAATH_KERNEL_VALIDITY_POLICY_RUNTIME_CODE_HASH`.

  `kernelDeployment(...)` now includes `entryPoint.runtimeCodeHash` and
  `create2Deployer`. The Kernel `0.4.0` profile also includes
  `factoryRuntimeCodeHash`. `@oaath/sdk/kernel` exports
  `OAATH_KERNEL_PERMISSION_ENABLE_APPROVAL_VERSION`, the version of the Kernel
  `0.3.3` permission-enable approval.

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

- c907cac: Breaking: one Kernel error vocabulary. `OaathKernelV4Error` and the
  `kernel_v4_*` codes are removed. Every Kernel entry point throws
  `OaathKernelRuntimeError`, which gains two codes:
  `kernel_runtime_chain_unsupported` and `kernel_runtime_evidence_invalid`.
  Invalid input now reports `kernel_runtime_input_invalid` and an unavailable read
  reports `kernel_runtime_read_unavailable`, whatever the Kernel version.
- 650577c: Add `prepareKernelPermissionRevocation` and `restoreKernelPermissionRevocation`
  to `@oaath/sdk/kernel`. They split an owner revocation of one Grant approval
  into separate awaited stages that do not depend on the transport. Preparation
  only reads. It returns a JSON-safe, versioned
  (`oaath.kernel-permission-revocation/v1`) record: approval, root owner,
  permission state, canonical teardown calls, lane, gas, and the exact unsigned
  prepared operation with its hash. `sign(owner)` produces one owner signature over
  exactly that operation and never submits. The caller routes the operation and
  signature itself, then observes with `verifyKernelPermissionRevocation`.

  Restoring a record re-derives the calls and operation on the same account. A
  changed approval, state, lane, gas, or hash is rejected before signing, as are
  another owner key and a contradicting `account`, `kernelVersion`, or
  `entryPoint`. Only Kernel v3.3 approvals are implemented. A v4 approval fails
  with the new `kernel_runtime_unsupported` code, and v4 owner revocation remains
  `prepareKernelPhoneRevocation`.

- 1d78c79: Add a `rate-limit` Kernel policy profile for an explicit number of validated
  operations per fixed interval. It composes with call/value bounds, expiry and
  the independent lifetime operation count. The public compiler captures positive
  canonical interval/count values and emits deterministic policy order. Existing
  policy identities stay unchanged when this profile is absent.

  The pinned contract owns the remaining quota and reset time per account and
  permission. Installation starts the first window. The first validation at or
  after its end replenishes the quota and starts a new interval; unused quota
  does not accumulate. A validated operation consumes a slot even when execution
  reverts. A reverted validation transaction rolls back its quota change. Runtime
  recreation reads chain state and does not reset the quota or permit submission
  retries. Existing operation journals and their unresolved-lane rules are unchanged.

  This profile uses a distinct deterministic module deployment; every bind proves
  its exact runtime hash on the action chain. Missing or different code fails with
  `kernel_runtime_policy_unavailable`. No deployment is implied or performed by
  adding the profile. The source, compiler input, licenses and deployment bytes
  are checked in and reproducible with `bun run --filter @oaath/sdk check:rate-limit-artifact`.

  This is the public Kernel composition primitive needed for Orchestra's daily
  cap. Default Grant policy and permission-request schemas are unchanged; their
  application integration remains separate.

- 4661b21: Add `verifyKernelPermissionRevocation` to `@oaath/sdk/kernel`: a stateless,
  read-only check of one issued Kernel v3.3 or v4 Grant approval on one chain. It
  dispatches on `approval.version`, reads through a caller-owned finalized
  observation capability (for example a chain port's `observation`), and returns
  `revoked` with the same `ChainRevocationEvidence` the SDK records, `active`,
  `approval-replayable` (absent, but the enable nonce is unused), or `unreadable`
  for any transport, finality, chain or state failure. It never signs, submits or
  retries.

  The SDK's own Grant revocation now uses the same owner. A v3.3 enable nonce is
  compared as Kernel's uint32 validation nonce; EntryPoint nonce keys, including
  custom uint16 lanes, are never consulted. A v4 install nonce under another
  install key is now `unreadable`, not merely not revoked.

- 887bb87: Execute Grants at existing Kernel v3.3 addresses using versioned all-chain
  approvals. Preserve preparation-before-signing, runtime nonce selection, and
  exact operation recovery across IndexedDB reloads. V3.3 revocation, external
  prepared-call signing, request-time validity attenuation, and phone approval
  remain unsupported.
- 5091579: Revoke installed and unused Kernel v3.3 Grant permissions without global nonce
  invalidation. Require finalized permission absence and consumed enable-approval
  evidence, and recover ambiguous owner submissions after reload without sending
  again. Preserve unrelated installed permissions.
- bdf3360: Bind existing Kernel 0.3.3 accounts and prepare/sign ECDSA owner UserOperations through the shared Kernel runtime without migration or permission installation.
- 1d78c79: Allow `webauthnKey` session authority through `createKernelRuntime` on an existing
  Kernel 0.3.3 account. The ECDSA restriction belongs to root-owner binding; session
  authority uses its independent signer module and existing permission envelope.
  No new runtime, credential format, approval version or operation state is added.

  One owner approval can enable the same passkey permission on multiple chains.
  The enable signature uses Kernel's chain-zero digest; subsequent operations use
  their chain-specific digest. Recreating the runtime and reading the installed
  account does not reinstall authority or reset any nonce. Reusing a consumed
  enable approval, signing the wrong digest and exceeding the call/value scope
  remain rejected by the actual Kernel/EntryPoint path.

  Local two-chain Anvil tests cover ECDSA and WebAuthn sessions, plus public packed
  composition. Browser credential selection and Orchestra's durable application
  grant/execution flow remain separate integration work; this change does not
  claim those paths are complete.

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
- 80c56fb: Plain Grant and owner `sendCalls`/`reviewCalls` take one optional `payer`
  setting in place of separate `feePayer` and `paymasterService` fields:
  `{ kind: "paymaster-service", url, context }` (`OaathPaymasterServicePayer`) or
  `{ kind: "connected-eoa", wallet }` (`OaathConnectedEoaPayer`). Omitting it
  keeps the chain's configured routes. Routing, sponsorship, fallback, and the
  `oaath-calls-review-v1` review contract are unchanged. `OaathPaymasterServiceInput`
  and `OaathConnectedEoaFeePayer` are removed without aliases.
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

- 672b133: Add owner mode to createOAAth for existing ECDSA-root Kernel v3.3 accounts.
  Review and send one UserOperation with a connected wallet, without an issuer,
  Grant, or enable envelope. Reuse the durable Operation journal and exact recovery;
  default IndexedDB prevents another send while the account/chain slot is unresolved.
  Default viem ports now serve v3.3 account reads through the public RPC pool.
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

- 1d78c79: Owner call review now estimates the complete call list, including explicitly
  selected sponsorship, and returns single-operation capacity and gas facts.
  An unavailable or rejected estimate cannot be reported as a successful review.
  Review remains read-only: it does not prompt, sign, submit or reserve an
  operation slot. Submission obtains a fresh quote through the existing journal.
- 7a6afe1: Routing decides over an ordered list of submission routes. `decideExecution`
  and `captureRoutingCapabilities` take `routes` (`erc4337-bundler` with its
  probe classification, `erc4337-handleops` with its fee payer) instead of
  separate `bundler` and `feePayer` facts. The first conclusively usable route
  wins, an unreadable bundler still forbids every later route, and an empty list
  returns `route: "none"` with `route_none_configured`.

  Breaking advanced API change: route reasons are per route
  (`route_available`, `route_absent`, `route_unsupported`, `route_unreadable`,
  each suffixed with `:<route kind>`) and replace the `bundler_*` and
  `fee_payer_*` codes. The selected route in review and execution evidence is
  unchanged. The EntryPoint 0.7 bundler, prefund and handleOps helpers now live
  under `routing/erc4337/`; their exports are unchanged.

- 6271afc: Allow an explicit registered ERC-7677 `payer: { kind: "paymaster-service" }` on plain Grant and owner
  sendCalls. The existing sponsorship owner finalizes gas and paymaster data before
  the operation is journaled or signed. reviewCalls reports the selected service
  without invoking it. Failed sponsorship never falls back to an unsponsored send.
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
- 9a5be93: `prepareKernelPermissionApproval` prepares and signs a request for an existing
  Kernel `0.3.3` or `0.4.0` account whose ECDSA or raw P-256 root owner is proven
  onchain, through the same owner wallet-approved mode uses.

  - `reads` is `KernelReads` (`createKernelReads`), which serves every supported
    deployment.
  - `signingRequest` is typed as the generic `kernel-enable`
    `Eip712OwnerSigningRequest`; a Kernel `0.4.0` request is still the replayable
    install request.
  - `KernelPermissionDecision.installApproval` may be a Kernel `0.3.3` approval;
    branch on its `version`.
  - `complete(artifact)` fails with `kernel_runtime_unsupported` unless the owner
    is P-256.
  - Wallet-approved chains that need different approvals now fail with source
    `kernel_runtime_binding_mismatch` instead of `local_permission_scope_mismatch`
    (still `oaath_client_state_conflict`).

- 1d78c79: Export `credentialKey` from `@oaath/sdk/kernel` for owner approval and public
  session preparation from public credential profiles. The factory validates
  the complete versioned credential and installs byte-identical public material
  to its signing profile. It has no signing capability and never verifies a
  signature as accepted. WebAuthn estimation uses an ABI-valid dummy assertion.

  Applications can derive and verify a passkey permission without pretending to
  own its authenticator. This adds no persisted state, approval or retry behavior.

- 1d78c79: Expose an exact immutable UserOperation reference codec and a read-only observer
  for applications that own their operation journals. The observer shares OAAth's
  receipt, transaction, canonical block and finality verification, including saved
  direct transaction hints. It neither creates Grants or Operations nor signs,
  submits, checks replacements, or authorizes a retry. Pending and unreadable
  evidence keep the saved identity unresolved.
- 1d78c79: Expose the existing Kernel v3.3 permission-state reader, decoder, status and
  revocation-call planner through `@oaath/sdk/kernel`. Custom applications can
  prepare the exact owner operation without duplicating Kernel module encodings.
  Installed authority requires uninstall; unused authority requires atomic install
  and uninstall to consume only that permission's enable nonce. Already absent and
  invalidated authority produces no calls. Other permissions remain usable.

  The caller pins the three permission reads to one canonical block and owns its
  operation journal. Permission absence alone is not revocation proof: its
  effective nonce must also exceed the retained approval's nonce. These exports
  do not submit, retry or imply transaction finality and add no persisted shape.

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

- 366e92f: Session key custody joins the one optional `session` setting:
  `session?: { kind?: "ecdsa" | "webauthn", custody?: "browser" | "application-backend" | "oaath-hosted", ... }`.
  Defaults are unchanged. The injected composition no longer accepts
  `sessionSigner`; remote custody comes only from the service bootstrap, which owns
  it. `custody` is a requirement assertion: a mismatch with the declared custody, a
  passkey under remote custody, or remote custody under wallet approvals fails
  with `oaath_client_capability_unsupported` (source `session_custody_unsupported`)
  before any session key, store, or signer request exists. `OaathSessionCustody`
  is exported. The protocol wire is unchanged.
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

- 79a163f: Supply runtime-owned estimation snapshots and bound account/permission usage
  context to custom chain ports, including relay-forwarded ports.
- 3458e4a: Use Kernel 0.3.3's native replayable enable path so one owner approval authorizes
  the same account, permission and validation nonce across chains. The runtime
  signs enable operations with Kernel's chain-zero digest while preserving the
  actual chain's EntryPoint hash in prepared operations. Installed sessions and
  owners keep normal chain-specific signatures.

  The v3.3 approval artifact is now v2 with chainScope "all"; previous chain-bound
  records are rejected. Export kernelV33OperationSigningHash for external session
  signers. High-level v3.3 Grant integration remains pending.

- 28e0b56: Support ECDSA session permission enable and subsequent execution at existing
  Kernel 0.3.3 addresses through createKernelRuntime. Add versioned all-chain
  approval primitives, effective validation nonce reads, and v3.3 nonce encoding.
  Enable operations apply the configured verification gas floor. The session
  operator now receives the deployment when encoding signatures. High-level
  v3.3 Grant integration remains pending.
- 14150b9: Report ABI-proven AA23 empty validation reverts with a closed likely-out-of-gas
  diagnostic and the requested verification gas limit. Preserve that hint through
  direct and relayed preparation, sponsorship, provider errors and uncertain
  submission outcomes without retaining raw provider errors or enabling retries.
  Forward configured enable gas floors through service bootstrap.
  Keep the paymaster's public service identity canonical while retaining the exact
  configured transport endpoint.
- 05d7f9a: Add `verifyKernelPermissionApproval({ approval, expected })`, a pure offline
  check of a permission approval against the reviewed owner, account, permission
  ID, session key and ordered packages. It dispatches on `approval.version`; only
  Kernel v3.3 approvals with an EOA root owner verify today, and other approval
  kinds return an `unsupported` version mismatch. A well-formed but wrong approval
  returns a typed `{ status: "mismatch", field, reason }`. It makes no RPC call and
  implies nothing about chain readiness or installation.
- 83f5010: Grant and owner call reviews share one versioned contract,
  `OAATH_CALLS_REVIEW_VERSION` (`oaath-calls-review-v1`), exported from the
  package root with `parseOaathCallsReview` and the `OaathCallsReviewContract`
  type. Semantic fields (`signer`, `enforcement`, `validation`,
  `fallback.condition`, `fallback.feePayer`) stay closed enums. Identity fields
  are opaque, bounded strings: `account: { address, implementation }` (for example
  `kernel:0.3.3`), `route` and `fallback.route`. A new Kernel version or transport
  adds identity values without changing the version. The parser rejects any other
  version with `oaath_client_review_version_unsupported`.
  `OaathOperationExecution.route` is an opaque string too.

  Breaking changes: a review's `account` is now `{ address, implementation }`.
  The owner review drops `kernelVersion`, adds `version`, `enforcement` (all
  `none`) and `validation: "estimated"`, and reports
  `capacity: { kind: "single-operation", detail }`. `detail` is transport-specific
  and outside the contract.

- 09fe1c8: Add ecdsaWalletKey for a connected viem wallet. It requests one EIP-191 signature
  over the exact operation digest and verifies the captured owner locally before
  returning the existing Kernel ECDSA envelope. Wallet rejection is never retried.
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

### Patch Changes

- 1d78c79: Remove successfully closed connections from the realm's active set. Disconnect
  can then sign out after short-lived permission/review connections were closed,
  including when no connection remains open. A failed connection close stays
  registered for retry; closing never substitutes for issuer sign-out.
- e342540: Add explicit Grant signer auto selection. Available owner authority executes one atomic UserOperation without enabling a session; public-only owner profiles retain session execution. Reviews distinguish root authority from onchain Grant policy, and both paths retain the same durable execution lane and recovery behavior.
- 84593a9: Breaking: `@oaath/protocol` renames `KernelV4Install` to `KernelInstall`. The
  SDK's shared Kernel shapes (`KernelCall`, `KernelInstall`,
  `KernelUserOperationGas`, `KernelValidation`, `KernelValidityTimeRange`) are
  now the owner types themselves instead of aliases of version-named shapes.
- 1d78c79: Use the upstream local Grant authorization path without an in-process issuer
  transport. Keep the combined owner/session client, local-wallet signing, durable
  custody and retryable cleanup. Add the decoded-policy callback before signing.

  The local SDK configuration now takes `account: address`, matching the current
  upstream API. Remove the earlier account descriptor and local issuer identity;
  unreleased local-mode state must be recreated under the current identity.

- 1d78c79: Support viem local accounts for existing Kernel v3.3 owner signatures and the
  connected-EOA handleOps fallback. Local signing keeps the configured signing
  capability instead of changing it into an RPC account; local fee payment uses
  the wallet's transaction action with the captured account.

  The Operation journal still owns the occupied lane and saved submission. Only
  a conclusive pre-acceptance bundler rejection permits the same signed operation
  to use handleOps once. Pending, unreadable, closed, and ambiguous submissions
  never permit another send. Closing releases runtime resources; recreating the
  client observes the retained operation without a wallet or another signature.

  Local Anvil verifies browser and local owner execution, exact fallback bytes,
  and recovery from a newly opened SQLite store. Unit tests cover local signing
  without RPC signing and reject fallback after ambiguous errors. No live chains
  or hosted bundlers were used.

- 87af134: Add local browser Grants for existing ECDSA-root Kernel v3.3 accounts. Approve once with the connected wallet's typed-data signature, execute with encrypted browser session custody, and recover operations or revocation after reload without a relay. Expose decoded approval policy before the canonical Kernel prompt.
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

- Updated dependencies [5f20fc4]
- Updated dependencies [84593a9]
- Updated dependencies [f17694a]
- Updated dependencies [990b316]
- Updated dependencies [2331dd8]
- Updated dependencies [3feaadc]
- Updated dependencies [6291c3c]
- Updated dependencies [be3b095]
- Updated dependencies [1d78c79]
- Updated dependencies [7213d87]
- Updated dependencies [17db987]
- Updated dependencies [73f14ca]
- Updated dependencies [14150b9]
- Updated dependencies [c37834a]
  - @oaath/protocol@0.3.0

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
