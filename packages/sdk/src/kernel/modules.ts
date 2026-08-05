/**
 * Pinned ERC-7579 module deployments for Kernel v4. Contract addresses live here
 * and in kernel-v4.ts only, never duplicated across key, operator, or hook files.
 * An unbound axis fails closed; never add an address that has not been reviewed
 * and proven.
 *
 * Every address here is chain-independent. These modules are deployed through the
 * CREATE2 deployer at KERNEL_V4_CREATE2_DEPLOYER with a zero salt, so one address
 * holds on every supported chain and no module is keyed per chain. Per-chain facts
 * stay where the evidence genuinely differs: the deployment profile's runtime code
 * hashes in kernel-v4.ts (Kernel caches block.chainid in its immutables, so one
 * address carries different runtime code per chain) and the code-presence reads
 * bindKernelV4Account performs on the action chain.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type KernelV4Deployment, kernelV4Deployment } from "../kernel-v4.js";
import { inputInvalid, isBuiltInKeyKind, runtimeFail } from "./internal.js";
import type { KernelBuiltInKeyKind, KernelKeyKind, KernelPolicyProfile } from "./types.js";

/**
 * The reviewed raw P-256 validator (moduleType 1): leekt/P256Validator at commit
 * 8f6a71992e297f2e7caa61df2c6eb0b6d9145d2d, src/P256Validator.sol, compiled with
 * solc 0.8.26+commit.8a97fa7a (optimizer 200 runs, no via-IR) and deployed through
 * KERNEL_V4_CREATE2_DEPLOYER with a zero salt, which fixes this address on every
 * chain. test/fixtures/kernel-v4-v0.7-deployments.json carries the exact
 * deployment input — taken from the module's own Ethereum Sepolia broadcast record,
 * whose creation code a recompile of that source reproduces byte for byte — so both
 * the address and the runtime code hash derive from it offline.
 *
 * Interface, checked against Kernel v4's own IERC7579Modules at the commit the
 * deployment profile pins (zerodevapp/kernel f2a84a332ec5a722e7e95a0d64601905c3c87fe9):
 *
 * - `onInstall(bytes)` decodes `(uint256 x, uint256 y)`, exactly the public
 *   material kernel/key/p256.ts publishes, and rejects an off-curve point.
 * - `validateUserOp(PackedUserOperation, bytes32 userOpHash)` decodes
 *   `(uint256 r, uint256 s)` from `userOp.signature` and verifies it against
 *   `userOpHash` directly, hashing nothing further. That is exactly what
 *   kernel/key/p256.ts signs: the raw 64-byte low-s r‖s over the 32-byte
 *   operation hash, handed to the module unwrapped because root validation
 *   carries no envelope. `_validateUserOpValidator` overwrites `op.signature`
 *   with the stripped signature before the call, so the two encodings meet.
 * - `isValidSignatureWithSender(address, bytes32, bytes)` is present with the
 *   declared shape, so ERC-1271 verification resolves through the same key.
 * - `isModuleType(1)` is true and nothing else is claimed.
 *
 * One interface gap, and why it is not a runtime gap: Kernel v4's IModule also
 * declares `isInitialized(address)`, which this module does not implement. No
 * Kernel v4 core path calls it — ModuleManager and ValidationManager reference it
 * nowhere — so the install and validation flows are unaffected. `onInstall` does
 * revert `AlreadyInitialized` for an account that already registered a key, and
 * ValidationManager requires `onInstall` success, so reinstalling this validator
 * on the same account fails until it is uninstalled.
 *
 * On-chain dependency, and the one fact that is genuinely per chain: the module
 * verifies through OpenZeppelin's `P256.verifyNative`, which staticcalls the
 * RIP-7212 / EIP-7951 precompile at 0x0000000000000000000000000000000000000100 and
 * has no Solidity fallback. It delegates to no verifier contract, so there is
 * nothing extra to vendor or deploy. Its constructor probes the precompile with a
 * known-valid vector and reverts `P256PrecompileNotAvailable()` otherwise, so on a
 * chain without it the pinned address simply cannot carry code — and
 * createKernelRuntime's bindAccount reads that code before any account address
 * depends on the module, failing closed with
 * kernel_runtime_validator_unavailable. The Sepolia deployment receipt in the
 * fixture is therefore also evidence that Ethereum Sepolia carried the precompile.
 * Where a supported chain lacks it, this axis is unavailable in fact even though
 * the registry entry is chain-independent, and no client-side list is kept.
 *
 * WebAuthn carries no entry: the reviewed plugin sets ship no v4 WebAuthn
 * validator, so root WebAuthn authority still fails closed. ECDSA carries no entry
 * by design: kernel/key/ecdsa.ts binds the caller's validator module and
 * bindKernelV4Account proves it has code before any account address depends on it.
 */
const PINNED_VALIDATORS: Readonly<Partial<Record<KernelBuiltInKeyKind, `0x${string}`>>> =
  Object.freeze({
    p256: "0x9906ab44ff795883c5a725687a2705be4118b0f3",
  });

/**
 * Permission signer modules (moduleType 6) bound per key kind and deployed through
 * KERNEL_V4_CREATE2_DEPLOYER with a zero salt, which fixes each address on every
 * chain. test/fixtures/kernel-v4-v0.7-deployments.json carries each exact deployment
 * input, and the local Kernel composition proof deploys it and shows the code
 * landing on the address pinned here.
 *
 * - ecdsa: ZeroDev's verified src/ECDSASigner.sol deployment on Arbitrum Sepolia.
 *   The fixture payload was extracted from creation transaction 0x8e282e...7a197,
 *   derives 0x6a6f...d4ff, and reproduces the deployed runtime code. onInstall takes
 *   the 20-byte signer address, exactly the public material kernel/key/ecdsa.ts
 *   publishes.
 * - webauthn: the reviewed src/signers/WebAuthnSigner.sol from
 *   zerodevapp/kernel-7579-plugins at commit 332deed6eeef3d6279cde50aa1d51eff53728bd4.
 *   onInstall decodes
 *   (uint256 pubKeyX, uint256 pubKeyY, bytes32), exactly the public material
 *   kernel/key/webauthn.ts publishes.
 *
 * Raw P-256 carries no entry: the reviewed plugin set ships only the WebAuthn
 * assertion signer, so a raw P-256 permission signer fails closed. Re-checked on
 * 2026-08-04 against that repository's master at 332deed: src/signers holds
 * ECDSASigner, WeightedECDSASigner and WebAuthnSigner only, and its P256Signer.sol
 * still exists solely on the unmerged branch feat/batch2, which is not reviewed
 * provenance. A raw P-256 owner therefore has root authority through the pinned
 * validator above while a raw P-256 session key does not exist; a session under a
 * P-256 owner uses an ECDSA session key, which is the iPhone flow's shape.
 */
const PINNED_SIGNERS: Readonly<Partial<Record<KernelBuiltInKeyKind, `0x${string}`>>> =
  Object.freeze({
    ecdsa: "0x6a6f069e2a08c2468e7724ab3250cdbfba14d4ff",
    webauthn: "0x8b2df925aa16071fcdf0053768420e242935ac65",
  });

/**
 * ZeroDev's reviewed CallPolicy (moduleType 5), which bounds every permitted
 * (callType, target, selector) triple and the native value each may move.
 * Package `zerodev-kernel-call-policy` 0.0.4, source mirrored at
 * https://github.com/cartesi/erc-4337-devnet
 * (zerodev/kernel-call-policy/0.0.4/src/CallPolicy.sol) together with its exact
 * Kernel v3 dependency sources and build profile (solc 0.8.24+commit.e11b9ed9,
 * via-IR, optimizer 200 runs, EVM paris, bytecode hash and CBOR metadata
 * disabled). Recompiling that source with that profile reproduces the package's
 * own cannon `expected` address bit for bit, so this address is ZeroDev's, not
 * ours. It is deployed through KERNEL_V4_CREATE2_DEPLOYER with a zero salt, so
 * one address holds on every chain.
 *
 * Kernel v4 and v3 declare the identical IPolicy: checkUserOpPolicy(bytes32 id,
 * PackedUserOperation) and PolicyBase.onInstall(bytes32 id ‖ data). The module
 * decodes the outer execute(bytes32,bytes) calldata, which is why permission
 * validations must not wrap their calldata in executeUserOp.
 */
const CALL_POLICY = "0x9a52283276a0ec8740df50bf01b28a80d880eaf2" as const;

/**
 * ZeroDev's reviewed TimestampPolicy (moduleType 5), which returns the ERC-4337
 * packed validAfter/validUntil range EntryPoint enforces, so an expired session
 * is refused on-chain with AA22 rather than by client-side refusal. Package
 * `zerodev-kernel-timestamp-policy` 0.0.1, source mirrored at
 * https://github.com/cartesi/erc-4337-devnet
 * (zerodev/kernel-timestamp-policy/0.0.1/src/TimestampPolicy.sol) with its own
 * vendored Kernel v3 dependencies and build profile (solc 0.8.24+commit.e11b9ed9,
 * via-IR, optimizer 200 runs, EVM paris, bytecode hash and CBOR metadata
 * disabled). Recompiling that source with that profile reproduces the package's
 * own cannon `expected` address bit for bit, so this address is ZeroDev's, not
 * ours. Its PolicyBase.onInstall takes `id ‖ abi.encode(ValidAfter, ValidUntil)`,
 * two uint48 words, which is exactly what permission/compile.ts emits.
 */
const TIMESTAMP_POLICY = "0xb9f8f524be6ecd8c945b1b87f9ae5c192fdce20f" as const;

/**
 * ZeroDev's reviewed RateLimitPolicy (moduleType 5), which caps how many
 * UserOperations one permission may validate on one chain. Package
 * `zerodev-kernel-ratelimit-policy` 0.0.1 (the cannon package name; the mirror
 * directory is kernel-rate-limit-policy), source mirrored at
 * https://github.com/cartesi/erc-4337-devnet
 * (zerodev/kernel-rate-limit-policy/0.0.1/src/RateLimitPolicy.sol) with its own
 * vendored Kernel v3 dependencies and the same build profile, which likewise
 * reproduces the package's cannon `expected` address.
 *
 * onInstall reads `id ‖ interval ‖ count ‖ startAt`, three packed uint48s, and
 * checkUserOpPolicy decrements `count` on every operation it validates, returning
 * 1 — Kernel's signature-failure sentinel — once the count is exhausted. With
 * interval and startAt zero it is a pure count cap that adds no time bound.
 *
 * The mapping from the Grant policy is deliberately conservative: an approved
 * perChainOperationLimit counts finalized operations, while this module counts
 * validated ones, so an operation whose execution reverts still consumes a slot.
 * The on-chain cap is therefore never more permissive than the approved one.
 */
const RATE_LIMIT_POLICY = "0xf63d4139b25c836334edd76641356c6b74c86873" as const;

/**
 * Policy modules bound per policy axis. CallPolicy enforces the call and value
 * axes together, in one module, from one configuration. A session installs one
 * package per distinct module, so a scope spanning several axes installs several
 * policies.
 *
 * All four axes are bound, which took one SDK-side fix. Recorded history, because
 * the failure mode is not obvious from the ABI: a permission carrying two policy
 * packages installed correctly — `validationInfo(vId)` read
 * `policies = [CallPolicy, TimestampPolicy]`, `signer = ECDSASigner`, hook = the
 * no-hook sentinel — yet its first operation was rejected with EntryPoint
 * `FailedOpWithRevert(0, "AA23 reverted", 0x8baa579f)`, Kernel's
 * `InvalidSignature()`, because `ValidationManager._validateUserOpPermission`
 * requires `permissionSignature.signatures.length == vInfo.policies.length + 1`
 * and sessionOperator's encodeSignature emitted a fixed two-slice envelope
 * regardless of how many policy packages resolvePackages installed. The envelope
 * now derives its empty policy slices from the same captured compiled policy that
 * resolvePackages installs from, so the two counts cannot drift again; the local
 * composition proof executes a two-package session, a post-expiry AA22 rejection
 * and an exhausted operation count on-chain.
 */
const PINNED_POLICIES: Readonly<Partial<Record<KernelPolicyProfile["kind"], `0x${string}`>>> =
  Object.freeze({
    call: CALL_POLICY,
    value: CALL_POLICY,
    expiry: TIMESTAMP_POLICY,
    "operation-limit": RATE_LIMIT_POLICY,
  });

/** Accepts only the exact frozen deployment profile owned by kernel-v4.ts. */
export function exactKernelDeployment(value: unknown): Readonly<KernelV4Deployment> {
  let chainId: unknown;
  try {
    chainId = (value as { readonly chainId?: unknown } | null | undefined)?.chainId;
  } catch {
    return inputInvalid("Kernel deployment profile is invalid");
  }
  const deployment = kernelV4Deployment(chainId);
  if (deployment !== value) {
    return inputInvalid("Kernel deployment profile is not the pinned Kernel v4 profile");
  }
  return deployment;
}

/**
 * The reviewed validator module bound to one reviewed key kind, or null when none
 * is. Both the composition factory and capability diagnosis read the registry
 * here, so an unbound axis can never read available on one path and fail on the
 * other.
 *
 * A consumer-authored kind is in neither registry and never reaches this one at
 * all: it binds its own validator through its KeyProfile, and the runtime proves
 * that module carries code on the action chain.
 */
export function pinnedValidatorModule(kind: KernelBuiltInKeyKind): `0x${string}` | null {
  return PINNED_VALIDATORS[kind] ?? null;
}

/**
 * The reviewed permission signer module bound to one key kind, or null when none
 * is. A consumer-authored kind resolves null here by construction, which is what
 * makes a session refuse to compose unless its own profile bound a signer module.
 */
export function pinnedSignerModule(kind: KernelKeyKind): `0x${string}` | null {
  return (isBuiltInKeyKind(kind) ? PINNED_SIGNERS[kind] : null) ?? null;
}

/** The reviewed policy module bound to one policy axis, or null when none is. */
export function pinnedPolicyModule(kind: KernelPolicyProfile["kind"]): `0x${string}` | null {
  return PINNED_POLICIES[kind] ?? null;
}

/** Resolves the reviewed validator module for one reviewed key kind, or fails closed. */
export function resolvePinnedValidator(kind: KernelBuiltInKeyKind): `0x${string}` {
  return (
    pinnedValidatorModule(kind) ??
    runtimeFail(
      "kernel_runtime_validator_unavailable",
      `Kernel v4 has no reviewed ${kind} validator module deployment`,
    )
  );
}

/** Resolves the reviewed permission signer module for one key kind, or fails closed. */
export function resolvePinnedSigner(kind: KernelKeyKind): `0x${string}` {
  return (
    pinnedSignerModule(kind) ??
    runtimeFail(
      "kernel_runtime_signer_unavailable",
      `Kernel v4 has no reviewed ${kind} permission signer module deployment`,
    )
  );
}

/** Resolves the reviewed policy module enforcing one policy axis, or fails closed. */
export function resolvePolicyModule(kind: KernelPolicyProfile["kind"]): `0x${string}` {
  return (
    pinnedPolicyModule(kind) ??
    runtimeFail(
      "kernel_runtime_policy_unavailable",
      `Kernel v4 has no reviewed ${kind} policy module deployment`,
    )
  );
}
