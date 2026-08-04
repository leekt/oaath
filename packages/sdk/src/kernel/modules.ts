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
 * Validator modules (moduleType 1) bound per key kind. Kernel v4 ships no reviewed
 * raw P-256 or WebAuthn validator deployment yet, so both kinds resolve to absent
 * and every composition using them fails closed. ECDSA carries no entry by design:
 * kernel/key/ecdsa.ts binds the caller's validator module and bindKernelV4Account
 * proves it has code before any account address depends on it.
 */
const PINNED_VALIDATORS: Readonly<Partial<Record<KernelBuiltInKeyKind, `0x${string}`>>> =
  Object.freeze({});

/**
 * Permission signer modules (moduleType 6) bound per key kind. Both are reviewed
 * modules from https://github.com/zerodevapp/kernel-7579-plugins at commit
 * 332deed6eeef3d6279cde50aa1d51eff53728bd4, compiled with solc
 * 0.8.30+commit.73712a01 (via-IR, optimizer 20000 runs, EVM prague) and deployed
 * through KERNEL_V4_CREATE2_DEPLOYER with a zero salt, which fixes each address on
 * every chain. test/fixtures/kernel-v4-v0.7-deployments.json carries the exact
 * deployment input, and the local Kernel composition proof deploys it and shows
 * the code landing on the address pinned here.
 *
 * - ecdsa: src/signers/ECDSASigner.sol — onInstall takes the 20-byte signer
 *   address, exactly the public material kernel/key/ecdsa.ts publishes.
 * - webauthn: src/signers/WebAuthnSigner.sol — onInstall decodes
 *   (uint256 pubKeyX, uint256 pubKeyY, bytes32), exactly the public material
 *   kernel/key/webauthn.ts publishes.
 *
 * Raw P-256 carries no entry: the reviewed plugin set ships only the WebAuthn
 * assertion signer, so a raw P-256 permission signer fails closed.
 */
const PINNED_SIGNERS: Readonly<Partial<Record<KernelBuiltInKeyKind, `0x${string}`>>> =
  Object.freeze({
    ecdsa: "0xd4c7dec43e67ffe3dcca0aeb71556123d3194e1d",
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
