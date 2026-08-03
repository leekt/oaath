/**
 * Kernel runtime composition contracts. Credential kind, operator authority,
 * policy hooks, and deployment profile are orthogonal axes: a key implements
 * KeyProfile, an authority implements OperatorProfile, and createKernelRuntime
 * is the only composition entry. Never add one runtime per combination.
 *
 * @author taek <leekt216@gmail.com>
 */
import type {
  KernelV4AccountDescriptor,
  KernelV4AccountReadCapability,
  KernelV4Call,
  KernelV4Deployment,
  KernelV4Install,
  KernelV4UserOperationGas,
  KernelV4Validation,
} from "../kernel-v4.js";
import type { PreparedUserOperation } from "../prepared-user-operation.js";

export type KernelRuntimeErrorCode =
  | "kernel_runtime_input_invalid"
  | "kernel_runtime_validator_unavailable"
  | "kernel_runtime_signer_unavailable"
  | "kernel_runtime_policy_unavailable"
  | "kernel_runtime_signing_failed"
  | "kernel_runtime_signature_invalid"
  | "kernel_runtime_binding_mismatch";

export class OaathKernelRuntimeError extends Error {
  readonly code: KernelRuntimeErrorCode;

  constructor(code: KernelRuntimeErrorCode, message: string) {
    super(message);
    this.name = "OaathKernelRuntimeError";
    this.code = code;
  }
}

export type KernelKeyKind = "ecdsa" | "p256" | "webauthn";
export type KernelOperatorAuthority = "owner" | "session";

/**
 * One credential kind. Owns public material, validator resolution against a
 * deployment profile, signing normalization, and local verification only. It
 * never chooses an authority, a policy, a bundler, or a fallback route.
 */
export interface KeyProfile {
  readonly kind: KernelKeyKind;
  /** Exact ERC-7579 validator moduleData that installs this key. */
  readonly publicMaterial: `0x${string}`;
  /**
   * Resolves the validator module for this key on one deployment. Fails closed
   * with kernel_runtime_validator_unavailable when no reviewed module is bound.
   */
  readonly resolveValidator: (deployment: Readonly<KernelV4Deployment>) => `0x${string}`;
  /** Fixed-width placeholder signature for gas estimation; never authorizes anything. */
  readonly dummySignature: `0x${string}`;
  /** Signs a 32-byte hash and returns normalized Kernel-native signature bytes. */
  readonly sign: (hash: `0x${string}`) => Promise<`0x${string}`>;
  /** Local verification of normalized signature bytes against this key's public material. */
  readonly verify: (hash: `0x${string}`, signature: `0x${string}`) => Promise<boolean>;
}

export interface KernelCallPolicyProfile {
  readonly kind: "call";
  readonly calls: readonly Readonly<{
    readonly target: `0x${string}`;
    readonly selectors: readonly `0x${string}`[];
  }>[];
}

export interface KernelValuePolicyProfile {
  readonly kind: "value";
  /** Canonical decimal uint256 string; the maximum total native value per call. */
  readonly maximumValue: string;
}

export interface KernelExpiryPolicyProfile {
  readonly kind: "expiry";
  /** Canonical decimal uint48 seconds. */
  readonly validAfter: string;
  /** Canonical decimal uint48 seconds. */
  readonly validUntil: string;
}

export interface KernelOperationLimitPolicyProfile {
  readonly kind: "operation-limit";
  /** Canonical decimal uint32 count of permitted operations on one chain. */
  readonly maximumOperations: string;
}

export type KernelPolicyProfile =
  | KernelCallPolicyProfile
  | KernelValuePolicyProfile
  | KernelExpiryPolicyProfile
  | KernelOperationLimitPolicyProfile;

/** One policy module and the exact payload it receives after the permission ID. */
export interface CompiledKernelPolicyPackage {
  readonly module: `0x${string}`;
  readonly policyData: `0x${string}`;
}

/**
 * One compiled permission scope: the policy packages a session installs, in
 * install order, plus the bounds they encode. Every requested axis is present as
 * a package, so nothing a caller asked for is silently unenforced.
 */
export interface CompiledKernelPermissionPolicy {
  readonly packages: readonly Readonly<CompiledKernelPolicyPackage>[];
  readonly calls: KernelCallPolicyProfile["calls"];
  /** Canonical decimal uint256 ceiling applied to every permitted call. */
  readonly maximumValue: string;
  /** Canonical decimal uint48 seconds, or null when no window was requested. */
  readonly validAfter: string | null;
  readonly validUntil: string | null;
  /** Canonical decimal uint32 count, or null when no operation limit was requested. */
  readonly maximumOperations: string | null;
}

/**
 * One authority. Owns validation binding and install packages only, accepts any
 * KeyProfile, and never inspects credential internals.
 */
export interface OperatorProfile {
  readonly authority: KernelOperatorAuthority;
  readonly key: KeyProfile;
  /** Compiled permission policy, or null for an authority that carries no policy. */
  readonly policy: Readonly<CompiledKernelPermissionPolicy> | null;
  /**
   * The module that validates this authority: a validator module for root
   * authority, a permission signer module for a session. Fails closed when no
   * reviewed module is pinned for this key kind.
   */
  readonly resolveAuthorityModule: (deployment: Readonly<KernelV4Deployment>) => `0x${string}`;
  /**
   * Wraps one normalized key signature in this authority's Kernel signature
   * envelope: identity for root, the permission signature envelope for a
   * session, whose policy slices precede the signer slice.
   */
  readonly encodeSignature: (signature: `0x${string}`) => `0x${string}`;
  /** Kernel validation binding used for nonce keys and validation type. */
  readonly resolveValidation: (
    deployment: Readonly<KernelV4Deployment>,
  ) => Readonly<KernelV4Validation>;
  /** ERC-7579 packages this authority requires on the action chain. */
  readonly resolvePackages: (
    deployment: Readonly<KernelV4Deployment>,
  ) => readonly Readonly<KernelV4Install>[];
}

export interface KernelRuntimeBindAccountInput {
  readonly accountIndex: string;
  readonly initialPackages: readonly KernelV4Install[];
}

export interface KernelRuntimePrepareInput {
  readonly kind: "execution" | "revocation";
  readonly grantId: string;
  readonly account: Readonly<KernelV4AccountDescriptor>;
  readonly nonceKey: string;
  readonly sequence: string;
  readonly calls: readonly KernelV4Call[];
  readonly gas: KernelV4UserOperationGas;
}

export interface CreateKernelRuntimeInput {
  readonly deployment: Readonly<KernelV4Deployment>;
  readonly operator: Readonly<OperatorProfile>;
  readonly reads: KernelV4AccountReadCapability;
}

export interface KernelRuntime {
  readonly deployment: Readonly<KernelV4Deployment>;
  readonly authority: KernelOperatorAuthority;
  readonly keyKind: KernelKeyKind;
  /** Validator module for root authority, permission signer module for a session. */
  readonly authorityModule: `0x${string}`;
  readonly validation: Readonly<KernelV4Validation>;
  /** ERC-7579 packages this operator installs, in Kernel install order. */
  readonly packages: readonly Readonly<KernelV4Install>[];
  readonly dummySignature: `0x${string}`;
  readonly bindAccount: (
    input: KernelRuntimeBindAccountInput,
  ) => Promise<Readonly<KernelV4AccountDescriptor>>;
  readonly prepareOperation: (input: KernelRuntimePrepareInput) => PreparedUserOperation;
  readonly signOperation: (prepared: unknown) => Promise<`0x${string}`>;
}
