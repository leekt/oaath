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
import type { PreparedPaymaster, PreparedUserOperation } from "../prepared-user-operation.js";

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

/** The credential kinds this SDK authors, each with its own reviewed modules. */
export type KernelBuiltInKeyKind = "ecdsa" | "p256" | "webauthn";
/**
 * One consumer-authored credential kind, bounded to `custom:` followed by 1 to
 * 32 lowercase alphanumeric or hyphen characters. The prefix is what keeps a
 * consumer profile from claiming a reviewed kind and inheriting its pinned
 * modules: a custom kind resolves no pinned module on any axis, so both its
 * validator and its permission signer module must be caller-bound and are
 * code-proven on the action chain before an account or permission depends on
 * them. The kind string is hashed into a session's permission ID, so two
 * distinct kinds never share a permission.
 */
export type KernelCustomKeyKind = `custom:${string}`;
export type KernelKeyKind = KernelBuiltInKeyKind | KernelCustomKeyKind;
export type KernelOperatorAuthority = "owner" | "session";

/**
 * One credential kind. Owns public material, validator resolution against a
 * deployment profile, signing normalization, and local verification only. It
 * never chooses an authority, a policy, a bundler, or a fallback route.
 *
 * A consumer implements this interface to add a credential kind. The runtime
 * captures every member as a hostile capability and mandates what it can verify
 * locally: a produced signature must verify against this profile's own bound
 * public material before it is ever wrapped in an authority envelope.
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
  /**
   * Caller-bound ERC-7579 permission signer module (moduleType 6) for a
   * consumer-authored kind, or null for a reviewed kind, whose signer module is
   * pinned by kind in kernel/modules.ts. A reviewed kind that carries one is
   * refused: a caller may never select the module a reviewed credential
   * installs.
   *
   * It is a plain address rather than a deployment-taking resolver because a
   * session's permission ID binds the signer module before any deployment is
   * known, which also makes the address chain-independent, exactly like every
   * pinned module. The runtime proves it carries code on the action chain when
   * an account binds.
   */
  readonly signerModule: `0x${string}` | null;
  /** Fixed-width placeholder signature for gas estimation; never authorizes anything. */
  readonly dummySignature: `0x${string}`;
  /** Signs a 32-byte hash and returns normalized Kernel-native signature bytes. */
  readonly sign: (hash: `0x${string}`) => Promise<`0x${string}`>;
  /** Local verification of normalized signature bytes against this key's public material. */
  readonly verify: (hash: `0x${string}`, signature: `0x${string}`) => Promise<boolean>;
}

/**
 * One permitted (target, selector) call carrying its own exact native value
 * ceiling. Value is not an independent policy axis: a global maximum would
 * widen every other call to the largest approved allowance, so each permission
 * compiles the limit the owner reviewed for exactly this call.
 */
export interface KernelCallPolicyPermission {
  readonly target: `0x${string}`;
  readonly selector: `0x${string}`;
  /** Canonical decimal uint256 string; `"0"` permits no native value. */
  readonly valueLimit: string;
}

export interface KernelCallPolicyProfile {
  readonly kind: "call";
  readonly permissions: readonly Readonly<KernelCallPolicyPermission>[];
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
  /** The exact per-call permissions CallPolicy installs, in compile order. */
  readonly permissions: readonly Readonly<KernelCallPolicyPermission>[];
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

/**
 * The two Kernel validation modes a composed runtime can reach. `standard`
 * validates against an already installed validation; `enable-replayable` carries
 * the install inline under one chain-agnostic owner enable signature, which is
 * how an all-chain approval materializes on a chain. Kernel's four remaining
 * modes stay unreachable — see the mode table in kernel-v4.ts for why each one
 * would weaken an invariant rather than add a capability.
 */
export type KernelRuntimeValidationMode = "standard" | "enable-replayable";

export interface KernelRuntimePrepareInput {
  readonly kind: "execution" | "revocation";
  readonly grantId: string;
  readonly account: Readonly<KernelV4AccountDescriptor>;
  readonly nonceKey: string;
  readonly sequence: string;
  readonly calls: readonly KernelV4Call[];
  readonly gas: KernelV4UserOperationGas;
  /**
   * Defaults to `standard`. Only kernel/permission/materialize.ts prepares
   * `enable-replayable`, because only it holds the owner enable signature the
   * resulting operation's signature envelope requires.
   */
  readonly mode?: KernelRuntimeValidationMode;
  /**
   * Optional EntryPoint 0.7 paymaster sponsorship; defaults to null
   * (self-funded). The fields are part of the hashed operation identity.
   */
  readonly paymaster?: Readonly<PreparedPaymaster> | null;
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
  /**
   * This authority's signature over one prepared operation. For an
   * `enable-replayable` operation it is the inner UserOperation signature only:
   * Kernel expects it wrapped in an EnableModeSignature envelope beside the owner
   * approval, and kernel/permission/materialize.ts, which holds that approval, is
   * what wraps it. Submitting the bare signature for an enable-mode operation
   * fails closed in Kernel's validation phase.
   */
  readonly signOperation: (prepared: unknown) => Promise<`0x${string}`>;
  /**
   * Verifies caller-produced normalized key bytes against this runtime's exact
   * prepared operation and bound public material, then applies the same Kernel
   * authority envelope as `signOperation`. It never signs or prepares anything.
   */
  readonly encodeVerifiedSignature: (
    prepared: unknown,
    signature: unknown,
  ) => Promise<`0x${string}`>;
}
