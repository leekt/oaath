/**
 * Capability diagnosis for the Kernel v4 axes: can one supported chain carry one
 * credential or policy capability at all? Facts come from the same pinned module
 * registry createKernelRuntime resolves through, so a capability can never read
 * `available` while the composition factory fails closed on the same axis.
 *
 * Diagnosis is local and total: it reads no chain, so no fact depends on
 * provider evidence. `absent` and `unreadable` therefore never occur here; they
 * stay in the closed status vocabulary for the evidence-derived facts owned by
 * per-chain routing, where a missing installation and an unreadable provider are
 * distinct outcomes.
 *
 * The module-existence question carries no per-chain dimension: every pinned
 * module address is chain-independent, so the registry is consulted without a
 * chain. The chain enters one way only, through deployment support — an
 * unsupported chain fails in kernelV4Deployment before any axis is diagnosed.
 *
 * A P-256 or WebAuthn credential is never downgraded: an unbound validator or
 * signer axis is reported unsupported and composed as a structured failure, never
 * as unrelated ECDSA authority.
 *
 * A consumer-authored kind carries caller-bound evidence on both axes and widens
 * no registry: its modules are the ones its own KeyProfile binds, proven to carry
 * code on the action chain when an account binds.
 *
 * All-chain materialization deliberately adds no axis here. It installs exactly
 * the packages the session's own credential and policy axes already resolve, and
 * its authority is Kernel's own replayable enable mode rather than a module — so
 * there is nothing extra whose deployment could be absent. A chain that supports
 * a session's axes supports materializing that session on it, and an unsupported
 * chain already fails in kernelV4Deployment.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type KernelV4SupportedChainId, kernelV4Deployment } from "../kernel-v4.js";
import { exactInput, inputInvalid, isBuiltInKeyKind } from "./internal.js";
import { pinnedPolicyModule, pinnedSignerModule, pinnedValidatorModule } from "./modules.js";
import type {
  KernelBuiltInKeyKind,
  KernelKeyKind,
  KernelOperatorAuthority,
  KernelPolicyProfile,
} from "./types.js";

/**
 * One owner credential, session credential, or policy hook axis. Every
 * consumer-authored kind shares the `owner_custom` and `session_custom` axes:
 * the fact they carry is that the SDK pins no module for such a kind and accepts
 * caller-bound evidence for one, which is identical for every custom kind.
 */
export type KernelCapability =
  | "owner_ecdsa"
  | "owner_p256"
  | "owner_webauthn"
  | "owner_custom"
  | "session_ecdsa"
  | "session_webauthn"
  | "session_custom"
  | "hook_call"
  | "hook_expiry"
  | "hook_operation_limit";

export type KernelCapabilityStatus = "available" | "absent" | "unsupported" | "unreadable";

/** Why an available capability is available; a consumer never infers it from prose. */
export type KernelCapabilityEvidence =
  | "caller_bound_validator"
  | "caller_bound_signer"
  | "pinned_reviewed_module";

export type KernelCapabilityReason =
  | "validator_module_deployment_unproven"
  | "signer_module_deployment_unproven"
  | "policy_module_deployment_unproven";

export type KernelCapabilityFact =
  | Readonly<{
      status: "available";
      capability: KernelCapability;
      chainId: KernelV4SupportedChainId;
      evidence: KernelCapabilityEvidence;
    }>
  | Readonly<{
      status: Exclude<KernelCapabilityStatus, "available">;
      capability: KernelCapability;
      chainId: KernelV4SupportedChainId;
      reason: KernelCapabilityReason;
    }>;

export interface DiagnoseKernelCapabilityInput {
  readonly chainId: number;
  readonly capability: KernelCapability;
}

type CapabilityOutcome =
  | Readonly<{ status: "available"; evidence: KernelCapabilityEvidence }>
  | Readonly<{
      status: Exclude<KernelCapabilityStatus, "available">;
      reason: KernelCapabilityReason;
    }>;

/**
 * The axis one capability resolves through: an owner capability needs a validator
 * module for its key kind, a session capability needs a permission signer module
 * for it, and a policy capability needs the module enforcing that policy axis.
 */
type CapabilityAxis = Readonly<
  | { capability: KernelCapability; axis: "validator" | "signer"; kind: KernelBuiltInKeyKind }
  | { capability: KernelCapability; axis: "policy"; kind: KernelPolicyProfile["kind"] }
  | { capability: KernelCapability; axis: "caller-bound"; evidence: KernelCapabilityEvidence }
>;

/**
 * Captures the requested capability into its axis. Every KernelCapability member
 * appears exactly once; an unknown or non-string capability fails closed.
 */
function capturedCapability(value: unknown): CapabilityAxis {
  switch (value) {
    case "owner_ecdsa":
      return Object.freeze({
        capability: value,
        axis: "validator" as const,
        kind: "ecdsa" as const,
      });
    case "owner_p256":
      return Object.freeze({
        capability: value,
        axis: "validator" as const,
        kind: "p256" as const,
      });
    case "owner_webauthn":
      return Object.freeze({
        capability: value,
        axis: "validator" as const,
        kind: "webauthn" as const,
      });
    // A consumer-authored kind resolves no pinned module on either axis, so both
    // its axes are satisfied by caller-bound evidence: the validator and signer
    // module addresses its KeyProfile binds, each code-proven on the action chain
    // before an account or permission depends on it. The pinned registry stays
    // exactly as narrow as the modules this SDK has reviewed.
    case "owner_custom":
      return Object.freeze({
        capability: value,
        axis: "caller-bound" as const,
        evidence: "caller_bound_validator" as const,
      });
    case "session_custom":
      return Object.freeze({
        capability: value,
        axis: "caller-bound" as const,
        evidence: "caller_bound_signer" as const,
      });
    // A session is a permission, so its credential axis is the signer module,
    // never a validator that would carry whole-key authority.
    case "session_ecdsa":
      return Object.freeze({ capability: value, axis: "signer" as const, kind: "ecdsa" as const });
    case "session_webauthn":
      return Object.freeze({
        capability: value,
        axis: "signer" as const,
        kind: "webauthn" as const,
      });
    // Value ceilings are enforced per permitted call inside CallPolicy, so
    // hook_call is the whole call-and-value axis; no separate value hook exists.
    case "hook_call":
      return Object.freeze({ capability: value, axis: "policy" as const, kind: "call" as const });
    case "hook_expiry":
      return Object.freeze({ capability: value, axis: "policy" as const, kind: "expiry" as const });
    case "hook_operation_limit":
      return Object.freeze({
        capability: value,
        axis: "policy" as const,
        kind: "operation-limit" as const,
      });
    default:
      return inputInvalid("Kernel capability is unsupported");
  }
}

function validatorOutcome(kind: KernelBuiltInKeyKind): CapabilityOutcome {
  // ECDSA carries no pinned entry by design: kernel/key/ecdsa.ts binds the
  // caller's validator module and bindKernelV4Account proves that module has
  // code on the action chain before any account address depends on it.
  if (kind === "ecdsa") {
    return Object.freeze({ status: "available" as const, evidence: "caller_bound_validator" });
  }
  return pinnedValidatorModule(kind)
    ? Object.freeze({ status: "available" as const, evidence: "pinned_reviewed_module" })
    : Object.freeze({
        status: "unsupported" as const,
        reason: "validator_module_deployment_unproven",
      });
}

function signerOutcome(kind: KernelBuiltInKeyKind): CapabilityOutcome {
  return pinnedSignerModule(kind)
    ? Object.freeze({ status: "available" as const, evidence: "pinned_reviewed_module" })
    : Object.freeze({
        status: "unsupported" as const,
        reason: "signer_module_deployment_unproven",
      });
}

function policyOutcome(kind: KernelPolicyProfile["kind"]): CapabilityOutcome {
  return pinnedPolicyModule(kind)
    ? Object.freeze({ status: "available" as const, evidence: "pinned_reviewed_module" })
    : Object.freeze({
        status: "unsupported" as const,
        reason: "policy_module_deployment_unproven",
      });
}

function axisOutcome(captured: CapabilityAxis): CapabilityOutcome {
  if (captured.axis === "caller-bound") {
    return Object.freeze({ status: "available" as const, evidence: captured.evidence });
  }
  if (captured.axis === "policy") return policyOutcome(captured.kind);
  if (captured.axis === "signer") return signerOutcome(captured.kind);
  return validatorOutcome(captured.kind);
}

/**
 * The capability one composition stands for. A consumer-authored kind maps to the
 * shared custom axis, so a caller never assembles a capability name from an
 * unbounded kind string.
 */
export function kernelKeyCapability(
  authority: KernelOperatorAuthority,
  kind: KernelKeyKind,
): KernelCapability {
  if (authority === "owner") {
    return isBuiltInKeyKind(kind) ? `owner_${kind}` : "owner_custom";
  }
  if (kind === "p256") {
    return inputInvalid("raw P-256 session credentials are unsupported");
  }
  return isBuiltInKeyKind(kind) ? `session_${kind}` : "session_custom";
}

/** Diagnoses one capability on one supported chain into one frozen fact. */
export function diagnoseKernelCapability(
  value: DiagnoseKernelCapabilityInput,
): KernelCapabilityFact {
  const record = exactInput(
    value,
    ["chainId", "capability"],
    "Kernel capability diagnosis",
    new WeakSet(),
  );
  // kernelV4Deployment owns the chain fact, so an unsupported or non-canonical
  // chain fails here with the same code the composition factory raises. It is the
  // only place the chain enters: the module registry below is chain-independent.
  const deployment = kernelV4Deployment(record.chainId);
  const captured = capturedCapability(record.capability);
  return Object.freeze({
    capability: captured.capability,
    chainId: deployment.chainId,
    ...axisOutcome(captured),
  });
}
