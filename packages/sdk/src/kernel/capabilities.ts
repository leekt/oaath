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
 * A P-256 or WebAuthn credential is never downgraded: an unbound validator axis
 * is reported unsupported and composed as a structured failure, never as
 * unrelated ECDSA authority.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type KernelV4Deployment,
  type KernelV4SupportedChainId,
  kernelV4Deployment,
} from "../kernel-v4.js";
import { exactInput, inputInvalid } from "./internal.js";
import { pinnedHookModule, pinnedValidatorModule } from "./modules.js";
import type { KernelKeyKind } from "./types.js";

/** One owner credential, session credential, or policy hook axis. */
export type KernelCapability =
  | "owner_ecdsa"
  | "owner_p256"
  | "owner_webauthn"
  | "session_ecdsa"
  | "session_p256"
  | "session_webauthn"
  | "hook_call"
  | "hook_value"
  | "hook_expiry"
  | "hook_operation_limit";

export type KernelCapabilityStatus = "available" | "absent" | "unsupported" | "unreadable";

/** Why an available capability is available; a consumer never infers it from prose. */
export type KernelCapabilityEvidence = "caller_bound_validator" | "pinned_reviewed_module";

export type KernelCapabilityReason =
  | "validator_module_deployment_unproven"
  | "hook_module_deployment_unproven";

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

/** The axis one capability resolves through: one key kind, or the policy hook module. */
type CapabilityAxis = Readonly<{
  capability: KernelCapability;
  axis: KernelKeyKind | "hook";
}>;

/**
 * Captures the requested capability into its axis. Every KernelCapability member
 * appears exactly once; an unknown or non-string capability fails closed.
 */
function capturedCapability(value: unknown): CapabilityAxis {
  switch (value) {
    case "owner_ecdsa":
    case "session_ecdsa":
      return Object.freeze({ capability: value, axis: "ecdsa" as const });
    case "owner_p256":
    case "session_p256":
      return Object.freeze({ capability: value, axis: "p256" as const });
    case "owner_webauthn":
    case "session_webauthn":
      return Object.freeze({ capability: value, axis: "webauthn" as const });
    // Kernel v4 pins one policy hook module per chain, so every policy axis
    // shares that one deployment fact.
    case "hook_call":
    case "hook_value":
    case "hook_expiry":
    case "hook_operation_limit":
      return Object.freeze({ capability: value, axis: "hook" as const });
    default:
      return inputInvalid("Kernel capability is unsupported");
  }
}

function validatorOutcome(
  deployment: Readonly<KernelV4Deployment>,
  kind: KernelKeyKind,
): CapabilityOutcome {
  // ECDSA carries no pinned entry by design: kernel/key/ecdsa.ts binds the
  // caller's validator module and bindKernelV4Account proves that module has
  // code on the action chain before any account address depends on it.
  if (kind === "ecdsa") {
    return Object.freeze({ status: "available" as const, evidence: "caller_bound_validator" });
  }
  return pinnedValidatorModule(deployment, kind)
    ? Object.freeze({ status: "available" as const, evidence: "pinned_reviewed_module" })
    : Object.freeze({
        status: "unsupported" as const,
        reason: "validator_module_deployment_unproven",
      });
}

function hookOutcome(deployment: Readonly<KernelV4Deployment>): CapabilityOutcome {
  return pinnedHookModule(deployment)
    ? Object.freeze({ status: "available" as const, evidence: "pinned_reviewed_module" })
    : Object.freeze({ status: "unsupported" as const, reason: "hook_module_deployment_unproven" });
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
  // chain fails here with the same code the composition factory raises.
  const deployment = kernelV4Deployment(record.chainId);
  const { capability, axis } = capturedCapability(record.capability);
  return Object.freeze({
    capability,
    chainId: deployment.chainId,
    ...(axis === "hook" ? hookOutcome(deployment) : validatorOutcome(deployment, axis)),
  });
}
