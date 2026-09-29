/**
 * Canonical permission request -> Kernel signing request -> grant artifact.
 * Preparation uses public credentials only. The one owner signature comes from
 * whoever holds the owner key: a key profile through `sign`, or an owner
 * device's signing artifact through `complete`. No signer, submission, or
 * durable state is retained here.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type ApprovePermissionDecision,
  hashOwnerSigningRequest,
  hashPermissionRequest,
  isKernelExistingAccountProfile,
  type KernelReplayableInstallOwnerSigningRequest,
  OAATH_OWNER_SIGNING_REQUEST_VERSION,
  OAATH_PERMISSION_DECISION_VERSION,
  type OwnerSigningArtifact,
  type PermissionRequest,
  parseKernelReplayableInstallOwnerSigningRequest,
  parseOwnerSigningArtifact,
  parsePermissionRequest,
} from "@oaath/protocol";
import {
  type KernelV4AccountReadCapability,
  kernelV4Deployment,
  kernelV4ReplayableInstallDigest,
  kernelV4ReplayableInstallTypedData,
} from "../../kernel-v4.js";
import { createKernelRuntime } from "../create-kernel-runtime.js";
import { captureKeyProfile, exactInput, inputInvalid, runtimeFail } from "../internal.js";
import { credentialKey } from "../key/credential.js";
import { p256Key } from "../key/p256.js";
import { ownerOperator } from "../operator/owner.js";
import { sessionOperator } from "../operator/session.js";
import type { KeyProfile } from "../types.js";
import { kernelPermissionInstallNonce } from "./install-nonce.js";
import {
  approveKernelPermissionAllChain,
  type KernelAllChainApproval,
  kernelAllChainCapabilityHash,
} from "./materialize.js";
import { deriveSessionPolicyProfiles } from "./profiles.js";

export interface PrepareKernelPermissionApprovalInput {
  readonly request: Readonly<PermissionRequest>;
  /** Configured chain used to bind the account; the resulting approval is replayable. */
  readonly chainId: number;
  readonly reads: Readonly<KernelV4AccountReadCapability>;
}

/** The existing decision and separately owned install approval consumed by createOAAth. */
export interface KernelPermissionDecision extends ApprovePermissionDecision {
  readonly installApproval: Readonly<KernelAllChainApproval>;
}

export interface PreparedKernelPermissionApproval {
  readonly request: Readonly<PermissionRequest>;
  /** The exact owner signing request, for an owner device that returns a signing artifact. */
  readonly signingRequest: Readonly<KernelReplayableInstallOwnerSigningRequest>;
  /**
   * Takes the one signature from a key profile for the request's owner
   * credential, wherever that key lives, and assembles a decision. The decision
   * time and owner key are checked before the owner is asked. Submits nothing.
   */
  sign(owner: Readonly<KeyProfile>, decidedAt: number): Promise<Readonly<KernelPermissionDecision>>;
  /** Verifies an owner device's signing artifact and assembles a decision; it submits nothing. */
  complete(
    artifact: Readonly<OwnerSigningArtifact>,
    decidedAt: number,
  ): Promise<Readonly<KernelPermissionDecision>>;
}

/**
 * Prepares the owner's Kernel approval from one captured request. Account and
 * permission packages come from createKernelRuntime; the owner never needs an
 * application session key, and preparation cannot sign.
 * Recreate with the same request to obtain the same signing request. Each
 * request selects its own install key at sequence zero; see
 * kernelPermissionInstallNonce for the account's global-minimum constraint.
 *
 * Supported: a P-256 owner of a Kernel `0.4.0` account derived through the
 * Kernel factory. Any other request (a Kernel `0.3.3` or existing account, or
 * another owner key kind) fails with `kernel_runtime_unsupported` before any
 * signing; local mode approves existing accounts through its own wallet path.
 */
export async function prepareKernelPermissionApproval(
  value: PrepareKernelPermissionApprovalInput,
): Promise<Readonly<PreparedKernelPermissionApproval>> {
  const input = exactInput(
    value,
    ["request", "chainId", "reads"],
    "Kernel permission approval preparation",
    new WeakSet(),
  );
  const request = parsePermissionRequest(input.request);
  const ownerCredential = request.logicalAccount.ownerCredential;
  if (
    ownerCredential.kind !== "p256" ||
    isKernelExistingAccountProfile(request.logicalAccount) ||
    request.logicalAccount.factoryRoute !== "kernel_factory"
  ) {
    return runtimeFail(
      "kernel_runtime_unsupported",
      "Kernel approval preparation requires a P-256 owner of a factory-derived Kernel 0.4.0 account",
    );
  }
  if (typeof input.chainId !== "number") return inputInvalid("approval chain is invalid");
  const deployment = kernelV4Deployment(input.chainId);
  const reads = input.reads as Readonly<KernelV4AccountReadCapability>;
  const requestHash = hashPermissionRequest(request);
  const installNonce = kernelPermissionInstallNonce(requestHash);
  const ownerKey = credentialKey({ credential: ownerCredential, validator: null });
  const ownerRuntime = createKernelRuntime({
    deployment,
    operator: ownerOperator({ key: ownerKey }),
    reads,
  });
  const sessionRuntime = createKernelRuntime({
    deployment,
    operator: sessionOperator({
      key: credentialKey({ credential: request.operatorCredential, validator: null }),
      policies: deriveSessionPolicyProfiles(request.policy),
    }),
    reads,
  });
  const descriptor = await ownerRuntime.bindAccount({
    accountIndex: request.logicalAccount.accountIndex,
    initialPackages: ownerRuntime.packages,
  });
  const scope = Object.freeze({
    account: descriptor.account,
    nonce: installNonce,
    packages: sessionRuntime.packages,
  });
  const signingRequest = parseKernelReplayableInstallOwnerSigningRequest({
    version: OAATH_OWNER_SIGNING_REQUEST_VERSION,
    kind: "eip712",
    purpose: "kernel-enable",
    signer: { account: descriptor.account, ownerCredential },
    typedData: kernelV4ReplayableInstallTypedData(scope),
    expectedDigest: kernelV4ReplayableInstallDigest(scope),
    replay: { nonce: installNonce, deadline: null },
  });
  const signingRequestHash = hashOwnerSigningRequest(signingRequest);

  function requireDecisionTime(decidedAt: number): void {
    if (
      !Number.isSafeInteger(decidedAt) ||
      decidedAt < request.requestedAt ||
      decidedAt >= request.expiresAt ||
      (request.policy.validUntil !== null && decidedAt > request.policy.validUntil)
    ) {
      inputInvalid("approval decision is outside the request or policy lifetime");
    }
  }

  async function decide(owner: Readonly<KeyProfile>, decidedAt: number) {
    const installApproval = await approveKernelPermissionAllChain({
      owner,
      account: descriptor.account,
      installNonce,
      packages: sessionRuntime.packages,
    });
    return Object.freeze({
      version: OAATH_PERMISSION_DECISION_VERSION,
      kind: "approve" as const,
      requestId: request.requestId,
      requestHash,
      decidedAt,
      approvedPolicy: request.policy,
      capabilityHash: kernelAllChainCapabilityHash(installApproval),
      installApproval,
    });
  }

  return Object.freeze({
    request,
    signingRequest,
    async sign(value: Readonly<KeyProfile>, decidedAt: number) {
      requireDecisionTime(decidedAt);
      const owner = captureKeyProfile(value);
      // Refuse another credential before it is prompted.
      if (owner.kind !== ownerKey.kind || owner.publicMaterial !== ownerKey.publicMaterial)
        return runtimeFail(
          "kernel_runtime_binding_mismatch",
          "approval owner key does not match the request's owner credential",
        );
      return decide(owner, decidedAt);
    },
    async complete(artifactValue: Readonly<OwnerSigningArtifact>, decidedAt: number) {
      requireDecisionTime(decidedAt);
      const artifact = parseOwnerSigningArtifact(artifactValue);
      if (artifact.requestHash !== signingRequestHash) {
        return runtimeFail(
          "kernel_runtime_signature_invalid",
          "owner artifact belongs to another Kernel signing request",
        );
      }
      return decide(
        p256Key({ credential: ownerCredential, sign: async () => artifact.signature }),
        decidedAt,
      );
    },
  });
}
