/**
 * Canonical permission request -> Kernel signing request -> grant artifact.
 * The service prepares from public credentials; the owner phone supplies the
 * one P-256 signature. No signer, submission, or durable state is retained here.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type ApprovePermissionDecision,
  hashOwnerSigningRequest,
  hashPermissionRequest,
  type KernelV4ReplayableInstallOwnerSigningRequest,
  OAATH_OWNER_SIGNING_REQUEST_VERSION,
  OAATH_PERMISSION_DECISION_VERSION,
  type OwnerSigningArtifact,
  type PermissionRequest,
  parseKernelV4ReplayableInstallOwnerSigningRequest,
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
import { exactInput, inputInvalid, inputUint, runtimeFail } from "../internal.js";
import { credentialKey } from "../key/credential.js";
import { p256Key } from "../key/p256.js";
import { ownerOperator } from "../operator/owner.js";
import { sessionOperator } from "../operator/session.js";
import {
  approveKernelPermissionAllChain,
  type KernelAllChainApproval,
  kernelAllChainCapabilityHash,
} from "./materialize.js";
import { deriveSessionPolicyProfiles } from "./profiles.js";

export interface PrepareKernelPhonePermissionApprovalInput {
  readonly request: Readonly<PermissionRequest>;
  /** Configured chain used to bind the account; the resulting approval is replayable. */
  readonly chainId: number;
  readonly reads: Readonly<KernelV4AccountReadCapability>;
  /** Deployment-owned install nonce. This helper does not allocate or advance it. */
  readonly installNonce: string;
}

/** The existing decision and separately owned install approval consumed by createOAAth. */
export interface KernelPhonePermissionArtifact extends ApprovePermissionDecision {
  readonly installApproval: Readonly<KernelAllChainApproval>;
}

export interface PreparedKernelPhonePermissionApproval {
  readonly request: Readonly<PermissionRequest>;
  readonly signingRequest: Readonly<KernelV4ReplayableInstallOwnerSigningRequest>;
  /** Verifies the phone artifact and assembles a decision; it submits nothing. */
  complete(
    artifact: Readonly<OwnerSigningArtifact>,
    decidedAt: number,
  ): Promise<Readonly<KernelPhonePermissionArtifact>>;
}

/**
 * Prepares the existing phone's P-256 Kernel approval from one captured request.
 * Account and permission packages come from createKernelRuntime; the phone
 * never needs an application session key, and preparation cannot sign.
 * Recreate with the same request and nonce to obtain the same signing request.
 */
export async function prepareKernelPhonePermissionApproval(
  value: PrepareKernelPhonePermissionApprovalInput,
): Promise<Readonly<PreparedKernelPhonePermissionApproval>> {
  const input = exactInput(
    value,
    ["request", "chainId", "reads", "installNonce"],
    "phone permission approval",
    new WeakSet(),
  );
  const request = parsePermissionRequest(input.request);
  const ownerCredential = request.logicalAccount.ownerCredential;
  if (ownerCredential.kind !== "p256")
    return inputInvalid("phone permission approval requires a P-256 owner");
  if (request.logicalAccount.factoryRoute !== "kernel_factory") {
    return inputInvalid("Kernel v4 phone approval requires the Kernel factory route");
  }
  if (typeof input.chainId !== "number") return inputInvalid("phone approval chain is invalid");
  const deployment = kernelV4Deployment(input.chainId);
  const reads = input.reads as Readonly<KernelV4AccountReadCapability>;
  const installNonce = inputUint(
    input.installNonce,
    (1n << 256n) - 1n,
    "phone approval install nonce",
  ).toString(10);
  const ownerRuntime = createKernelRuntime({
    deployment,
    operator: ownerOperator({
      key: credentialKey({ credential: ownerCredential, validator: null }),
    }),
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
  const signingRequest = parseKernelV4ReplayableInstallOwnerSigningRequest({
    version: OAATH_OWNER_SIGNING_REQUEST_VERSION,
    kind: "eip712",
    purpose: "kernel-enable",
    signer: { account: descriptor.account, ownerCredential },
    typedData: kernelV4ReplayableInstallTypedData(scope),
    expectedDigest: kernelV4ReplayableInstallDigest(scope),
    replay: { nonce: installNonce, deadline: null },
  });
  const signingRequestHash = hashOwnerSigningRequest(signingRequest);
  const requestHash = hashPermissionRequest(request);

  return Object.freeze({
    request,
    signingRequest,
    async complete(artifactValue: Readonly<OwnerSigningArtifact>, decidedAt: number) {
      if (
        !Number.isSafeInteger(decidedAt) ||
        decidedAt < request.requestedAt ||
        decidedAt >= request.expiresAt ||
        (request.policy.validUntil !== null && decidedAt > request.policy.validUntil)
      ) {
        return inputInvalid("phone approval decision is outside the request or policy lifetime");
      }
      const artifact = parseOwnerSigningArtifact(artifactValue);
      if (artifact.requestHash !== signingRequestHash) {
        return runtimeFail(
          "kernel_runtime_signature_invalid",
          "phone artifact belongs to another Kernel signing request",
        );
      }
      const installApproval = await approveKernelPermissionAllChain({
        owner: p256Key({ credential: ownerCredential, sign: async () => artifact.signature }),
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
    },
  });
}
