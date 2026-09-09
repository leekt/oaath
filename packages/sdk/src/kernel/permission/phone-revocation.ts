/**
 * Public credentials and a retained approval -> exact owner-phone revocation.
 * Preparation and completion never submit or claim that revocation finished.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  hashKernelV4RevocationSigningRequest,
  hashPermissionRequest,
  type KernelV4RevocationEffect,
  type KernelV4RevocationSigningRequest,
  OAATH_KERNEL_V4_REVOCATION_SIGNING_REQUEST_VERSION,
  OAATH_OWNER_SIGNING_REQUEST_VERSION,
  type OwnerSigningArtifact,
  type PermissionRequest,
  parseKernelV4RevocationSigningRequest,
  parseOwnerSigningArtifact,
  parsePermissionRequest,
} from "@oaath/protocol";
import {
  toPackedUserOperation,
  toUserOperation,
  type UserOperation,
} from "viem/account-abstraction";
import {
  encodeKernelV4InstallNonceInvalidationCall,
  encodeKernelV4PermissionUninstallCalls,
  type KernelV4AccountReadCapability,
  type KernelV4UserOperationGas,
  kernelV4Deployment,
  kernelV4ReplayableInstallTypedData,
} from "../../kernel-v4.js";
import {
  asViemUserOperation,
  OAATH_PREPARED_USER_OPERATION_VERSION,
  type PreparedUserOperation,
  parsePreparedUserOperation,
} from "../../prepared-user-operation.js";
import { createKernelRuntime } from "../create-kernel-runtime.js";
import { exactInput, inputInvalid, runtimeFail, sameInstall } from "../internal.js";
import { credentialKey } from "../key/credential.js";
import { p256Key } from "../key/p256.js";
import { ownerOperator } from "../operator/owner.js";
import { sessionOperator } from "../operator/session.js";
import { kernelPermissionInstallNonce } from "./install-nonce.js";
import { type KernelAllChainApproval, parseKernelAllChainApproval } from "./materialize.js";
import { deriveSessionPolicyProfiles } from "./profiles.js";

export interface PrepareKernelPhoneRevocationInput {
  readonly request: Readonly<PermissionRequest>;
  readonly approval: Readonly<KernelAllChainApproval>;
  readonly chainId: number;
  readonly reads: Readonly<KernelV4AccountReadCapability>;
  /** Chosen from chain evidence: invalidate an unused install, or remove an installed permission. */
  readonly effect: KernelV4RevocationEffect;
  readonly nonceKey: string;
  readonly sequence: string;
  readonly gas: Readonly<KernelV4UserOperationGas>;
}

export interface PreparedKernelPhoneRevocation {
  readonly signingRequest: Readonly<KernelV4RevocationSigningRequest>;
  readonly prepared: Readonly<PreparedUserOperation>;
  /** Verifies and returns the exact root signature; no submission or finality effect. */
  complete(artifact: Readonly<OwnerSigningArtifact>): Promise<`0x${string}`>;
}

/**
 * Prepares one self-funded P-256 owner operation from the canonical phone grant.
 * The orchestrator supplies the chain evidence, root operation nonce and gas,
 * and retains this exact request before asking the phone. Expired application
 * permissions may still be revoked; current owner consent has its own lifetime.
 */
export async function prepareKernelPhoneRevocation(
  value: PrepareKernelPhoneRevocationInput,
): Promise<Readonly<PreparedKernelPhoneRevocation>> {
  const input = exactInput(
    value,
    ["request", "approval", "chainId", "reads", "effect", "nonceKey", "sequence", "gas"],
    "phone revocation",
    new WeakSet(),
  );
  const request = parsePermissionRequest(input.request);
  const approval = parseKernelAllChainApproval(input.approval);
  const ownerCredential = request.logicalAccount.ownerCredential;
  if (ownerCredential.kind !== "p256" || request.logicalAccount.factoryRoute !== "kernel_factory")
    return inputInvalid("phone revocation requires the P-256 Kernel owner");
  if (
    typeof input.chainId !== "number" ||
    (input.effect !== "invalidate-install" && input.effect !== "uninstall-permission")
  )
    return inputInvalid("phone revocation chain or effect is invalid");
  if (approval.installNonce !== kernelPermissionInstallNonce(hashPermissionRequest(request)))
    return inputInvalid("phone revocation approval belongs to another request");
  const deployment = kernelV4Deployment(input.chainId);
  const reads = input.reads as KernelV4AccountReadCapability;
  const key = p256Key({
    credential: ownerCredential,
    sign: async () =>
      runtimeFail(
        "kernel_runtime_signing_failed",
        "phone revocation preparation has no owner signer",
      ),
  });
  const owner = createKernelRuntime({ deployment, operator: ownerOperator({ key }), reads });
  const session = createKernelRuntime({
    deployment,
    operator: sessionOperator({
      key: credentialKey({ credential: request.operatorCredential, validator: null }),
      policies: deriveSessionPolicyProfiles(request.policy),
    }),
    reads,
  });
  if (
    approval.packages.length !== session.packages.length ||
    !approval.packages.every((entry, index) => {
      const expected = session.packages[index];
      return expected !== undefined && sameInstall(entry, expected);
    })
  )
    return inputInvalid("phone revocation approval does not bind the requested permission");
  if (!(await key.verify(approval.digest, approval.enableSignature)))
    return runtimeFail(
      "kernel_runtime_signature_invalid",
      "phone revocation approval has no valid owner signature",
    );
  const account = await owner.bindAccount({
    accountIndex: request.logicalAccount.accountIndex,
    initialPackages: owner.packages,
  });
  if (account.account !== approval.account)
    return inputInvalid("phone revocation account contradicts its approval");
  const calls =
    input.effect === "invalidate-install"
      ? [
          encodeKernelV4InstallNonceInvalidationCall({
            account: account.account,
            installNonce: approval.installNonce,
          }),
        ]
      : encodeKernelV4PermissionUninstallCalls({
          account: account.account,
          packages: approval.packages,
        });
  const prepared = owner.prepareOperation({
    kind: "revocation",
    grantId: request.requestId,
    account,
    nonceKey: input.nonceKey as string,
    sequence: input.sequence as string,
    calls,
    gas: input.gas as KernelV4UserOperationGas,
  });
  const packed = toPackedUserOperation(asViemUserOperation(prepared.userOperation));
  const signingRequest = parseKernelV4RevocationSigningRequest({
    version: OAATH_KERNEL_V4_REVOCATION_SIGNING_REQUEST_VERSION,
    kind: "kernel-revocation",
    permissionRequest: request,
    install: {
      version: OAATH_OWNER_SIGNING_REQUEST_VERSION,
      kind: "eip712",
      purpose: "kernel-enable",
      signer: { account: account.account, ownerCredential },
      typedData: kernelV4ReplayableInstallTypedData({
        account: account.account,
        nonce: approval.installNonce,
        packages: approval.packages,
      }),
      expectedDigest: approval.digest,
      replay: { nonce: approval.installNonce, deadline: null },
    },
    effect: input.effect,
    chainId: prepared.chainId,
    entryPoint: prepared.entryPoint.address,
    operation: {
      sender: packed.sender.toLowerCase(),
      nonce: packed.nonce.toString(10),
      initCode: packed.initCode,
      callData: packed.callData,
      accountGasLimits: packed.accountGasLimits,
      preVerificationGas: packed.preVerificationGas.toString(10),
      gasFees: packed.gasFees,
      paymasterAndData: packed.paymasterAndData,
    },
    expectedDigest: prepared.userOperationHash,
  });
  return restoredRevocation(signingRequest, prepared, owner);
}

/**
 * Reconstructs a previously admitted immutable phone request without chain
 * reads, gas quotes, nonce allocation or account preparation. In particular,
 * factory bytes remain present even if the account deployed after consent.
 * This does not admit a grant or prove that a submission happened.
 */
export function restoreKernelPhoneRevocation(
  value: unknown,
): Readonly<PreparedKernelPhoneRevocation> {
  const signingRequest = parseKernelV4RevocationSigningRequest(value);
  const credential = signingRequest.install.signer.ownerCredential;
  if (credential.kind !== "p256") return inputInvalid("phone revocation requires P-256");
  const owner = createKernelRuntime({
    deployment: kernelV4Deployment(signingRequest.chainId),
    operator: ownerOperator({
      key: p256Key({
        credential,
        sign: async () =>
          runtimeFail("kernel_runtime_signing_failed", "restored phone request has no signer"),
      }),
    }),
    reads: {
      read: async () =>
        runtimeFail("kernel_runtime_binding_mismatch", "restoration must not read the chain"),
    },
  });
  const operation = toUserOperation({
    ...signingRequest.operation,
    nonce: BigInt(signingRequest.operation.nonce),
    preVerificationGas: BigInt(signingRequest.operation.preVerificationGas),
    signature: "0x",
  }) as unknown as UserOperation<"0.7">;
  const prepared = parsePreparedUserOperation({
    version: OAATH_PREPARED_USER_OPERATION_VERSION,
    kind: "revocation",
    grantId: signingRequest.permissionRequest.requestId,
    chainId: signingRequest.chainId,
    entryPoint: { version: "0.7", address: signingRequest.entryPoint },
    userOperation: {
      sender: operation.sender,
      nonce: operation.nonce.toString(10),
      callData: operation.callData,
      callGasLimit: operation.callGasLimit.toString(10),
      verificationGasLimit: operation.verificationGasLimit.toString(10),
      preVerificationGas: operation.preVerificationGas.toString(10),
      maxFeePerGas: operation.maxFeePerGas.toString(10),
      maxPriorityFeePerGas: operation.maxPriorityFeePerGas.toString(10),
      factory: operation.factory
        ? { address: operation.factory, data: operation.factoryData }
        : null,
      paymaster: null,
    },
    userOperationHash: signingRequest.expectedDigest,
  });
  if (prepared.entryPoint.address !== owner.deployment.entryPoint.address)
    return inputInvalid("restored revocation has an unsupported EntryPoint");
  return restoredRevocation(signingRequest, prepared, owner);
}
function restoredRevocation(
  signingRequest: Readonly<KernelV4RevocationSigningRequest>,
  prepared: Readonly<PreparedUserOperation>,
  owner: ReturnType<typeof createKernelRuntime>,
): Readonly<PreparedKernelPhoneRevocation> {
  const requestHash = hashKernelV4RevocationSigningRequest(signingRequest);
  return Object.freeze({
    signingRequest,
    prepared,
    async complete(value: Readonly<OwnerSigningArtifact>) {
      const artifact = parseOwnerSigningArtifact(value);
      if (artifact.requestHash !== requestHash)
        return runtimeFail(
          "kernel_runtime_signature_invalid",
          "phone artifact belongs to another revocation request",
        );
      return owner.encodeVerifiedSignature(prepared, artifact.signature);
    },
  });
}
