/**
 * Kernel 0.4.0 owner revocation: public credentials and a retained approval ->
 * one exact root operation. Preparation and signing never submit or claim finality.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  hashKernelRevocationSigningRequest,
  hashPermissionRequest,
  isKernelExistingAccountProfile,
  type KernelRevocationEffect,
  type KernelRevocationSigningRequest,
  OAATH_KERNEL_REVOCATION_SIGNING_REQUEST_VERSION,
  OAATH_OWNER_SIGNING_REQUEST_VERSION,
  type OwnerSigningArtifact,
  type PermissionRequest,
  parseKernelRevocationSigningRequest,
  parseOwnerSigningArtifact,
  parsePermissionRequest,
} from "@oaath/protocol";
import {
  toPackedUserOperation,
  toUserOperation,
  type UserOperation,
} from "viem/account-abstraction";
import {
  encodeKernelInstallNonceInvalidationCall,
  encodeKernelPermissionUninstallCalls,
  type KernelUserOperationGas,
  type KernelV4AccountReadCapability,
  kernelV4Deployment,
  kernelV4ReplayableInstallTypedData,
} from "../../kernel-v4.js";
import {
  asViemUserOperation,
  OAATH_PREPARED_USER_OPERATION_VERSION,
  type PreparedPaymaster,
  type PreparedUserOperation,
  parsePreparedUserOperation,
} from "../../prepared-user-operation.js";
import { createKernelRuntime } from "../create-kernel-runtime.js";
import {
  captureKeyProfile,
  exactInput,
  inputInvalid,
  runtimeFail,
  sameInstall,
} from "../internal.js";
import { credentialKey } from "../key/credential.js";
import { p256Key } from "../key/p256.js";
import { ownerOperator } from "../operator/owner.js";
import { sessionOperator } from "../operator/session.js";
import type { KernelRuntime, KeyProfile } from "../types.js";
import { kernelPermissionInstallNonce } from "./install-nonce.js";
import { type KernelAllChainApproval, parseKernelAllChainApproval } from "./materialize.js";
import { deriveSessionPolicyProfiles } from "./profiles.js";

export interface PrepareKernelV4RevocationInput {
  readonly request: Readonly<PermissionRequest>;
  readonly approval: Readonly<KernelAllChainApproval>;
  readonly chainId: number;
  readonly reads: Readonly<KernelV4AccountReadCapability>;
  /** Chosen from chain evidence: invalidate an unused install, or remove an installed permission. */
  readonly effect: KernelRevocationEffect;
  readonly nonceKey: string;
  readonly sequence: string;
  readonly gas: Readonly<KernelUserOperationGas>;
  /** Caller-supplied EntryPoint 0.7 sponsorship, or null for a self-funded operation. */
  readonly paymaster: Readonly<PreparedPaymaster> | null;
}

export interface KernelSigningRequestRevocation {
  readonly signingRequest: Readonly<KernelRevocationSigningRequest>;
  readonly prepared: Readonly<PreparedUserOperation>;
  /** One owner key-profile signature over exactly `prepared`, encoded for the account; never submits. */
  sign(owner: Readonly<KeyProfile>): Promise<`0x${string}`>;
  /** Verifies an owner device's signing artifact and returns the exact root signature. */
  complete(artifact: Readonly<OwnerSigningArtifact>): Promise<`0x${string}`>;
}

/**
 * Prepares one P-256 owner operation from the canonical grant, self-funded or
 * sponsored by the caller's paymaster, which the operation hash binds.
 * The orchestrator supplies the chain evidence, root operation nonce and gas,
 * and retains this exact request before asking the owner. Expired application
 * permissions may still be revoked; current owner consent has its own lifetime.
 */
export async function prepareKernelV4Revocation(
  value: PrepareKernelV4RevocationInput,
): Promise<Readonly<KernelSigningRequestRevocation>> {
  const input = exactInput(
    value,
    [
      "request",
      "approval",
      "chainId",
      "reads",
      "effect",
      "nonceKey",
      "sequence",
      "gas",
      "paymaster",
    ],
    "Kernel revocation preparation",
    new WeakSet(),
  );
  const request = parsePermissionRequest(input.request);
  const approval = parseKernelAllChainApproval(input.approval);
  const ownerCredential = request.logicalAccount.ownerCredential;
  if (
    ownerCredential.kind !== "p256" ||
    isKernelExistingAccountProfile(request.logicalAccount) ||
    request.logicalAccount.factoryRoute !== "kernel_factory"
  )
    return inputInvalid("Kernel v4 revocation requires the P-256 Kernel owner");
  if (
    typeof input.chainId !== "number" ||
    (input.effect !== "invalidate-install" && input.effect !== "uninstall-permission")
  )
    return inputInvalid("Kernel v4 revocation chain or effect is invalid");
  if (approval.installNonce !== kernelPermissionInstallNonce(hashPermissionRequest(request)))
    return inputInvalid("Kernel v4 revocation approval belongs to another request");
  const deployment = kernelV4Deployment(input.chainId);
  const reads = input.reads as KernelV4AccountReadCapability;
  const key = p256Key({
    credential: ownerCredential,
    sign: async () =>
      runtimeFail(
        "kernel_runtime_signing_failed",
        "Kernel v4 revocation preparation has no owner signer",
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
    return inputInvalid("Kernel v4 revocation approval does not bind the requested permission");
  if (!(await key.verify(approval.digest, approval.enableSignature)))
    return runtimeFail(
      "kernel_runtime_signature_invalid",
      "Kernel v4 revocation approval has no valid owner signature",
    );
  const account = await owner.bindAccount({
    accountIndex: request.logicalAccount.accountIndex,
    initialPackages: owner.packages,
  });
  if (account.account !== approval.account)
    return inputInvalid("Kernel v4 revocation account contradicts its approval");
  const calls =
    input.effect === "invalidate-install"
      ? [
          encodeKernelInstallNonceInvalidationCall({
            account: account.account,
            installNonce: approval.installNonce,
          }),
        ]
      : encodeKernelPermissionUninstallCalls({
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
    gas: input.gas as KernelUserOperationGas,
    paymaster: input.paymaster as Readonly<PreparedPaymaster> | null,
  });
  const packed = toPackedUserOperation(asViemUserOperation(prepared.userOperation));
  const signingRequest = parseKernelRevocationSigningRequest({
    version: OAATH_KERNEL_REVOCATION_SIGNING_REQUEST_VERSION,
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
 * Reconstructs a previously admitted immutable revocation request without chain
 * reads, gas quotes, nonce allocation or account preparation. In particular,
 * factory bytes remain present even if the account deployed after consent.
 * This does not admit a grant or prove that a submission happened.
 */
export function restoreKernelV4Revocation(
  value: unknown,
): Readonly<KernelSigningRequestRevocation> {
  const signingRequest = parseKernelRevocationSigningRequest(value);
  const credential = signingRequest.install.signer.ownerCredential;
  if (credential.kind !== "p256") return inputInvalid("Kernel v4 revocation requires P-256");
  const owner = createKernelRuntime({
    deployment: kernelV4Deployment(signingRequest.chainId),
    operator: ownerOperator({
      key: p256Key({
        credential,
        sign: async () =>
          runtimeFail("kernel_runtime_signing_failed", "restored revocation request has no signer"),
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
      paymaster: unpackPaymaster(signingRequest.operation.paymasterAndData),
    },
    userOperationHash: signingRequest.expectedDigest,
  });
  if (prepared.entryPoint.address !== owner.deployment.entryPoint.address)
    return inputInvalid("restored revocation has an unsupported EntryPoint");
  return restoredRevocation(signingRequest, prepared, owner);
}
/** EntryPoint 0.7 `paymaster(20) || verificationGasLimit(16) || postOpGasLimit(16) || data`. */
function unpackPaymaster(packed: `0x${string}`): Readonly<PreparedPaymaster> | null {
  if (packed === "0x") return null;
  return Object.freeze({
    address: `0x${packed.slice(2, 42)}` as `0x${string}`,
    verificationGasLimit: BigInt(`0x${packed.slice(42, 74)}`).toString(10),
    postOpGasLimit: BigInt(`0x${packed.slice(74, 106)}`).toString(10),
    data: `0x${packed.slice(106)}` as `0x${string}`,
  });
}

function restoredRevocation(
  signingRequest: Readonly<KernelRevocationSigningRequest>,
  prepared: Readonly<PreparedUserOperation>,
  owner: Readonly<KernelRuntime>,
): Readonly<KernelSigningRequestRevocation> {
  const requestHash = hashKernelRevocationSigningRequest(signingRequest);
  const credential = signingRequest.install.signer.ownerCredential;
  if (credential.kind !== "p256") return inputInvalid("Kernel v4 revocation requires P-256");
  const ownerKey = p256Key({
    credential,
    sign: async () =>
      runtimeFail("kernel_runtime_signing_failed", "revocation request has no signer"),
  });
  return Object.freeze({
    signingRequest,
    prepared,
    async sign(value: Readonly<KeyProfile>) {
      const key = captureKeyProfile(value);
      // Refuse another credential before it is prompted.
      if (key.kind !== ownerKey.kind || key.publicMaterial !== ownerKey.publicMaterial)
        return runtimeFail(
          "kernel_runtime_binding_mismatch",
          "revocation owner key does not match the prepared owner",
        );
      const signer = createKernelRuntime({
        deployment: owner.deployment,
        operator: ownerOperator({ key }),
        reads: {
          read: async () =>
            runtimeFail("kernel_runtime_binding_mismatch", "revocation signing must not read"),
        },
      });
      return signer.signOperation(prepared);
    },
    async complete(value: Readonly<OwnerSigningArtifact>) {
      const artifact = parseOwnerSigningArtifact(value);
      if (artifact.requestHash !== requestHash)
        return runtimeFail(
          "kernel_runtime_signature_invalid",
          "owner artifact belongs to another revocation request",
        );
      return owner.encodeVerifiedSignature(prepared, artifact.signature);
    },
  });
}
