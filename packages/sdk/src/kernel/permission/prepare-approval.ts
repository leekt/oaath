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
  type Eip712OwnerSigningRequest,
  hashCanonicalEip712TypedData,
  hashOwnerSigningRequest,
  hashPermissionRequest,
  isKernelExistingAccountProfile,
  type KernelExistingAccountProfile,
  OAATH_OWNER_SIGNING_REQUEST_VERSION,
  OAATH_PERMISSION_DECISION_VERSION,
  type OwnerSigningArtifact,
  type PermissionRequest,
  parseKernelReplayableInstallOwnerSigningRequest,
  parseOwnerSigningArtifact,
  parseOwnerSigningRequest,
  parsePermissionRequest,
} from "@oaath/protocol";
import { hashTypedData } from "viem";
import {
  kernelV4Deployment,
  kernelV4ReplayableInstallDigest,
  kernelV4ReplayableInstallTypedData,
} from "../../kernel-v4.js";
import { createKernelRuntime } from "../create-kernel-runtime.js";
import {
  type KernelAccountDescriptor,
  type KernelReads,
  kernelDeployment,
} from "../deployment/account.js";
import type { KernelDeployment } from "../deployment/profile.js";
import { ECDSA_VALIDATOR } from "../deployment/v33.js";
import { captureKeyProfile, exactInput, inputInvalid, runtimeFail } from "../internal.js";
import { credentialKey } from "../key/credential.js";
import { p256Key } from "../key/p256.js";
import { ownerOperator } from "../operator/owner.js";
import { sessionOperator } from "../operator/session.js";
import type { KernelRuntime, KeyProfile } from "../types.js";
import {
  approveKernelPermission,
  type KernelGrantApproval,
  type KernelPermissionEnableTypedData,
  kernelGrantCapabilityHash,
  kernelPermissionEnableTypedData,
  kernelPermissionNonce,
} from "./approval.js";
import { kernelPermissionInstallNonce } from "./install-nonce.js";
import { approveKernelPermissionAllChain } from "./materialize.js";
import { deriveSessionPolicyProfiles } from "./profiles.js";

export interface PrepareKernelPermissionApprovalInput {
  readonly request: Readonly<PermissionRequest>;
  /** Configured chain used to bind the account; the resulting approval covers every chain. */
  readonly chainId: number;
  readonly reads: KernelReads;
}

/** The existing decision and separately owned install approval consumed by createOAAth. */
export interface KernelPermissionDecision extends ApprovePermissionDecision {
  readonly installApproval: Readonly<KernelGrantApproval>;
}

export interface PreparedKernelPermissionApproval {
  readonly request: Readonly<PermissionRequest>;
  /**
   * The exact `kernel-enable` owner signing request. For a Kernel `0.4.0`
   * account it is the replayable install request an owner device completes.
   */
  readonly signingRequest: Readonly<Eip712OwnerSigningRequest>;
  /**
   * Takes the one signature from a key profile for the request's owner
   * credential, wherever that key lives, and assembles a decision. The decision
   * time and owner key are checked before the owner is asked. Submits nothing.
   */
  sign(owner: Readonly<KeyProfile>, decidedAt: number): Promise<Readonly<KernelPermissionDecision>>;
  /**
   * Verifies an owner device's P-256 signing artifact and assembles a decision;
   * it submits nothing. Another owner kind fails with `kernel_runtime_unsupported`.
   */
  complete(
    artifact: Readonly<OwnerSigningArtifact>,
    decidedAt: number,
  ): Promise<Readonly<KernelPermissionDecision>>;
}

/** One configured chain an existing account is bound on. */
export interface ExistingAccountApprovalChain {
  readonly chainId: number;
  readonly reads: KernelReads;
}

/** The one enable approval an existing account's request binds on every configured chain. */
export interface ExistingAccountApproval {
  /** The first chain's session runtime; the approval is identical on every chain. */
  readonly runtime: Readonly<KernelRuntime>;
  readonly account: Readonly<KernelAccountDescriptor>;
  readonly nonce: string;
  /** The exact EIP-712 value the owner signs, from the account's deployment. */
  readonly typedData: KernelPermissionEnableTypedData;
  readonly digest: `0x${string}`;
}

/**
 * Binds an existing-account request on each configured chain and derives the
 * one enable approval its root owner signs. The owner key is proven as the
 * account's onchain root owner on every chain first; chains that would need
 * different approvals fail with `kernel_runtime_binding_mismatch`. The owner
 * key may be public-only: this never signs.
 */
export async function prepareExistingAccountApproval(input: {
  readonly request: Readonly<PermissionRequest>;
  readonly owner: Readonly<KeyProfile>;
  readonly session: Readonly<KeyProfile>;
  readonly chains: readonly Readonly<ExistingAccountApprovalChain>[];
}): Promise<Readonly<ExistingAccountApproval>> {
  const { request } = input;
  if (!isKernelExistingAccountProfile(request.logicalAccount))
    return runtimeFail("kernel_runtime_unsupported", "the request names no existing account");
  const { address, kernelVersion } = request.logicalAccount;
  const requestHash = hashPermissionRequest(request);
  let scope: string | undefined;
  let approval: Readonly<Omit<ExistingAccountApproval, "digest">> | undefined;
  for (const chain of input.chains) {
    // The selected deployment stays typed as any supported one: approval
    // typed data and nonce come from it, never from a version literal.
    const options: Readonly<{ deployment: Readonly<KernelDeployment>; reads: KernelReads }> = {
      deployment: kernelDeployment({ chainId: chain.chainId, kernelVersion }),
      reads: chain.reads,
    };
    await createKernelRuntime({
      ...options,
      operator: ownerOperator({ key: input.owner }),
    }).bindAccount({ address });
    const runtime = createKernelRuntime({
      ...options,
      operator: sessionOperator({
        key: input.session,
        policies: deriveSessionPolicyProfiles(request.policy),
      }),
    });
    const account = await runtime.bindAccount({ address });
    const nonce = await kernelPermissionNonce({
      runtime,
      account,
      reads: chain.reads,
      requestHash,
    });
    if (runtime.validation.kind !== "permission")
      return runtimeFail("kernel_runtime_binding_mismatch", "session runtime has no permission");
    const next = JSON.stringify({
      nonce,
      permissionId: runtime.validation.permissionId,
      packages: runtime.packages,
    });
    if (scope !== undefined && scope !== next)
      return runtimeFail(
        "kernel_runtime_binding_mismatch",
        "configured chains require different permission approvals",
      );
    scope = next;
    approval ??= Object.freeze({
      runtime,
      account,
      nonce,
      typedData: kernelPermissionEnableTypedData({ runtime, account, nonce }),
    });
  }
  if (!approval) return inputInvalid("approval requires at least one chain");
  return Object.freeze({
    ...approval,
    digest: hashTypedData(approval.typedData as Parameters<typeof hashTypedData>[0]),
  });
}

/** Kernel 0.3.3's enable domain, in the protocol's canonical EIP-712 order. */
const V33_ENABLE_DOMAIN = Object.freeze([
  { name: "name", type: "string" },
  { name: "version", type: "string" },
  { name: "chainId", type: "uint256" },
  { name: "verifyingContract", type: "address" },
]);

/** The owner signing request for one existing account's prepared approval. */
function existingSigningRequest(
  account: Readonly<KernelExistingAccountProfile>,
  approval: Readonly<ExistingAccountApproval>,
): Readonly<Eip712OwnerSigningRequest> {
  const signer = { account: account.address, ownerCredential: account.ownerCredential };
  const replay = { nonce: approval.nonce, deadline: null };
  if (account.kernelVersion === "0.4.0")
    return parseKernelReplayableInstallOwnerSigningRequest({
      version: OAATH_OWNER_SIGNING_REQUEST_VERSION,
      kind: "eip712",
      purpose: "kernel-enable",
      signer,
      typedData: approval.typedData,
      expectedDigest: approval.digest,
      replay,
    });
  // Kernel 0.3.3's typed data carries numeric fields; the canonical form states
  // them as decimal strings and names its domain type, and must hash the same.
  const typedData = JSON.parse(
    JSON.stringify({
      ...approval.typedData,
      types: { EIP712Domain: V33_ENABLE_DOMAIN, ...approval.typedData.types },
    }),
    (_key, value) => (typeof value === "number" ? String(value) : value),
  );
  const request = parseOwnerSigningRequest({
    version: OAATH_OWNER_SIGNING_REQUEST_VERSION,
    kind: "eip712",
    purpose: "kernel-enable",
    signer,
    typedData,
    expectedDigest: approval.digest,
    replay,
  }) as Readonly<Eip712OwnerSigningRequest>;
  if (hashCanonicalEip712TypedData(request.typedData) !== approval.digest)
    return runtimeFail("kernel_runtime_evidence_invalid", "enable typed data does not hash");
  return request;
}

/**
 * Prepares the owner's Kernel approval from one captured request. Account and
 * permission packages come from createKernelRuntime; the owner never needs an
 * application session key, and preparation cannot sign.
 * Recreate with the same request to obtain the same signing request. Each
 * Kernel `0.4.0` request selects its own install key at sequence zero; see
 * kernelPermissionInstallNonce for the account's global-minimum constraint. A
 * Kernel `0.3.3` request binds the account's current enable nonce.
 *
 * Supported: an existing Kernel `0.3.3` or `0.4.0` account with its ECDSA or
 * raw P-256 root owner, proven onchain, and a P-256 owner of a Kernel `0.4.0`
 * account derived through the Kernel factory. Any other request fails with
 * `kernel_runtime_unsupported` before any signing.
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
  const account = request.logicalAccount;
  const ownerCredential = account.ownerCredential;
  const existing = isKernelExistingAccountProfile(account);
  if (!existing && (ownerCredential.kind !== "p256" || account.factoryRoute !== "kernel_factory")) {
    return runtimeFail(
      "kernel_runtime_unsupported",
      "Kernel approval preparation requires an existing account or a P-256 owner of a factory-derived Kernel 0.4.0 account",
    );
  }
  if (typeof input.chainId !== "number") return inputInvalid("approval chain is invalid");
  const reads = input.reads as KernelReads;
  const requestHash = hashPermissionRequest(request);
  const ownerKey = credentialKey({
    credential: ownerCredential,
    validator: ownerCredential.kind === "ecdsa" ? ECDSA_VALIDATOR : null,
  });
  const sessionKey = credentialKey({ credential: request.operatorCredential, validator: null });

  let signingRequest: Readonly<Eip712OwnerSigningRequest>;
  let approve: (owner: Readonly<KeyProfile>) => Promise<Readonly<KernelGrantApproval>>;
  if (existing) {
    const approval = await prepareExistingAccountApproval({
      request,
      owner: ownerKey,
      session: sessionKey,
      chains: [{ chainId: input.chainId, reads }],
    });
    signingRequest = existingSigningRequest(account, approval);
    approve = (owner) =>
      approveKernelPermission({
        owner,
        runtime: approval.runtime,
        account: approval.account,
        nonce: approval.nonce,
      });
  } else {
    const deployment = kernelV4Deployment(input.chainId);
    const installNonce = kernelPermissionInstallNonce(requestHash);
    const ownerRuntime = createKernelRuntime({
      deployment,
      operator: ownerOperator({ key: ownerKey }),
      reads,
    });
    const sessionRuntime = createKernelRuntime({
      deployment,
      operator: sessionOperator({
        key: sessionKey,
        policies: deriveSessionPolicyProfiles(request.policy),
      }),
      reads,
    });
    const descriptor = await ownerRuntime.bindAccount({
      accountIndex: account.accountIndex,
      initialPackages: ownerRuntime.packages,
    });
    const scope = Object.freeze({
      account: descriptor.account,
      nonce: installNonce,
      packages: sessionRuntime.packages,
    });
    signingRequest = parseKernelReplayableInstallOwnerSigningRequest({
      version: OAATH_OWNER_SIGNING_REQUEST_VERSION,
      kind: "eip712",
      purpose: "kernel-enable",
      signer: { account: descriptor.account, ownerCredential },
      typedData: kernelV4ReplayableInstallTypedData(scope),
      expectedDigest: kernelV4ReplayableInstallDigest(scope),
      replay: { nonce: installNonce, deadline: null },
    });
    approve = (owner) =>
      approveKernelPermissionAllChain({
        owner,
        account: descriptor.account,
        installNonce,
        packages: sessionRuntime.packages,
      });
  }
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
    const installApproval = await approve(owner);
    return Object.freeze({
      version: OAATH_PERMISSION_DECISION_VERSION,
      kind: "approve" as const,
      requestId: request.requestId,
      requestHash,
      decidedAt,
      approvedPolicy: request.policy,
      capabilityHash: kernelGrantCapabilityHash(installApproval),
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
      if (ownerCredential.kind !== "p256")
        return runtimeFail(
          "kernel_runtime_unsupported",
          "a signing artifact completes only a P-256 owner's approval",
        );
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
