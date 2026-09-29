/** Wallet-owned consent through the canonical local Grant authorization boundary. */
import {
  hashPermissionRequest,
  OAATH_PERMISSION_DECISION_VERSION,
  type PermissionRequest,
} from "@oaath/protocol";
import { hashTypedData, keccak256, recoverAddress, stringToHex } from "viem";
import { createKernelRuntime } from "../kernel/create-kernel-runtime.js";
import { kernelV33Deployment } from "../kernel/deployment/v33.js";
import { ownerOperator } from "../kernel/operator/owner.js";
import { sessionOperator } from "../kernel/operator/session.js";
import { deriveSessionPolicyProfiles } from "../kernel/permission/profiles.js";
import {
  type KernelV33PermissionApproval,
  type KernelV33PermissionScope,
  kernelV33CapabilityHash,
  kernelV33PermissionEnableTypedData,
  kernelV33PermissionInstallNonce,
  OAATH_KERNEL_V33_APPROVAL_VERSION,
  parseKernelV33PermissionApproval,
} from "../kernel/permission/v33.js";
import type { KeyProfile } from "../kernel/types.js";
import type { GrantStore } from "../store.js";
import type { OaathBinding } from "./binding.js";
import { clientFail, mapClientFailure } from "./errors.js";
import type { OaathChainCapability } from "./grant-handle.js";

export type LocalPermissionSign = (
  request: ReturnType<typeof kernelV33PermissionEnableTypedData> & {
    readonly account?: `0x${string}`;
  },
) => Promise<unknown>;

export interface OaathLocalApprovalReview {
  readonly account: `0x${string}`;
  readonly chainScope: "all";
  readonly policy: Readonly<PermissionRequest["policy"]>;
  readonly typedData: ReturnType<typeof kernelV33PermissionEnableTypedData>;
}

export function createLocalPermissionAuthority(input: {
  readonly binding: Readonly<OaathBinding>;
  readonly owner: Readonly<KeyProfile>;
  readonly session: Readonly<KeyProfile>;
  readonly grants: GrantStore;
  readonly chains: readonly Readonly<OaathChainCapability>[];
  readonly signTypedData: LocalPermissionSign;
  readonly localWallet: boolean;
  readonly onApproval: ((review: Readonly<OaathLocalApprovalReview>) => Promise<void>) | null;
  readonly now: () => number;
}) {
  let pending = false;
  let closed = false;
  const fail = () => clientFail("oaath_client_state_conflict", "local permission state disagrees");
  function assertActive(request: Readonly<PermissionRequest>) {
    if (closed) return clientFail("oaath_client_closed", "local authority is closed");
    if (input.now() >= request.expiresAt) return fail();
  }
  async function signApproval(request: Readonly<PermissionRequest>) {
    if (request.logicalAccount.kernelVersion !== "0.3.3") return fail();
    const address = request.logicalAccount.address;
    let scope: Readonly<KernelV33PermissionScope> | undefined;
    for (const chain of input.chains) {
      const deployment = kernelV33Deployment(chain.chainId);
      const options = { deployment, reads: chain.reads };
      // Verify the connected root owner on every configured chain before consent.
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
      const nonce = await kernelV33PermissionInstallNonce({ runtime, account, reads: chain.reads });
      if (runtime.validation.kind !== "permission") return fail();
      const next = Object.freeze({
        chainScope: "all" as const,
        account: address,
        nonce,
        permissionId: runtime.validation.permissionId,
        packages: runtime.packages,
      });
      if (scope && JSON.stringify(scope) !== JSON.stringify(next)) {
        return clientFail(
          "oaath_client_state_conflict",
          "configured chains require different permission approvals",
          "local_permission_scope_mismatch",
        );
      }
      scope = next;
    }
    if (!scope) return fail();
    const typedData = kernelV33PermissionEnableTypedData(scope);
    const digest = hashTypedData(typedData);
    await input
      .onApproval?.(
        structuredClone({ account: address, chainScope: "all", policy: request.policy, typedData }),
      )
      .catch(() =>
        clientFail("oaath_client_decision_unavailable", "local permission approval failed"),
      );
    assertActive(request);
    const produced = await input
      .signTypedData({
        ...typedData,
        ...(input.localWallet ? {} : { account: input.owner.publicMaterial as `0x${string}` }),
      })
      .catch(() =>
        clientFail("oaath_client_decision_unavailable", "local permission approval failed"),
      );
    if (typeof produced !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(produced))
      return clientFail("oaath_client_signing_failed", "local permission signature is invalid");
    const signature = produced.toLowerCase() as `0x${string}`;
    if (
      (await recoverAddress({ hash: digest, signature })).toLowerCase() !==
      input.owner.publicMaterial
    )
      return clientFail("oaath_client_signing_failed", "local permission signer changed");
    return parseKernelV33PermissionApproval({
      version: OAATH_KERNEL_V33_APPROVAL_VERSION,
      ...scope,
      digest,
      enableSignature: signature,
    });
  }
  return Object.freeze({
    invalidation: Object.freeze({
      async invalidateCapability(
        request: Readonly<{ grantId: string; capabilityHash: `0x${string}` }>,
      ) {
        const record = await input.grants.get(request.grantId);
        const grant = record?.value;
        if (
          !grant ||
          grant.state !== "revoking" ||
          grant.approval?.capabilityHash !== request.capabilityHash ||
          JSON.stringify(grant.identity.application) !==
            JSON.stringify(input.binding.application) ||
          JSON.stringify(grant.identity.logicalAccount) !== JSON.stringify(input.binding.account) ||
          JSON.stringify(grant.identity.operatorCredential) !==
            JSON.stringify(input.binding.operatorCredential)
        )
          return fail();
        // Local admission is stopped by the durable revoking state, which every
        // fresh Grant handle reads. This acknowledges that exact state only;
        // the Grant still requires separate finalized onchain revocation proof.
        return Object.freeze({
          evidenceHash: keccak256(
            stringToHex(
              JSON.stringify([
                "@oaath/sdk:local-admission-revocation/v1",
                input.binding.bindingId,
                request.grantId,
                request.capabilityHash,
                record.storeRevision,
                grant.revocationStartedAt,
              ]),
            ),
          ),
          invalidatedAt: Math.max(input.now(), grant.updatedAt),
        });
      },
    }),
    async approve(request: Readonly<PermissionRequest>) {
      assertActive(request);
      if (pending)
        return clientFail(
          "oaath_client_state_conflict",
          "local permission approval is pending",
          "local_request_pending",
        );
      pending = true;
      try {
        const approval = await signApproval(request);
        assertActive(request);
        return Object.freeze({
          version: OAATH_PERMISSION_DECISION_VERSION,
          kind: "approve",
          requestId: request.requestId,
          requestHash: hashPermissionRequest(request),
          decidedAt: input.now(),
          approvedPolicy: request.policy,
          capabilityHash: kernelV33CapabilityHash(approval),
          installApproval: approval,
        });
      } catch (error) {
        return mapClientFailure(error, "local permission approval failed");
      } finally {
        pending = false;
      }
    },
    close() {
      closed = true;
    },
  });
}
