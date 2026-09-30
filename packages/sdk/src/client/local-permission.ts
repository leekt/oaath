/** Wallet-owned consent through the canonical local Grant authorization boundary. */
import {
  hashPermissionRequest,
  isKernelExistingAccountProfile,
  OAATH_PERMISSION_DECISION_VERSION,
  type PermissionRequest,
} from "@oaath/protocol";
import { keccak256, stringToHex } from "viem";
import {
  approveKernelPermission,
  type KernelPermissionEnableTypedData,
  kernelGrantCapabilityHash,
  signedKernelPermissionApproval,
} from "../kernel/permission/approval.js";
import { prepareExistingAccountApproval } from "../kernel/permission/prepare-approval.js";
import type { KeyProfile } from "../kernel/types.js";
import type { GrantStore } from "../store.js";
import type { OaathBinding } from "./binding.js";
import { clientFail, mapClientFailure } from "./errors.js";
import type { OaathChainCapability } from "./grant-handle.js";

/** Wallet typed-data signing for the selected deployment's enable approval. */
export type LocalPermissionSign = (
  request: KernelPermissionEnableTypedData & {
    readonly account?: `0x${string}`;
  },
) => Promise<unknown>;

export interface OaathWalletApprovalReview {
  readonly account: `0x${string}`;
  readonly chainScope: "all";
  readonly policy: Readonly<PermissionRequest["policy"]>;
  /** The exact enable approval the wallet signs, from the account's deployment. */
  readonly typedData: KernelPermissionEnableTypedData;
}

export function createLocalPermissionAuthority(input: {
  readonly binding: Readonly<OaathBinding>;
  readonly owner: Readonly<KeyProfile>;
  readonly session: Readonly<KeyProfile>;
  readonly grants: GrantStore;
  readonly chains: readonly Readonly<OaathChainCapability>[];
  /** A wallet's typed-data prompt, or null when the owner key profile signs. */
  readonly walletApproval: Readonly<{
    signTypedData: LocalPermissionSign;
    localWallet: boolean;
  }> | null;
  readonly onApproval: ((review: Readonly<OaathWalletApprovalReview>) => Promise<void>) | null;
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
    // Local mode binds an existing account on its detected deployment.
    if (!isKernelExistingAccountProfile(request.logicalAccount)) return fail();
    const address = request.logicalAccount.address;
    // Verifies the root owner on every configured chain before consent.
    const approvalInput = await prepareExistingAccountApproval({
      request,
      owner: input.owner,
      session: input.session,
      chains: input.chains,
    });
    const { typedData } = approvalInput;
    await input
      .onApproval?.(
        structuredClone({ account: address, chainScope: "all", policy: request.policy, typedData }),
      )
      .catch(() =>
        clientFail("oaath_client_decision_unavailable", "local permission approval failed"),
      );
    assertActive(request);
    const wallet = input.walletApproval;
    if (wallet === null)
      // The owner key signs the same digest; the artifact recomputes and checks it.
      return approveKernelPermission({
        owner: input.owner,
        runtime: approvalInput.runtime,
        account: approvalInput.account,
        nonce: approvalInput.nonce,
      }).catch((error) => mapClientFailure(error, "local permission approval failed"));
    const produced = await wallet
      .signTypedData({
        ...typedData,
        ...(wallet.localWallet ? {} : { account: input.owner.publicMaterial as `0x${string}` }),
      })
      .catch(() =>
        clientFail("oaath_client_decision_unavailable", "local permission approval failed"),
      );
    // The root owner was proven onchain above; the assembler checks the digest
    // and that the wallet's signature recovers to it.
    return signedKernelPermissionApproval({
      runtime: approvalInput.runtime,
      account: approvalInput.account,
      nonce: approvalInput.nonce,
      owner: input.owner.publicMaterial as `0x${string}`,
      typedData,
      signature: produced,
    }).catch((error) => mapClientFailure(error, "local permission signature is invalid"));
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
          capabilityHash: kernelGrantCapabilityHash(approval),
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
