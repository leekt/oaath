/** In-process issuer: the ordinary permission protocol, with wallet-owned consent. */
import {
  deriveCodeChallenge,
  hashPermissionRequest,
  OAATH_PERMISSION_DECISION_VERSION,
  type PermissionRequest,
  parsePermissionRequest,
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

type Pending = {
  readonly request: Readonly<PermissionRequest>;
  readonly challenge: string;
  readonly code: string;
  stage: "requested" | "approving" | "approved" | "consumed";
  approval: Readonly<KernelV33PermissionApproval> | null;
};

export type LocalPermissionSign = (
  request: ReturnType<typeof kernelV33PermissionEnableTypedData> & {
    readonly account?: `0x${string}`;
  },
) => Promise<unknown>;

export function createLocalPermissionAuthority(input: {
  readonly binding: Readonly<OaathBinding>;
  readonly owner: Readonly<KeyProfile>;
  readonly session: Readonly<KeyProfile>;
  readonly grants: GrantStore;
  readonly chains: readonly Readonly<OaathChainCapability>[];
  readonly signTypedData: LocalPermissionSign;
  readonly localWallet: boolean;
  readonly now: () => number;
}) {
  let pending: Pending | null = null;
  let signedOut = false;
  const fail = () => clientFail("oaath_client_state_conflict", "local permission state disagrees");
  function current(id: string) {
    if (signedOut) clientFail("oaath_client_signed_out", "local authority signed out");
    if (!pending || pending.request.requestId !== id || input.now() >= pending.request.expiresAt)
      return fail();
    return pending;
  }
  async function approve(request: Readonly<PermissionRequest>) {
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
    const produced = await input.signTypedData({
      ...typedData,
      ...(input.localWallet ? {} : { account: input.owner.publicMaterial as `0x${string}` }),
    });
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
        if (pending?.request.requestId === request.grantId) pending = null;
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
    issuer: Object.freeze({
      url: input.binding.issuer.url,
      async fetch(request: Request): Promise<Response> {
        if (signedOut)
          return Response.json({ error: { code: "local_signed_out" } }, { status: 401 });
        const path = request.url.slice(input.binding.issuer.url.length);
        if (!request.url.startsWith(`${input.binding.issuer.url}/`) || request.method !== "POST")
          return fail();
        if (path === "/authorization/resume") {
          // No external authentication exists in this mode. Durable Grant validation
          // and fresh chain evidence still govern all execution and recovery.
          return Response.json({ decision: null });
        }
        if (path === "/authorization/requests") {
          if (pending && input.now() < pending.request.expiresAt)
            return Response.json({ error: { code: "local_request_pending" } }, { status: 409 });
          const body = await request.json();
          if (
            body.redirectUri !== input.binding.redirectUri ||
            typeof body.codeChallenge !== "string"
          )
            return fail();
          const scope = parsePermissionRequest({
            ...JSON.parse(body.requestedScope),
            requestId: crypto.randomUUID(),
          });
          if (
            JSON.stringify(scope.logicalAccount) !== JSON.stringify(input.binding.account) ||
            JSON.stringify(scope.operatorCredential) !==
              JSON.stringify(input.binding.operatorCredential) ||
            JSON.stringify(scope.application) !== JSON.stringify(input.binding.application) ||
            JSON.stringify(scope.context) !== JSON.stringify(input.binding.context) ||
            scope.sessionSigner !== null
          )
            return fail();
          pending = {
            request: scope,
            challenge: body.codeChallenge,
            code: crypto.randomUUID(),
            stage: "requested",
            approval: null,
          };
          return Response.json({ requestId: scope.requestId, expiresAt: scope.expiresAt });
        }
        if (path === "/authorization/codes/consume") {
          const body = await request.json();
          const value = current(pending?.request.requestId ?? "");
          if (
            value.stage !== "approved" ||
            body.code !== value.code ||
            body.redirectUri !== input.binding.redirectUri ||
            deriveCodeChallenge(body.codeVerifier, fail) !== value.challenge
          )
            return fail();
          value.stage = "consumed";
          return Response.json({
            requestId: value.request.requestId,
            artifactId: value.request.requestId,
          });
        }
        const match = /^\/authorization\/artifacts\/([^/]+)\/claim$/.exec(path);
        if (match) {
          const value = current(match[1]!);
          if (value.stage !== "consumed" || !value.approval) return fail();
          const artifact = {
            version: OAATH_PERMISSION_DECISION_VERSION,
            kind: "approve",
            requestId: value.request.requestId,
            requestHash: hashPermissionRequest(value.request),
            decidedAt: input.now(),
            approvedPolicy: value.request.policy,
            capabilityHash: kernelV33CapabilityHash(value.approval),
            installApproval: value.approval,
          };
          pending = null;
          return Response.json({
            requestId: value.request.requestId,
            artifact: JSON.stringify(artifact),
          });
        }
        return fail();
      },
      async signOut() {
        signedOut = true;
        pending = null;
      },
    }),
    authorization: Object.freeze({
      async authorize(request: {
        readonly requestId: string;
        readonly redirectUri: string;
        readonly expiresAt: number;
      }) {
        const value = current(request.requestId);
        if (
          value.stage !== "requested" ||
          request.redirectUri !== input.binding.redirectUri ||
          request.expiresAt !== value.request.expiresAt
        )
          return fail();
        value.stage = "approving";
        try {
          const approval = await approve(value.request);
          if (current(request.requestId) !== value) return fail();
          value.approval = approval;
          value.stage = "approved";
          return { code: value.code };
        } catch (error) {
          if (pending === value) pending = null;
          return mapClientFailure(error, "local permission approval failed");
        }
      },
    }),
    close() {
      signedOut = true;
      pending = null;
    },
  });
}
