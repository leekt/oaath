/**
 * Opens a plan's adopted Grant through the SDK's injected composition: the
 * retained binding, the PostgreSQL Grant/Operation/context stores, the
 * budgeted chain ports, and the plan's sealed session key. `resume()` rebuilds
 * the same handle in any replica after any restart.
 *
 * Revocation's off-chain step asks the issuer to invalidate the Grant, proven
 * by the session key (`OAAth-Grant-Proof`).
 *
 * @author taek <leekt216@gmail.com>
 */
import type { KernelAccountProfile } from "@oaath/protocol";
import { createOAAth, type OaathGrantHandle } from "@oaath/sdk";
import { ECDSA_VALIDATOR, kernelKey } from "@oaath/sdk/kernel";
import { type PlanRow, type ServiceContext, ServiceError } from "./context.js";
import { loadSigner, type SessionSigner } from "./signer.js";
import {
  createContextStore,
  createGrantStore,
  createOperationStore,
  createUnusedStores,
} from "./store.js";

/** The exact text the issuer rebuilds for one grant-scoped request. */
export function grantRequestMessage(
  grantId: string,
  method: string,
  path: string,
  issuedAt: number,
): string {
  return `OAAth grant request v1\ngrant: ${grantId}\nmethod: ${method}\npath: ${path}\nissued: ${issuedAt}`;
}

/** `Authorization: OAAth-Grant-Proof <issuedAt>.<signature>` for one issuer request. */
export async function grantProof(
  signer: SessionSigner,
  grantId: string,
  method: string,
  path: string,
  issuedAt: number,
): Promise<string> {
  const signature = await signer.signMessage(grantRequestMessage(grantId, method, path, issuedAt));
  return `OAAth-Grant-Proof ${issuedAt}.${signature}`;
}

export interface OpenedGrant {
  readonly grant: Readonly<OaathGrantHandle>;
  readonly signer: SessionSigner;
  readonly close: () => Promise<void>;
}

export async function openGrant(context: ServiceContext, plan: PlanRow): Promise<OpenedGrant> {
  if (
    plan.grant_id === null ||
    plan.binding === null ||
    plan.signer_scope === null ||
    plan.signer === null
  )
    throw new ServiceError("grant_unavailable");
  const grantId = plan.grant_id;
  const signer = await loadSigner(
    context.pool,
    context.config.sealKey,
    plan.signer_scope,
    plan.signer,
  );
  const owner = (plan.binding.account as KernelAccountProfile).ownerCredential;
  const oaath = createOAAth({
    binding: plan.binding,
    approve: async () => {
      throw new ServiceError("approval_not_local");
    },
    invalidation: {
      async invalidateCapability({ capabilityHash }) {
        const path = `/oauth/grants/${encodeURIComponent(grantId)}/invalidate`;
        const response = await fetch(`${context.config.issuer}${path}`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: await grantProof(signer, grantId, "POST", path, context.now()),
          },
          body: JSON.stringify({ capability_hash: capabilityHash }),
          signal: AbortSignal.timeout(10_000),
          redirect: "error",
        });
        if (!response.ok) throw new ServiceError("issuer_invalidation_refused");
        return await response.json();
      },
    },
    stores: {
      grants: createGrantStore(context.pool),
      operations: createOperationStore(context.pool),
      context: createContextStore(context.pool),
      ...createUnusedStores(),
    },
    chains: [context.chain(plan.terms.chainId)],
    signing: {
      owner: kernelKey({
        credential: owner,
        validator: owner.kind === "ecdsa" ? ECDSA_VALIDATOR : null,
      }),
      session: kernelKey({ account: signer.account, validator: ECDSA_VALIDATOR }),
    },
    localKeyIds: [],
    now: context.now,
  });
  try {
    const connection = await oaath.connect();
    const grant = await connection.resume();
    if (grant === null) throw new ServiceError("grant_unavailable");
    return Object.freeze({
      grant,
      signer,
      close: async () => {
        await connection.close();
        await oaath.close();
      },
    });
  } catch (error) {
    await oaath.close().catch(() => undefined);
    throw error;
  }
}
