/**
 * The service as an ordinary OAuth client of an OAAth issuer.
 *
 * ```text
 * state and owner      plan: draft|awaiting_consent -> authorized, by this module
 * persisted evidence   sealed PKCE verifier + nonce + expected Grant (before PAR's URL
 *                      is returned); then the Grant record + client context + binding
 * resource occupied?   one pending authorization per plan; a new authorize replaces it
 * retry safe?          authorize: yes (a fresh PAR; the old state stops matching);
 *                      a pending code: one token request per consent tick, never a
 *                      new authorization
 * forbidden            adopting a Grant whose signer, application, policy, expiry or
 *                      account differ from what this plan asked for; a decision whose
 *                      capability hash does not bind the install approval
 * crash/reload         the callback is answered from PostgreSQL by any replica
 * ```
 *
 * The issuer is trusted for nothing: the decision carries the account root's
 * replayable install signature, which Kernel verifies on chain.
 *
 * @author taek <leekt216@gmail.com>
 */
import { createHash, randomBytes } from "node:crypto";
import { derivePlanPolicy } from "@oaath/automation";
import {
  advanceGrant,
  applyPermissionDecision,
  createGrantFromPermissionRequest,
  type GrantPolicy,
  type PermissionRequest,
  parsePermissionDecision,
  parsePermissionRequest,
  sameGrantIdentity,
} from "@oaath/protocol";
import { captureOaathBinding, GrantStore, type OaathBindingInput } from "@oaath/sdk/advanced";
import { kernelPermissionCapabilityHash, parseKernelPermissionApproval } from "@oaath/sdk/kernel";
import { OAATH_CLIENT_CONTEXT_VERSION } from "@oaath/sdk/persistence";
import { type PlanRow, readPlan, type ServiceContext, ServiceError } from "./context.js";
import { open, seal } from "./db.js";
import { ensureSigner, operatorCredential, signerScope } from "./signer.js";
import { createContextStore, createGrantStore } from "./store.js";

/** How long a member's pending request is redeemed before it is dropped. */
const CONSENT_POLL_SECONDS = 30;

interface PendingAuthorization {
  readonly verifier: string;
  readonly nonce: string;
  readonly expected: Readonly<{
    policy: GrantPolicy;
    expiresAt: number;
    deviceId: string;
    signer: `0x${string}`;
  }>;
  /** Set once the issuer issued a code that awaits the account root. */
  readonly code: string | null;
}

const base64Url = (bytes: Buffer) => bytes.toString("base64url");

export function redirectUri(context: ServiceContext): string {
  return `${context.config.publicUrl}/v1/oauth/callback`;
}

async function postForm(
  url: string,
  form: Record<string, string>,
): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      body: new URLSearchParams(form),
      signal: AbortSignal.timeout(15_000),
      redirect: "error",
    });
  } catch {
    throw new ServiceError("issuer_unavailable", 503);
  }
  const body = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  if (!response.ok) {
    const error = typeof body?.error === "string" ? body.error : "issuer_rejected";
    throw new ServiceError(
      /^[a-z0-9_]{1,64}$/u.test(error) ? `issuer_${error}` : "issuer_rejected",
      409,
    );
  }
  if (body === null) throw new ServiceError("issuer_unreadable", 503);
  return body;
}

/**
 * Pushes the plan's Grant request and returns the issuer URL the owner opens.
 * The pending authorization is durable before the URL leaves the service.
 */
export async function startAuthorization(
  context: ServiceContext,
  plan: PlanRow,
  returnTo: string | null,
): Promise<string> {
  if (plan.status !== "draft" && plan.status !== "awaiting_consent")
    throw new ServiceError("authorization_state_conflict");
  const scopeId = signerScope(plan);
  const signer = await ensureSigner(context.pool, context.config.sealKey, scopeId);
  const policy = derivePlanPolicy(plan.definition, plan.terms, context.now());
  const expected = {
    policy,
    expiresAt: plan.terms.schedule.endAt,
    deviceId: signer.deviceId,
    signer: signer.address,
  };
  const verifier = base64Url(randomBytes(32));
  const state = base64Url(randomBytes(32));
  const nonce = base64Url(randomBytes(32));
  const detail = {
    type: "oaath_grant",
    signer: operatorCredential(signer.address),
    policy,
    chains: [plan.terms.chainId],
    expires_at: expected.expiresAt,
    device_id: signer.deviceId,
  };
  const pushed = await postForm(`${context.config.issuer}/oauth/par`, {
    authorization_details: JSON.stringify([detail]),
    client_id: context.config.clientId,
    redirect_uri: redirectUri(context),
    response_type: "code",
    code_challenge: base64Url(createHash("sha256").update(verifier).digest()),
    code_challenge_method: "S256",
    scope: "openid",
    state,
    nonce,
    // The session's user is the OAAth signer the application's login proved;
    // the issuer binds it and the account so the portal opens on them.
    login_hint: `${plan.user_id}@${plan.account}`,
  });
  if (typeof pushed.request_uri !== "string") throw new ServiceError("issuer_unreadable", 503);
  const pending: PendingAuthorization = { verifier, nonce, expected, code: null };
  const updated = await context.pool.query(
    `UPDATE automation_plans SET status='awaiting_consent', revision=revision+1, signer_scope=$2, signer=$3,
       permission=$4, oauth_state=$5, oauth=$6, return_to=$7, next_consent_at=NULL, diagnostic=NULL
     WHERE id=$1 AND status IN ('draft','awaiting_consent')`,
    [
      plan.id,
      scopeId,
      signer.address,
      policy,
      state,
      seal(context.config.sealKey, pending, `oauth:${plan.id}`),
      returnTo,
    ],
  );
  if (updated.rowCount !== 1) throw new ServiceError("authorization_state_conflict");
  return `${context.config.issuer}/authorize?${new URLSearchParams({
    client_id: context.config.clientId,
    request_uri: pushed.request_uri,
  })}`;
}

export type CallbackOutcome = Readonly<{
  planId: string | null;
  status: "authorized" | "pending" | "declined" | "invalid";
  returnTo: string | null;
}>;

/** The browser's return from the issuer. Any replica answers it from PostgreSQL. */
export async function completeAuthorization(
  context: ServiceContext,
  query: URLSearchParams,
): Promise<CallbackOutcome> {
  const state = query.get("state");
  const row =
    state === null
      ? undefined
      : (
          await context.pool.query(
            "SELECT id FROM automation_plans WHERE oauth_state=$1 AND status='awaiting_consent'",
            [state],
          )
        ).rows[0];
  if (row === undefined) return { planId: null, status: "invalid", returnTo: null };
  const plan = await readPlan(context.pool, row.id);
  // RFC 9207: the response must come from the issuer this plan asked.
  if (query.get("iss") !== context.config.issuer)
    return { planId: plan.id, status: "invalid", returnTo: plan.return_to };
  const code = query.get("code");
  if (query.get("error") !== null || code === null) {
    await context.pool.query(
      "UPDATE automation_plans SET status='draft', revision=revision+1, oauth_state=NULL, oauth=NULL, diagnostic='consent_declined' WHERE id=$1 AND oauth_state=$2",
      [plan.id, state],
    );
    return { planId: plan.id, status: "declined", returnTo: plan.return_to };
  }
  const pending = open<PendingAuthorization>(
    context.config.sealKey,
    plan.oauth,
    `oauth:${plan.id}`,
  );
  const status = await redeem(context, plan, { ...pending, code });
  return { planId: plan.id, status, returnTo: plan.return_to };
}

/** One token request for a member request still awaiting the account root. */
export async function redeemPendingConsent(context: ServiceContext, planId: string): Promise<void> {
  const plan = await readPlan(context.pool, planId);
  if (plan.status !== "awaiting_consent" || plan.oauth === null) return;
  const pending = open<PendingAuthorization>(
    context.config.sealKey,
    plan.oauth,
    `oauth:${plan.id}`,
  );
  if (pending.code === null) return;
  if (pending.expected.expiresAt <= context.now()) {
    await context.pool.query(
      "UPDATE automation_plans SET status='expired', revision=revision+1, oauth=NULL, oauth_state=NULL, next_consent_at=NULL WHERE id=$1 AND status='awaiting_consent'",
      [plan.id],
    );
    return;
  }
  await redeem(context, plan, { ...pending, code: pending.code });
}

async function redeem(
  context: ServiceContext,
  plan: PlanRow,
  pending: PendingAuthorization & { code: string },
): Promise<"authorized" | "pending" | "declined"> {
  let token: Record<string, unknown>;
  try {
    token = await postForm(`${context.config.issuer}/oauth/token`, {
      grant_type: "authorization_code",
      client_id: context.config.clientId,
      code: pending.code,
      code_verifier: pending.verifier,
      redirect_uri: redirectUri(context),
    });
  } catch (error) {
    const code = error instanceof ServiceError ? error.code : "issuer_unavailable";
    if (code === "issuer_authorization_pending" || code === "issuer_slow_down") {
      await context.pool.query(
        "UPDATE automation_plans SET oauth=$2, next_consent_at=$3 WHERE id=$1 AND status='awaiting_consent'",
        [
          plan.id,
          seal(context.config.sealKey, pending, `oauth:${plan.id}`),
          context.now() + CONSENT_POLL_SECONDS,
        ],
      );
      return "pending";
    }
    if (code === "issuer_access_denied" || code === "issuer_invalid_grant") {
      await context.pool.query(
        "UPDATE automation_plans SET status='draft', revision=revision+1, oauth=NULL, oauth_state=NULL, next_consent_at=NULL, diagnostic='consent_declined' WHERE id=$1 AND status='awaiting_consent'",
        [plan.id],
      );
      return "declined";
    }
    throw error;
  }
  await adoptGrant(context, plan, pending.expected, token);
  return "authorized";
}

function same(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

/**
 * Verifies the released Grant is exactly the one this plan requested, then
 * persists it through the SDK's own Grant and client-context contracts.
 */
async function adoptGrant(
  context: ServiceContext,
  plan: PlanRow,
  expected: PendingAuthorization["expected"],
  token: Record<string, unknown>,
): Promise<void> {
  const mismatch = () => new ServiceError("grant_mismatch");
  const details = token.authorization_details;
  if (!Array.isArray(details) || details.length !== 1) throw mismatch();
  const detail = details[0] as Record<string, unknown>;
  let request: Readonly<PermissionRequest>;
  try {
    request = parsePermissionRequest(detail.permission_request);
  } catch {
    throw mismatch();
  }
  const origin = new URL(context.config.publicUrl).origin;
  const account = request.logicalAccount as { address?: string; ownerCredential: unknown };
  if (
    detail.type !== "oaath_grant" ||
    detail.grant_id !== request.requestId ||
    !same(request.operatorCredential, operatorCredential(expected.signer)) ||
    !same(request.application, {
      applicationId: context.config.clientId,
      clientId: context.config.clientId,
      origin,
      deviceId: expected.deviceId,
    }) ||
    !same(request.policy, expected.policy) ||
    request.expiresAt !== expected.expiresAt ||
    request.chainScope !== "all" ||
    request.sessionSigner !== null ||
    // A derived profile names no address; the context and the install approval do.
    (account.address !== undefined && account.address !== plan.account) ||
    request.context.accountId !== plan.account
  )
    throw mismatch();
  let decision: ReturnType<typeof parsePermissionDecision>;
  let approval: ReturnType<typeof parseKernelPermissionApproval>;
  try {
    decision = parsePermissionDecision(detail.decision);
    approval = parseKernelPermissionApproval(detail.enable);
  } catch {
    throw mismatch();
  }
  if (
    decision.kind !== "approve" ||
    (approval as { account?: string }).account !== plan.account ||
    kernelPermissionCapabilityHash(approval) !== decision.capabilityHash ||
    !same(decision.approvedPolicy, expected.policy)
  )
    throw mismatch();
  const applied = applyPermissionDecision({
    request,
    grant: createGrantFromPermissionRequest(request),
    observation: { status: "available", decision },
    evaluatedAt: context.now(),
  });
  if (applied.status !== "applied" || applied.grant.state !== "approved") throw mismatch();
  const active = advanceGrant(applied.grant, {
    type: "activate",
    identity: applied.grant.identity,
    activatedAt: context.now(),
  });

  const binding: OaathBindingInput = {
    issuer: context.config.issuer,
    applicationId: request.application.applicationId,
    applicationName: context.config.clientId,
    clientId: context.config.clientId,
    origin,
    redirectUri: redirectUri(context),
    deviceId: expected.deviceId,
    userHandle: request.context.accountId,
    context: request.context,
    account: request.logicalAccount,
    operatorCredential: request.operatorCredential,
  };
  const { bindingId } = captureOaathBinding(binding);
  const grants = new GrantStore(createGrantStore(context.pool));
  const committed = await grants.compareAndSwap({
    grantId: request.requestId,
    expectedStoreRevision: null,
    next: active,
  });
  if (committed.status !== "committed") {
    // A retried callback finds its own Grant; anything else is a conflict.
    const retained = await grants.get(request.requestId);
    if (!retained || !sameGrantIdentity(retained.value.identity, active.identity)) throw mismatch();
  }
  await createContextStore(context.pool).write(
    Object.freeze({
      version: OAATH_CLIENT_CONTEXT_VERSION,
      bindingId,
      grantId: request.requestId,
      request,
      approvedPolicy: decision.approvedPolicy,
      installApproval: approval,
      updatedAt: context.now(),
    }),
  );
  const authorized = await context.pool.query(
    `UPDATE automation_plans SET status='authorized', revision=revision+1, grant_id=$2, binding=$3,
       oauth=NULL, oauth_state=NULL, next_consent_at=NULL, diagnostic=NULL
     WHERE id=$1 AND status='awaiting_consent' AND signer=$4`,
    [plan.id, request.requestId, binding, expected.signer],
  );
  if (authorized.rowCount !== 1) throw new ServiceError("authorization_state_conflict");
}
