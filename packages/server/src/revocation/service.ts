/**
 * Owner revocation custody: absent -> pending -> approved | rejected once.
 * The immutable request and terminal decision are the only persisted evidence.
 * Approval occupies this operation ID; it proves custody, never submission or
 * onchain completion. No execution lane is acquired here. A decision retry reads
 * the stored outcome before expiry or artifact handling. Enqueue/ambiguous
 * commits are never automatically retried. Reload needs only store/KMS; there
 * is no in-memory preparation to recover. Transactions own rollback and release.
 */
import {
  hashPermissionRequest,
  type KernelV4RevocationSigningRequest,
  type PermissionRequest,
  parseKernelV4RevocationSigningRequest,
} from "@oaath/protocol";
import { sealArtifact } from "../artifact/encrypt.js";
import { readApprovedPermission } from "../authorization/approved-permission.js";
import { randomIdentifier } from "../authorization/challenge.js";
import type { AuthorizationDecisionCommand } from "../authorization/decision.js";
import { verifyKernelV4RevocationOwnerSigningArtifact } from "../authorization/owner-signing.js";
import { classifyStoredAuthorizationScope } from "../authorization/scope.js";
import { type RelayClock, relayNow } from "../clock.js";
import type { ServiceDirectory } from "../directory/service.js";
import {
  type OwnerPhoneRevocationDecision,
  projectOwnerPhoneRevocation,
} from "../native/revocation.js";
import { relayFailure } from "../relay/errors.js";
import type { RelayCaller } from "../security/authentication.js";
import type { RelayKms } from "../security/kms.js";
import {
  type RelayStore,
  type RelayTransaction,
  withRelayTransaction,
} from "../store/interface.js";
import { timestamp } from "../store/records.js";
import {
  OAATH_REVOCATION_DECISION_RECORD_VERSION,
  OAATH_REVOCATION_REQUEST_RECORD_VERSION,
  REVOCATION_OPERATION_PREFIX,
  type RevocationDecisionRecord,
  type RevocationRequestRecord,
} from "./records.js";

export interface RequestOwnerPhoneRevocationInput {
  readonly store: RelayStore;
  readonly clock: RelayClock;
  readonly kms: RelayKms;
  readonly directory: ServiceDirectory;
  /** Deployment-authenticated original application/member. */
  readonly caller: RelayCaller;
  readonly grantId: string;
  readonly chainId: number;
  readonly requestTtlMs: number;
  /**
   * Deployment uses prepareKernelPhoneRevocation to verify the retained Kernel
   * capability, read target-chain state, and choose effect/root nonce/gas.
   * Receives the retained approval plaintext; never log or expose it to clients.
   * Returns the SDK signingRequest only. Must not sign or submit an operation.
   */
  readonly prepare: (
    input: Readonly<{ request: Readonly<PermissionRequest>; artifact: string; chainId: number }>,
  ) => Promise<unknown>;
}

/** Deployment enqueue capability; returns metadata for the existing phone transport/push. */
export async function requestOwnerPhoneRevocation(
  input: RequestOwnerPhoneRevocationInput,
): Promise<Readonly<{ operationId: string; expiresAt: number }>> {
  const { store, clock, kms, directory, caller, grantId, chainId, requestTtlMs, prepare } = input;
  if (caller.role !== "client")
    return relayFailure("relay_forbidden", "only the originating client may request revocation");
  if (
    !Number.isSafeInteger(chainId) ||
    chainId < 1 ||
    !Number.isSafeInteger(requestTtlMs) ||
    requestTtlMs < 1
  )
    return relayFailure("relay_request_invalid", "revocation chain or TTL is invalid");
  const source = await withRelayTransaction(store, async (transaction) => {
    const request = await transaction.lockAuthorizationRequest(grantId);
    if (!request || request.clientId !== caller.clientId || request.subject !== caller.subject)
      return relayFailure("relay_forbidden", "permission is not owned by this caller");
    const scope = classifyStoredAuthorizationScope(request.requestedScope, request.requestId);
    const decision = await transaction.lockAuthorizationDecision(grantId);
    if (scope.kind !== "permission-request" || decision?.outcome !== "approved")
      return relayFailure("relay_request_invalid", "permission is not approved");
    const owner = await directory.resolveRevocationOwner(caller, {
      requestId: grantId,
      requestedScope: request.requestedScope,
      chainId,
    });
    if (!owner) return relayFailure("relay_forbidden", "account or chain is not assigned");
    const retained = await readApprovedPermission(
      transaction,
      kms,
      request,
      decision,
      scope.request,
    );
    if (!retained)
      return relayFailure("relay_record_unreadable", "approved permission is unreadable");
    return { request: scope.request, artifact: retained.plaintext, owner };
  });
  let signingRequest: Readonly<KernelV4RevocationSigningRequest>;
  try {
    signingRequest = parseKernelV4RevocationSigningRequest(
      await prepare(Object.freeze({ request: source.request, artifact: source.artifact, chainId })),
    );
  } catch {
    return relayFailure("relay_request_invalid", "revocation preparation failed");
  }
  if (
    signingRequest.chainId !== chainId ||
    hashPermissionRequest(signingRequest.permissionRequest) !==
      hashPermissionRequest(source.request)
  )
    return relayFailure(
      "relay_request_invalid",
      "prepared revocation changed its permission or chain",
    );
  const createdAt = relayNow(clock);
  const expiresAt = timestamp(
    createdAt + requestTtlMs,
    "revocation expiry",
    "relay_request_invalid",
  );
  const record: RevocationRequestRecord = Object.freeze({
    version: OAATH_REVOCATION_REQUEST_RECORD_VERSION,
    operationId: REVOCATION_OPERATION_PREFIX + randomIdentifier(),
    ...source.owner,
    createdAt,
    expiresAt,
    signingRequest,
  });
  await withRelayTransaction(store, async (transaction) => {
    if (!(await transaction.insertRevocationRequest(record)))
      return relayFailure("relay_internal", "revocation operation ID already exists");
  });
  return Object.freeze({ operationId: record.operationId, expiresAt });
}

interface OwnerRevocationInput {
  readonly store: RelayStore;
  readonly clock: RelayClock;
  readonly caller: RelayCaller;
  readonly operationId: string;
}
async function readOwnerState(transaction: RelayTransaction, input: OwnerRevocationInput) {
  if (input.caller.role !== "owner")
    return relayFailure("relay_forbidden", "caller may not decide");
  const request = await transaction.lockRevocationRequest(input.operationId);
  if (!request) return relayFailure("relay_not_found", "revocation request is absent");
  if (request.ownerSubject !== input.caller.subject)
    return relayFailure("relay_forbidden", "revocation belongs to another owner");
  const decision = await transaction.lockRevocationDecision(input.operationId);
  if (
    decision &&
    (decision.decidedAt < request.createdAt || decision.decidedAt > request.expiresAt)
  )
    return relayFailure(
      "relay_record_unreadable",
      "revocation decision time contradicts its request",
    );
  return { request, decision };
}
function requirePending(request: RevocationRequestRecord, clock: RelayClock) {
  if (relayNow(clock) > request.expiresAt)
    return relayFailure("relay_expired", "revocation request expired");
}
export async function fetchOwnerPhoneRevocation(input: OwnerRevocationInput) {
  const { request, decision } = await withRelayTransaction(input.store, (transaction) =>
    readOwnerState(transaction, input),
  );
  if (decision) return relayFailure("relay_already_decided", "revocation is already decided");
  requirePending(request, input.clock);
  return projectOwnerPhoneRevocation({
    operationId: request.operationId,
    ownerSubject: request.ownerSubject,
    expiresAt: request.expiresAt,
    request: request.signingRequest,
  });
}
function answer(
  decision: RevocationDecisionRecord,
  settlement: "decided" | "replayed",
): OwnerPhoneRevocationDecision {
  return Object.freeze({
    version: "oaath.native-revocation-decision/v1",
    operationId: decision.operationId,
    outcome: decision.outcome,
    decidedAt: decision.decidedAt,
    settlement,
  });
}
export async function submitOwnerPhoneRevocationDecision(
  input: OwnerRevocationInput & {
    readonly kms: RelayKms;
    readonly command: AuthorizationDecisionCommand;
  },
): Promise<OwnerPhoneRevocationDecision> {
  const initial = await withRelayTransaction(input.store, (transaction) =>
    readOwnerState(transaction, input),
  );
  if (initial.decision) return answer(initial.decision, "replayed");
  requirePending(initial.request, input.clock);
  const artifactRef =
    input.command.outcome === "approved"
      ? await sealArtifact(
          input.kms,
          verifyKernelV4RevocationOwnerSigningArtifact(
            initial.request.signingRequest,
            input.command.artifact,
          ),
        )
      : null;
  return withRelayTransaction(input.store, async (transaction) => {
    const { request, decision } = await readOwnerState(transaction, input);
    if (decision) return answer(decision, "replayed");
    requirePending(request, input.clock);
    const decidedAt = relayNow(input.clock);
    if (decidedAt < request.createdAt || decidedAt > request.expiresAt)
      return relayFailure("relay_expired", "decision is outside the request window");
    const record: RevocationDecisionRecord = Object.freeze({
      version: OAATH_REVOCATION_DECISION_RECORD_VERSION,
      operationId: request.operationId,
      outcome: input.command.outcome,
      decidedAt,
      artifactRef,
    });
    if (!(await transaction.insertRevocationDecision(record)))
      return relayFailure("relay_state_ambiguous", "revocation decision insertion did not settle");
    return answer(record, "decided");
  });
}
