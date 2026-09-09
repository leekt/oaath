/**
 * Owner revocation custody: absent -> pending -> approved | rejected once.
 * The immutable request and terminal decision are the only persisted evidence.
 * Approval occupies this operation ID; it proves custody, never submission or
 * onchain completion. No execution lane is acquired here. A decision retry reads
 * the stored outcome before expiry or artifact handling. An ambiguous enqueue
 * response is recovered by looking up the original grant/chain; it never
 * authorizes a blind insertion. Only expired undecided custody may be replaced.
 * Enqueue recovery needs only the store; signing custody needs KMS. There
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
  readonly directory: Pick<ServiceDirectory, "resolveRevocationOwner">;
  /** Deployment-authenticated original application/member. */
  readonly caller: RelayCaller;
  readonly grantId: string;
  readonly chainId: number;
  readonly requestTtlMs: number;
  /**
   * Deployment uses prepareKernelPhoneRevocation to verify the retained Kernel
   * capability, read target-chain state, and choose effect/root nonce/gas.
   * Receives the retained approval plaintext; never log or expose it to clients.
   * Preparation must not reserve a nonce or execution lane; concurrent
   * preparations may lose admission.
   * Returns the SDK signingRequest only. Must not sign or submit an operation.
   */
  readonly prepare: (
    input: Readonly<{ request: Readonly<PermissionRequest>; artifact: string; chainId: number }>,
  ) => Promise<unknown>;
}

export interface OwnerPhoneRevocationStatus {
  readonly grantId: string;
  readonly chainId: number;
  readonly operationId: string;
  /** Relay timestamp in milliseconds. */
  readonly expiresAt: number;
  /** Custody status only, never submission or grant revocation completion. */
  readonly status: "pending" | "approved" | "rejected" | "expired";
}

type ClientRevocationInput = Pick<
  RequestOwnerPhoneRevocationInput,
  "store" | "clock" | "caller" | "grantId" | "chainId"
>;

async function readClientState(transaction: RelayTransaction, input: ClientRevocationInput) {
  if (input.caller.role !== "client")
    return relayFailure("relay_forbidden", "only the originating client may request revocation");
  const source = await transaction.lockAuthorizationRequest(input.grantId);
  if (
    !source ||
    source.clientId !== input.caller.clientId ||
    source.subject !== input.caller.subject
  )
    return relayFailure("relay_forbidden", "permission is not owned by this caller");
  const request = await transaction.lockLatestRevocationRequest(input.grantId, input.chainId);
  const current = request ? { request, decision: await readDecision(transaction, request) } : null;
  return { source, current };
}

function statusOf(
  state: { request: RevocationRequestRecord; decision: RevocationDecisionRecord | undefined },
  clock: RelayClock,
): Readonly<OwnerPhoneRevocationStatus> {
  return Object.freeze({
    grantId: state.request.signingRequest.permissionRequest.requestId,
    chainId: state.request.signingRequest.chainId,
    operationId: state.request.operationId,
    expiresAt: state.request.expiresAt,
    status:
      state.decision?.outcome ??
      (relayNow(clock) > state.request.expiresAt ? "expired" : "pending"),
  });
}
function reusable(
  state: Awaited<ReturnType<typeof readClientState>>["current"],
  clock: RelayClock,
) {
  return (
    state !== null && (state.decision !== undefined || relayNow(clock) <= state.request.expiresAt)
  );
}

/** Authenticated metadata lookup. It never prepares, opens KMS custody or submits. */
export async function fetchClientPhoneRevocation(
  input: ClientRevocationInput,
): Promise<Readonly<OwnerPhoneRevocationStatus>> {
  return withRelayTransaction(input.store, async (transaction) => {
    const { current } = await readClientState(transaction, input);
    if (!current) return relayFailure("relay_not_found", "revocation request is absent");
    return statusOf(current, input.clock);
  });
}

/**
 * Returns the current grant/chain request before touching preparation or KMS.
 * Only positively expired, undecided custody may be replaced. Approved custody
 * remains immutable even after expiry: operation evidence owns any replacement.
 * Pure preparation runs outside the transaction; final admission locks the
 * original grant again so concurrent callers share the winner's exact request.
 */
export async function requestOwnerPhoneRevocation(
  input: RequestOwnerPhoneRevocationInput,
): Promise<Readonly<OwnerPhoneRevocationStatus & { created: boolean }>> {
  const { store, clock, kms, directory, caller, grantId, chainId, requestTtlMs, prepare } = input;
  if (
    !Number.isSafeInteger(chainId) ||
    chainId < 1 ||
    !Number.isSafeInteger(requestTtlMs) ||
    requestTtlMs < 1
  )
    return relayFailure("relay_request_invalid", "revocation chain or TTL is invalid");
  const source = await withRelayTransaction(store, async (transaction) => {
    const { source: request, current } = await readClientState(transaction, input);
    if (current && reusable(current, clock)) return { retained: statusOf(current, clock) } as const;
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
    return { request: scope.request, artifact: retained.plaintext, owner } as const;
  });
  if ("retained" in source) return Object.freeze({ ...source.retained, created: false });
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
  return withRelayTransaction(store, async (transaction) => {
    const { current } = await readClientState(transaction, input);
    if (current && reusable(current, clock))
      return Object.freeze({ ...statusOf(current, clock), created: false });
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
    if (!(await transaction.insertRevocationRequest(record)))
      return relayFailure("relay_state_ambiguous", "revocation request insertion did not settle");
    return Object.freeze({
      ...statusOf({ request: record, decision: undefined }, clock),
      created: true,
    });
  });
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
  const state = await readRevocationState(transaction, input.operationId);
  if (state.request.ownerSubject !== input.caller.subject)
    return relayFailure("relay_forbidden", "revocation belongs to another owner");
  return state;
}
/** Shared durable request/decision binding; caller admission belongs to each use case. */
export async function readRevocationState(transaction: RelayTransaction, operationId: string) {
  const request = await transaction.lockRevocationRequest(operationId);
  if (!request) return relayFailure("relay_not_found", "revocation request is absent");
  return { request, decision: await readDecision(transaction, request) };
}
async function readDecision(transaction: RelayTransaction, request: RevocationRequestRecord) {
  const decision = await transaction.lockRevocationDecision(request.operationId);
  if (
    decision &&
    (decision.decidedAt < request.createdAt || decision.decidedAt > request.expiresAt)
  )
    return relayFailure(
      "relay_record_unreadable",
      "revocation decision time contradicts its request",
    );
  return decision;
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
