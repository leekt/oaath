/**
 * Authoritative approve/reject transition.
 *
 * ```text
 * state and owner        the decision record owns "decided"; the request record
 *                        never mutates
 * persisted evidence     the immutable requestedScope is reclassified from the
 *                        durable request before every approval attempt
 * resource occupied?     a refused approval occupies nothing and performs no KMS
 *                        sealing; a rejection occupies only its decision row
 * retry positively safe? refused approval is read-only; a terminal outcome is
 *                        replayed by the native saga and rejected by this owner
 * transitions            permission or verified Kernel owner signing:
 *                        undecided -> approved | rejected;
 *                        every reject-only scope: undecided -> rejected once
 * terminal               both outcomes; a second decide fails relay_already_decided
 * crash/reload           the decision, the code, and the sealed artifact commit in
 *                        one transaction on the row-locked request, so a crash
 *                        leaves the request undecided and nothing released
 * cleanup owner          the relay transaction; refused approvals allocate nothing
 * ```
 *
 * Subject binding: the authoritative subject is recovered from the stored
 * authorization request by `requestId` and compared against the authenticated
 * owner. No wire field names the subject. A decision envelope that carries a
 * subject identifier is rejected as an unknown field by exact capture, because a
 * field that only *names* a subject is not cryptographically bound to it and can
 * never decide authority.
 *
 * @author taek <leekt216@gmail.com>
 */

import { sealArtifact } from "../artifact/encrypt.js";
import { type RelayClock, relayNow } from "../clock.js";
import { relayFailure } from "../relay/errors.js";
import type { RelayCaller } from "../security/authentication.js";
import type { RelayKms } from "../security/kms.js";
import type { RelayStore } from "../store/interface.js";
import { withRelayTransaction } from "../store/interface.js";
import {
  OAATH_AUTHORIZATION_CODE_RECORD_VERSION,
  OAATH_AUTHORIZATION_DECISION_RECORD_VERSION,
  OAATH_ENCRYPTED_ARTIFACT_RECORD_VERSION,
} from "../store/records.js";
import { randomIdentifier, sha256Base64Url } from "./challenge.js";
import { verifyKernelV4ReplayableInstallOwnerSigningArtifact } from "./owner-signing.js";
import { fetchAuthorizationRequest } from "./request.js";
import { classifyStoredAuthorizationScope } from "./scope.js";

export type AuthorizationDecisionCommand =
  /** The owner approves and hands over the artifact the client will claim once. */
  Readonly<{ outcome: "approved"; artifact: string }> | Readonly<{ outcome: "rejected" }>;

export interface SubmitAuthorizationDecisionInput {
  readonly store: RelayStore;
  readonly clock: RelayClock;
  readonly kms: RelayKms;
  /** Authenticated `owner` caller; only the bound subject may decide. */
  readonly caller: RelayCaller;
  readonly requestId: string;
  readonly command: AuthorizationDecisionCommand;
  readonly codeTtlMs: number;
}

export type SubmittedAuthorizationDecision =
  | Readonly<{
      outcome: "approved";
      decidedAt: number;
      /** Released exactly once, here. Only its SHA-256 is stored. */
      code: string;
      artifactId: string;
      redirectUri: string;
      codeExpiresAt: number;
    }>
  | Readonly<{ outcome: "rejected"; decidedAt: number }>;

export async function submitAuthorizationDecision(
  input: SubmitAuthorizationDecisionInput,
): Promise<SubmittedAuthorizationDecision> {
  const decidedAt = relayNow(input.clock);
  let approvedArtifact: string | undefined;

  // Approval is the artifact-creating transition, so the shared decision owner
  // admits it only for an exact scope this server currently permits to release.
  // Refusal happens before KMS sealing or any durable decision/code/artifact.
  if (input.command.outcome === "approved") {
    const state = await fetchAuthorizationRequest({
      store: input.store,
      clock: input.clock,
      caller: input.caller,
      requestId: input.requestId,
    });
    // Preserve the transaction owner's existing precedence: the native saga
    // must recover an earlier terminal outcome without reclassifying its scope.
    if (state.decision !== null) {
      return relayFailure("relay_already_decided", "authorization request is already decided");
    }
    if (state.expired) {
      return relayFailure("relay_expired", "authorization request expired");
    }
    const scope = classifyStoredAuthorizationScope(state.requestedScope, state.requestId);
    if (scope.kind === "permission-request") {
      approvedArtifact = input.command.artifact;
    } else if (scope.kind === "kernel-owner-signing-request") {
      approvedArtifact = verifyKernelV4ReplayableInstallOwnerSigningArtifact(
        scope.request,
        input.command.artifact,
      );
    } else {
      return relayFailure("relay_request_invalid", "the authorization scope is reject-only");
    }
  }

  // Seal before the transaction: the store only ever receives references, and
  // an uncommitted decision leaves nothing but unreferenced ciphertexts. The
  // code is sealed too so the authenticated client can pick it up later; PKCE
  // still guards its consumption.
  let approved:
    | Readonly<{ code: string; artifactId: string; ciphertextRef: string; codeRef: string }>
    | undefined;
  if (input.command.outcome === "approved") {
    if (approvedArtifact === undefined) {
      return relayFailure("relay_internal", "approved artifact was not authorized");
    }
    const code = randomIdentifier();
    approved = Object.freeze({
      code,
      artifactId: randomIdentifier(),
      ciphertextRef: await sealArtifact(input.kms, approvedArtifact),
      codeRef: await sealArtifact(input.kms, code),
    });
  }
  const codeHash = approved ? await sha256Base64Url(approved.code) : undefined;
  const decision = Object.freeze({
    version: OAATH_AUTHORIZATION_DECISION_RECORD_VERSION,
    requestId: input.requestId,
    outcome: input.command.outcome,
    decidedAt,
    codeRef: approved?.codeRef ?? null,
    codeExpiresAt: approved ? decidedAt + input.codeTtlMs : null,
  } as const);

  const redirectUri = await withRelayTransaction(input.store, async (transaction) => {
    const request = await transaction.lockAuthorizationRequest(input.requestId);
    // The stored request owns the subject. A mismatch is reported as absence so
    // the endpoint is not an existence oracle for another subject's request.
    if (!request || request.subject !== input.caller.subject) {
      return relayFailure("relay_not_found", "authorization request does not exist");
    }
    if (await transaction.lockAuthorizationDecision(input.requestId)) {
      return relayFailure("relay_already_decided", "authorization request is already decided");
    }
    if (decidedAt >= request.expiresAt) {
      return relayFailure("relay_expired", "authorization request expired");
    }
    if (!(await transaction.insertAuthorizationDecision(decision))) {
      return relayFailure("relay_already_decided", "authorization request is already decided");
    }
    if (approved && codeHash !== undefined) {
      const inserted =
        (await transaction.insertAuthorizationCode(
          Object.freeze({
            version: OAATH_AUTHORIZATION_CODE_RECORD_VERSION,
            codeHash,
            requestId: request.requestId,
            clientId: request.clientId,
            redirectUri: request.redirectUri,
            codeChallenge: request.codeChallenge,
            artifactId: approved.artifactId,
            createdAt: decidedAt,
            expiresAt: decidedAt + input.codeTtlMs,
            consumedAt: null,
          }),
        )) &&
        (await transaction.insertEncryptedArtifact(
          Object.freeze({
            version: OAATH_ENCRYPTED_ARTIFACT_RECORD_VERSION,
            artifactId: approved.artifactId,
            requestId: request.requestId,
            clientId: request.clientId,
            ciphertextRef: approved.ciphertextRef,
            createdAt: decidedAt,
            claimedAt: null,
          }),
        ));
      if (!inserted) {
        return relayFailure("relay_internal", "released identifier is not unique");
      }
    }
    return request.redirectUri;
  });

  if (approved && codeHash !== undefined) {
    return Object.freeze({
      outcome: "approved",
      decidedAt,
      code: approved.code,
      artifactId: approved.artifactId,
      redirectUri,
      codeExpiresAt: decidedAt + input.codeTtlMs,
    });
  }
  return Object.freeze({ outcome: "rejected", decidedAt });
}
