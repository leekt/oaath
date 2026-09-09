/** Composes durable approved phone custody with the existing SDK execution owners. */
import { parseOwnerSigningArtifact } from "@oaath/protocol";
import {
  createOperationObserver,
  createOperationRunner,
  type OperationObserveResult,
  type OperationObserverCapabilities,
  type OperationStartResult,
  OperationStore,
  type OperationStoreAdapter,
} from "@oaath/sdk/advanced";
import { type PreparedUserOperation, restoreKernelPhoneRevocation } from "@oaath/sdk/kernel";
import { openArtifact } from "../artifact/encrypt.js";
import { type RelayClock, relayNow } from "../clock.js";
import { relayFailure } from "../relay/errors.js";
import type { RelayKms } from "../security/kms.js";
import { type RelayStore, withRelayTransaction } from "../store/interface.js";
import { readRevocationState } from "./service.js";

export interface OwnerPhoneRevocationExecutorInput {
  readonly store: RelayStore;
  readonly kms: RelayKms;
  readonly clock: RelayClock;
  readonly operationId: string;
  readonly operations: OperationStoreAdapter;
  readonly observation: OperationObserverCapabilities;
  /**
   * Opens a session for this exact prepared operation and verified root signature.
   * Opening must not send. Return { submit(): Promise<{ userOperationHash }>, close() }.
   * Both opening and submit happen only after durable submission_attempted.
   */
  readonly submission: Readonly<{
    openSubmission(
      prepared: Readonly<PreparedUserOperation>,
      signature: `0x${string}`,
    ): Promise<unknown>;
    close(): Promise<void>;
  }>;
}

/**
 * Deployment execution capability, not a client/phone HTTP route. A terminal
 * approved decision is custody; the existing Operation journal owns execution.
 * Reload reconstructs exact bytes without quoting or preparing on chain. The
 * journal is read before KMS/submission access. An attempted or terminal hash
 * never opens another session, even after consent expiry. Observe reads only
 * chain evidence and retains uncertainty. Close delegates retryable resource
 * cleanup to the runner; the deployment owns relay store, pool and KMS lifetime.
 */
export interface OwnerPhoneRevocationExecutor {
  readonly operationId: string;
  readonly userOperationHash: `0x${string}`;
  start(timeoutMs: number): Promise<OperationStartResult>;
  observe(timeoutMs: number): Promise<OperationObserveResult>;
  close(): Promise<void>;
}
export async function createOwnerPhoneRevocationExecutor(
  input: OwnerPhoneRevocationExecutorInput,
): Promise<Readonly<OwnerPhoneRevocationExecutor>> {
  const { store, kms, clock, operationId, operations, observation, submission } = input;
  const { request, decision } = await withRelayTransaction(store, (transaction) =>
    readRevocationState(transaction, operationId),
  );
  if (decision?.outcome !== "approved" || decision.artifactRef === null)
    return relayFailure("relay_request_invalid", "revocation has no approved custody");
  const artifactRef = decision.artifactRef;
  const restored = restoreKernelPhoneRevocation(request.signingRequest);
  const prepared = restored.prepared;
  const key = Object.freeze({
    grantId: prepared.grantId,
    chainId: prepared.chainId,
    kind: "revocation" as const,
  });
  const journal = new OperationStore(operations);
  const noEffect = async () => undefined;
  const runner = createOperationRunner({
    terminalBehavior: "reuse_same_kind",
    requestHash: null,
    store: journal,
    observer: createOperationObserver(observation),
    preparation: {
      prepare: async () => prepared,
      reserveOperation: noEffect,
      releaseOperationReservation: noEffect,
      authorizeOperation: async () => {
        if (relayNow(clock) > request.expiresAt)
          return relayFailure("relay_expired", "revocation consent expired before submission");
      },
      abandonOperation: noEffect,
      confirmOperationPublished: noEffect,
      close: noEffect,
    },
    submission: {
      async openSubmission(snapshot: PreparedUserOperation) {
        const artifact = parseOwnerSigningArtifact(
          JSON.parse(await openArtifact(kms, artifactRef)),
        );
        const signature = await restored.complete(artifact);
        return submission.openSubmission(snapshot, signature);
      },
      close: () => submission.close(),
    },
  });
  function runInput(timeoutMs: number) {
    const now = Math.floor(relayNow(clock) / 1000);
    return {
      kind: "revocation",
      key,
      expectedUserOperationHash: prepared.userOperationHash,
      preparedAt: now,
      attemptedAt: now,
      submittedAt: now,
      observedAt: now,
      timeoutMs,
    };
  }
  return Object.freeze({
    operationId,
    userOperationHash: prepared.userOperationHash,
    async start(timeoutMs: number) {
      const existing = await journal.getExact(key, prepared.userOperationHash);
      if (existing && existing.value.state !== "prepared")
        return Object.freeze({ status: "started" as const, record: existing });
      if (relayNow(clock) > request.expiresAt)
        return relayFailure("relay_expired", "revocation consent expired before submission");
      return runner.resumePreparedOperation(runInput(timeoutMs));
    },
    observe: (timeoutMs: number) => runner.observeOperation(runInput(timeoutMs)),
    close: () => runner.close(),
  });
}
