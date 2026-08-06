/**
 * Durable-record capture and transaction discipline.
 *
 * An unreadable, extra-bearing, old-version, or contradictory record fails
 * closed. A settled transaction can never be reused.
 *
 * @author taek <leekt216@gmail.com>
 */

import { describe, expect, it } from "vitest";
import { OaathRelayError, type RelayErrorCode } from "../src/relay/errors.js";
import { withRelayTransaction } from "../src/store/interface.js";
import { createMemoryRelayStore } from "../src/store/memory.js";
import {
  OAATH_AUTHORIZATION_CODE_RECORD_VERSION,
  OAATH_AUTHORIZATION_DECISION_RECORD_VERSION,
  OAATH_AUTHORIZATION_REQUEST_RECORD_VERSION,
  OAATH_ENCRYPTED_ARTIFACT_RECORD_VERSION,
  parseAuthorizationCodeRecord,
  parseAuthorizationDecisionRecord,
  parseAuthorizationRequestRecord,
  parseEncryptedArtifactRecord,
} from "../src/store/records.js";

const REQUEST = Object.freeze({
  version: OAATH_AUTHORIZATION_REQUEST_RECORD_VERSION,
  requestId: "request-1",
  clientId: "client-a",
  subject: "subject-1",
  redirectUri: "https://app.example/callback",
  codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  requestedScope: "{}",
  createdAt: 1_700_000_000_000,
  expiresAt: 1_700_000_300_000,
});

const CODE = Object.freeze({
  version: OAATH_AUTHORIZATION_CODE_RECORD_VERSION,
  codeHash: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  requestId: "request-1",
  clientId: "client-a",
  redirectUri: "https://app.example/callback",
  codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  artifactId: "artifact-1",
  createdAt: 1_700_000_000_000,
  expiresAt: 1_700_000_060_000,
  consumedAt: null,
});

const ARTIFACT = Object.freeze({
  version: OAATH_ENCRYPTED_ARTIFACT_RECORD_VERSION,
  artifactId: "artifact-1",
  requestId: "request-1",
  clientId: "client-a",
  ciphertextRef: "kms:opaque",
  createdAt: 1_700_000_000_000,
  claimedAt: null,
});

const DECISION = Object.freeze({
  version: OAATH_AUTHORIZATION_DECISION_RECORD_VERSION,
  requestId: "request-1",
  outcome: "approved",
  decidedAt: 1_700_000_000_000,
  codeRef: "sealed:code-1",
  codeExpiresAt: 1_700_000_060_000,
});

function expectFailureCode(run: () => unknown, code: RelayErrorCode): void {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathRelayError);
    if (error instanceof OaathRelayError) expect(error.code).toBe(code);
    return;
  }
  throw new Error("expected a relay failure");
}

describe("durable record capture", () => {
  it("accepts the exact current version", () => {
    expect(parseAuthorizationRequestRecord({ ...REQUEST })).toEqual(REQUEST);
    expect(parseAuthorizationDecisionRecord({ ...DECISION })).toEqual(DECISION);
    expect(parseAuthorizationCodeRecord({ ...CODE })).toEqual(CODE);
    expect(parseAuthorizationCodeRecord({ ...CODE, consumedAt: CODE.createdAt })).toMatchObject({
      consumedAt: CODE.createdAt,
    });
    expect(parseEncryptedArtifactRecord({ ...ARTIFACT })).toEqual(ARTIFACT);
    expect(
      parseEncryptedArtifactRecord({ ...ARTIFACT, claimedAt: ARTIFACT.createdAt }),
    ).toMatchObject({ claimedAt: ARTIFACT.createdAt });
  });

  it("rejects an old, extra-bearing, missing, or malformed record", () => {
    const rejected: readonly unknown[] = [
      undefined,
      null,
      "record",
      [REQUEST],
      { ...REQUEST, version: "oaath.authorization-request-record/v0" },
      { ...REQUEST, extra: 1 },
      { ...REQUEST, requestId: undefined },
      { ...REQUEST, requestId: "not canonical" },
      { ...REQUEST, requestId: "" },
      { ...REQUEST, requestId: "a".repeat(257) },
      { ...REQUEST, subject: 7 },
      { ...REQUEST, redirectUri: `https://app.example/${"a".repeat(2048)}` },
      { ...REQUEST, requestedScope: "a".repeat(8193) },
      { ...REQUEST, createdAt: -1 },
      { ...REQUEST, createdAt: 1.5 },
      { ...REQUEST, createdAt: "1700000000000" },
      { ...REQUEST, expiresAt: Number.MAX_SAFE_INTEGER + 2 },
      Object.assign(Object.create({ inherited: true }), REQUEST),
      Object.defineProperty({ ...REQUEST }, "requestId", { value: "x", enumerable: false }),
      Object.defineProperty({ ...REQUEST }, "clientId", { get: () => "client-a" }),
    ];
    for (const value of rejected) {
      expectFailureCode(() => parseAuthorizationRequestRecord(value), "relay_record_unreadable");
    }
  });

  it("rejects an unsupported decision outcome", () => {
    expectFailureCode(
      () => parseAuthorizationDecisionRecord({ ...DECISION, outcome: "maybe" }),
      "relay_record_unreadable",
    );
  });

  it("rejects a contradictory one-shot timestamp", () => {
    expectFailureCode(
      () => parseAuthorizationCodeRecord({ ...CODE, consumedAt: -1 }),
      "relay_record_unreadable",
    );
    expectFailureCode(
      () => parseEncryptedArtifactRecord({ ...ARTIFACT, claimedAt: "now" }),
      "relay_record_unreadable",
    );
    expectFailureCode(
      () => parseEncryptedArtifactRecord({ ...ARTIFACT, ciphertextRef: "" }),
      "relay_record_unreadable",
    );
  });

  it("rejects a record the store itself cannot read back", async () => {
    const store = createMemoryRelayStore();
    const transaction = await store.begin();
    // A record written outside the parser must still fail closed on read.
    await transaction.insertAuthorizationRequest({
      ...REQUEST,
      version: "oaath.authorization-request-record/v0",
    } as unknown as typeof REQUEST);
    await expect(transaction.lockAuthorizationRequest(REQUEST.requestId)).rejects.toThrowError(
      OaathRelayError,
    );
    await transaction.rollback();
  });
});

describe("relay transaction discipline", () => {
  it("refuses to reuse a settled transaction", async () => {
    const store = createMemoryRelayStore();
    const transaction = await store.begin();
    await transaction.commit();

    await expect(transaction.lockAuthorizationRequest("request-1")).rejects.toThrowError(
      OaathRelayError,
    );
    await expect(transaction.insertAuthorizationRequest(REQUEST)).rejects.toThrowError(
      OaathRelayError,
    );
    await expect(transaction.commit()).rejects.toThrowError(OaathRelayError);
    // Rollback after settling is a no-op, never a second decision.
    await expect(transaction.rollback()).resolves.toBeUndefined();
  });

  it("discards a rolled-back write", async () => {
    const store = createMemoryRelayStore();
    await expect(
      withRelayTransaction(store, async (transaction) => {
        await transaction.insertAuthorizationRequest(REQUEST);
        throw new OaathRelayError("relay_internal", "abandon this transition");
      }),
    ).rejects.toThrowError(OaathRelayError);

    const found = await withRelayTransaction(store, (transaction) =>
      transaction.lockAuthorizationRequest(REQUEST.requestId),
    );
    expect(found).toBeUndefined();
  });

  it("serializes transactions and refuses a closed store", async () => {
    const store = createMemoryRelayStore();
    const first = await store.begin();
    const secondPending = store.begin();
    let secondStarted = false;
    void secondPending.then(() => {
      secondStarted = true;
    });
    await Promise.resolve();
    expect(secondStarted).toBe(false);

    expect(await first.insertAuthorizationRequest(REQUEST)).toBe(true);
    await first.commit();
    const second = await secondPending;
    expect(await second.insertAuthorizationRequest(REQUEST)).toBe(false);
    await second.rollback();

    await store.close();
    await expect(store.begin()).rejects.toThrowError(OaathRelayError);
  });
});
