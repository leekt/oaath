/**
 * One-time encrypted artifact release, and the proof that plaintext never
 * reaches the store.
 *
 * @author taek <leekt216@gmail.com>
 */

import { describe, expect, it } from "vitest";
import type { RelayStore, RelayTransaction } from "../src/store/interface.js";
import { createMemoryRelayStore } from "../src/store/memory.js";
import {
  approve,
  claim,
  consume,
  createHarness,
  createRequest,
  expectFailure,
  expectOk,
  OTHER_CLIENT_TOKEN,
} from "./support.js";

const SECRET = '{"sessionKey":"never-in-the-store"}';

/** Records every value handed to the store so a test can prove what was written. */
function createRecordingStore(): { store: RelayStore; written: unknown[] } {
  const inner = createMemoryRelayStore();
  const written: unknown[] = [];
  const store: RelayStore = {
    async begin(): Promise<RelayTransaction> {
      const transaction = await inner.begin();
      return {
        ...transaction,
        insertAuthorizationRequest(record) {
          written.push(record);
          return transaction.insertAuthorizationRequest(record);
        },
        insertAuthorizationDecision(record) {
          written.push(record);
          return transaction.insertAuthorizationDecision(record);
        },
        insertAuthorizationCode(record) {
          written.push(record);
          return transaction.insertAuthorizationCode(record);
        },
        insertEncryptedArtifact(record) {
          written.push(record);
          return transaction.insertEncryptedArtifact(record);
        },
      };
    },
    close: () => inner.close(),
  };
  return { store, written };
}

describe("encrypted artifact claim", () => {
  it("releases the artifact exactly once", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    const decision = await approve(harness, created.requestId, SECRET);
    await expectOk(await consume(harness, decision.code), 200);

    const claimed = await expectOk<{ artifact: string }>(
      await claim(harness, decision.artifactId),
      200,
    );
    expect(claimed.artifact).toBe(SECRET);
    await expectFailure(
      await claim(harness, decision.artifactId),
      "relay_artifact_already_claimed",
    );
  });

  it("releases once under concurrent claims", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    const decision = await approve(harness, created.requestId, SECRET);
    await expectOk(await consume(harness, decision.code), 200);

    const responses = await Promise.all([
      claim(harness, decision.artifactId),
      claim(harness, decision.artifactId),
    ]);
    expect(responses.map((response) => response.status).sort()).toEqual([200, 409]);
  });

  it("hides an artifact bound to another client, and an unknown one", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    const decision = await approve(harness, created.requestId, SECRET);

    await expectFailure(
      await claim(harness, decision.artifactId, OTHER_CLIENT_TOKEN),
      "relay_not_found",
    );
    await expectFailure(await claim(harness, "unknown-artifact"), "relay_not_found");
    // The bound client can still claim exactly once.
    await expectOk(await claim(harness, decision.artifactId), 200);
  });

  it("burns the artifact when the KMS cannot open it after the claim commits", async () => {
    let openable = true;
    const harness = createHarness({
      kms: {
        async encrypt(plaintext: string) {
          return `ref:${btoa(plaintext)}`;
        },
        async decrypt(reference: string) {
          if (!openable) throw new Error("kms down");
          return atob(reference.slice("ref:".length));
        },
      },
    });
    const created = await createRequest(harness);
    const decision = await approve(harness, created.requestId, SECRET);

    openable = false;
    await expectFailure(await claim(harness, decision.artifactId), "relay_kms_unavailable");
    openable = true;
    // The claim committed before the KMS was asked, so there is no second release.
    await expectFailure(
      await claim(harness, decision.artifactId),
      "relay_artifact_already_claimed",
    );
  });

  it("rejects a KMS that returns an unusable plaintext", async () => {
    const harness = createHarness({
      kms: {
        async encrypt() {
          return "ref:opaque";
        },
        async decrypt() {
          return { not: "a string" };
        },
      },
    });
    const created = await createRequest(harness);
    const decision = await approve(harness, created.requestId, SECRET);
    await expectFailure(await claim(harness, decision.artifactId), "relay_kms_unavailable");
  });

  it("never hands plaintext to the store", async () => {
    const recording = createRecordingStore();
    const harness = createHarness({}, recording.store);
    const created = await createRequest(harness);
    const decision = await approve(harness, created.requestId, SECRET);
    await expectOk(await consume(harness, decision.code), 200);
    await expectOk(await claim(harness, decision.artifactId), 200);

    const serialized = JSON.stringify(recording.written);
    expect(serialized).not.toContain(SECRET);
    expect(serialized).not.toContain("never-in-the-store");
    // The released code is only ever stored as its digest.
    expect(serialized).not.toContain(decision.code);
    expect(recording.written).toHaveLength(4);
  });
});
