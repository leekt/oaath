import assert from "node:assert/strict";
import test from "node:test";
import { p256 } from "@noble/curves/nist.js";
import {
  hashCanonicalEip712TypedData,
  hashOwnerSigningRequest,
  serializeOwnerSigningArtifact,
} from "@oaath/protocol";
import { createOAAth } from "@oaath/sdk";
import { hexToBytes, toHex } from "viem";
import { startPhoneService } from "./service.mjs";

test("canonical phone approval executes repeated bounded jobs on a real P-256 Kernel account", async () => {
  const service = await startPhoneService({ simulate: true });
  const secret = p256.utils.randomPrivateKey();
  let oaath;
  let connection;
  try {
    // This is the exact code grammar accepted by the native PairingCode owner.
    assert.match(service.pairingCode, /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{10}$/);
    const pairedResponse = await fetch(`${service.url}/native/pairings`, {
      method: "POST",
      body: JSON.stringify({
        pairingCode: service.pairingCode,
        deviceToken: "00".repeat(32),
        publicKey: toHex(p256.getPublicKey(secret, false).slice(1)),
      }),
    });
    assert.equal(pairedResponse.status, 200, "pairing must enroll the actual account");
    const paired = await pairedResponse.json();
    const ownerFetch = (path, body) =>
      fetch(`${service.url}${path}`, {
        headers: {
          authorization: `Bearer ${paired.deviceCredential}`,
          ...(body ? { "content-type": "application/json" } : {}),
        },
        ...(body ? { method: "POST", body: JSON.stringify(body) } : {}),
      });
    let approvals = 0;
    let phoneFailure;
    const clientFetch = async (request) => {
      try {
        const headers = new Headers(request.headers);
        headers.set("authorization", "Bearer demo-client-token");
        const response = await fetch(new Request(request, { headers }));
        if (
          request.method === "POST" &&
          new URL(request.url).pathname === "/authorization/requests" &&
          response.status === 201
        ) {
          const { requestId } = await response.clone().json();
          const consent = await (await ownerFetch(`/native/projections/${requestId}`)).json();
          assert.equal(consent.scope.kind, "permission-request");
          assert.equal(consent.scope.context.workspaceId, "personal-1");
          assert.equal(consent.scope.context.accountId, "account-1");
          const inbox = await (await ownerFetch("/demo/inbox")).json();
          assert.equal(inbox.requests.length, 1);
          assert.equal(inbox.requests[0].operationId, requestId);
          const signing = await (
            await ownerFetch(`/native/permission-signing/${requestId}`)
          ).json();
          assert.deepEqual({ ...signing, scope: consent.scope }, consent);
          const packet = signing.scope.request;
          assert.equal(packet.signer.account, paired.account);
          assert.equal(hashCanonicalEip712TypedData(packet.typedData), packet.expectedDigest);
          const artifact = (signingKey) =>
            serializeOwnerSigningArtifact({
              version: "oaath.owner-signing-artifact/v1",
              kind: "p256",
              requestHash: hashOwnerSigningRequest(packet),
              signature: toHex(
                p256
                  .sign(hexToBytes(packet.expectedDigest), signingKey, {
                    prehash: false,
                    lowS: true,
                  })
                  .toCompactRawBytes(),
              ),
            });
          const foreign = p256.utils.randomPrivateKey();
          try {
            const refused = await ownerFetch(`/native/decisions/${requestId}`, {
              command: "approve",
              artifact: artifact(foreign),
            });
            assert.equal(refused.ok, false, "an invalid artifact cannot release consent");
          } finally {
            foreign.fill(0);
          }
          assert.equal((await ownerFetch(`/native/projections/${requestId}`)).status, 200);
          assert.equal(service.chain.sends.length, 0, "consent cannot submit a job");
          const approved = await ownerFetch(`/native/decisions/${requestId}`, {
            command: "approve",
            artifact: artifact(secret),
          });
          assert.equal(approved.status, 200, "the canonical phone decision must commit");
          approvals += 1;
          assert.equal((await (await ownerFetch("/demo/inbox")).json()).requests.length, 0);
        }
        return response;
      } catch (error) {
        phoneFailure = error;
        throw error;
      }
    };
    oaath = createOAAth({ url: service.url, origin: service.url, fetch: clientFetch });
    connection = await oaath.connect();
    assert.equal(await connection.resume(), null);
    const grant = await connection
      .requestPermission({
        chainScope: "all",
        permissions: [
          { calls: [{ target: service.target, selectors: ["0x12345678"], valueLimit: "5" }] },
        ],
        expiresIn: 1800,
        perChainOperationLimit: 3,
      })
      .catch((error) => {
        throw phoneFailure ?? error;
      });
    assert.equal(grant.state, "active");
    assert.equal(await grant.account(service.chainId), paired.account);
    const job = {
      chain: service.chainId,
      calls: [{ target: service.target, value: "5", data: "0x12345678" }],
    };
    const first = await grant.sendCalls(job);
    await assert.rejects(grant.sendCalls(job), { code: "oaath_client_state_conflict" });
    assert.equal(service.chain.sends.length, 1);
    const saved = await grant.getOperation({ chain: service.chainId, id: first.id });
    assert.equal(saved.id, first.id);
    const outcome = await saved.wait();
    assert.equal(outcome.status, "finalized");
    assert.equal(outcome.outcome, "success");
    assert.equal(service.chain.sends.length, 1, "observation cannot resubmit");
    for (let index = 0; index < 2; index += 1) {
      const operation = await grant.sendCalls(job);
      const next = await operation.wait();
      assert.equal(next.status, "finalized");
      assert.equal(next.outcome, "success");
    }
    assert.equal(service.chain.sends.length, 3);
    assert.equal(approvals, 1);
    assert.equal(BigInt(service.chain.sends[2].userOperation.nonce) & ((1n << 64n) - 1n), 1n);
    await assert.rejects(grant.sendCalls(job), { code: "oaath_client_scope_denied" });
    assert.equal(service.chain.sends.length, 3, "the fourth job exceeds the approved bound");
  } finally {
    secret.fill(0);
    await connection?.close();
    await oaath?.close();
    await service.close();
  }
});
