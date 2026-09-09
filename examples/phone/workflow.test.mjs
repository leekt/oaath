import assert from "node:assert/strict";
import test from "node:test";
import { p256 } from "@noble/curves/nist.js";
import {
  hashCanonicalEip712TypedData,
  hashOwnerSigningRequest,
  serializeOwnerSigningArtifact,
} from "@oaath/protocol";
import { createOAAth } from "@oaath/sdk";
import { KERNEL_V4_ENTRY_POINT_V07 } from "@oaath/sdk/kernel";
import { hexToBytes, toHex } from "viem";
import { startPhoneService } from "./service.mjs";

for (const workspaceKind of ["personal", "team"])
  test(`${workspaceKind} phone service runs and revokes across configured chains`, async () => {
    const used = workspaceKind === "team";
    const service = await startPhoneService({ simulate: true, workspaceKind });
    const secret = p256.utils.randomPrivateKey();
    let oaath;
    let connection;
    let teammate;
    try {
      assert.equal(service.chains?.length, 2, "one composition must serve both configured chains");
      const [firstChain, secondChain] = service.chains;
      const chainId = firstChain.capability.chainId;
      const secondChainId = secondChain.capability.chainId;
      const sends = () => service.chains.reduce((count, chain) => count + chain.sends.length, 0);
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
      assert.equal(paired.version, "oaath.phone-pairing/v1");
      assert.deepEqual(
        paired.chains,
        service.chains.map((chain) => ({
          chainId: chain.capability.chainId,
          entryPoint: KERNEL_V4_ENTRY_POINT_V07,
        })),
      );
      assert.deepEqual(Object.keys(paired), ["version", "deviceCredential", "account", "chains"]);
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
      const clientFetchFor = (token) => async (request) => {
        const beforeConsent = sends();
        try {
          const headers = new Headers(request.headers);
          headers.set("authorization", `Bearer ${token}`);
          const response = await fetch(new Request(request, { headers }));
          if (
            request.method === "POST" &&
            new URL(request.url).pathname === "/authorization/requests" &&
            response.status === 201
          ) {
            const { requestId } = await response.clone().json();
            const consent = await (await ownerFetch(`/native/projections/${requestId}`)).json();
            assert.equal(consent.scope.kind, "permission-request");
            assert.equal(consent.scope.context.workspaceId, `${workspaceKind}-1`);
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
            assert.equal(sends(), beforeConsent, "consent cannot submit a job");
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
      const clientFetch = clientFetchFor("demo-client-token");
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
      assert.equal(await grant.account(chainId), paired.account);
      const job = {
        chain: chainId,
        calls: [{ target: service.target, value: "5", data: "0x12345678" }],
      };
      if (used) {
        const first = await grant.sendCalls(job);
        await assert.rejects(grant.sendCalls(job), { code: "oaath_client_state_conflict" });
        assert.equal(firstChain.sends.length, 1);
        const saved = await grant.getOperation({ chain: chainId, id: first.id });
        assert.equal(saved.id, first.id);
        const outcome = await saved.wait();
        assert.equal(outcome.status, "finalized");
        assert.equal(outcome.outcome, "success");
        assert.equal(firstChain.sends.length, 1, "observation cannot resubmit");
        for (let index = 0; index < 2; index += 1) {
          const operation = await grant.sendCalls(job);
          const next = await operation.wait();
          assert.equal(next.status, "finalized");
          assert.equal(next.outcome, "success");
        }
        assert.equal(firstChain.sends.length, 3);
        assert.equal(approvals, 1);
        assert.equal(BigInt(firstChain.sends[2].userOperation.nonce) & ((1n << 64n) - 1n), 1n);
        await assert.rejects(grant.sendCalls(job), { code: "oaath_client_scope_denied" });
        assert.equal(firstChain.sends.length, 3, "the fourth job exceeds the approved bound");
      }
      let teammateGrant;
      if (used) {
        // One approval executes on another configured chain with its own budget.
        const otherJob = await grant.sendCalls({ ...job, chain: secondChainId });
        // Leave the first member's SDK record submitted while another member sends.
        assert.equal(approvals, 1);
        teammate = createOAAth({
          url: service.url,
          origin: service.url,
          fetch: clientFetchFor("demo-teammate-token"),
        });
        const teammateConnection = await teammate.connect();
        assert.equal(teammate.binding.context.workspaceKind, "team");
        assert.notEqual(teammate.binding.subject.userHandle, oaath.binding.subject.userHandle);
        assert.equal(await teammateConnection.resume(), null);
        teammateGrant = await teammateConnection.requestPermission({
          chainScope: "all",
          permissions: [
            { calls: [{ target: service.target, selectors: ["0x12345678"], valueLimit: "5" }] },
          ],
          expiresIn: 1800,
          perChainOperationLimit: 2,
        });
        const ownJob = await teammateGrant.sendCalls({ ...job, chain: secondChainId });
        assert.equal(
          (await ownJob.wait()).outcome,
          "success",
          "another member's jobs cannot consume this grant budget",
        );
        const old = await grant.getOperation({ chain: secondChainId, id: otherJob.id });
        assert.equal(
          (await old.observe()).status,
          "finalized",
          "another member cannot erase the earlier receipt",
        );
      } else {
        const outsider = await fetch(`${service.url}/bootstrap`, {
          headers: { authorization: "Bearer demo-teammate-token" },
        });
        assert.equal(outsider.ok, false, "personal workspace has no second member");
      }
      async function revoke(current, usedChains) {
        const before = service.chains.map((chain) => chain.sends.length);
        await current.revoke();
        assert.equal(current.state, "revoking");
        assert.deepEqual(
          service.chains.map((chain) => chain.sends.length),
          before,
          "consent cannot submit owner work",
        );
        const pending = await (await ownerFetch("/demo/inbox")).json();
        assert.equal(pending.requests.length, 2);
        const projections = await Promise.all(
          pending.requests.map(async ({ operationId }) =>
            (await ownerFetch(`/native/projections/${operationId}`)).json(),
          ),
        );
        projections.sort((left, right) => left.scope.chainId - right.scope.chainId);
        for (const [index, projection] of projections.entries()) {
          const request = projection.scope;
          assert.equal(request.kind, "kernel-revocation");
          assert.equal(request.chainId, service.chains[index].capability.chainId);
          assert.equal(
            request.effect,
            usedChains.has(request.chainId) ? "uninstall-permission" : "invalidate-install",
          );
          assert.equal(request.operation.sender, paired.account);
          const signed = serializeOwnerSigningArtifact({
            version: "oaath.owner-signing-artifact/v1",
            kind: "p256",
            requestHash: request.requestHash,
            signature: toHex(
              p256
                .sign(hexToBytes(request.expectedDigest), secret, { prehash: false, lowS: true })
                .toCompactRawBytes(),
            ),
          });
          const decide = () =>
            ownerFetch(`/native/revocation-decisions/${projection.operationId}`, {
              command: "approve",
              artifact: signed,
            });
          const approved = await decide();
          assert.equal(approved.status, 200);
          assert.equal((await approved.json()).outcome, "approved");
          await service.settle();
          await current.revoke();
          await service.settle();
          assert.equal(
            current.state,
            index === 0 ? "revoking" : "revoked",
            "one chain cannot complete the other chain's obligation",
          );
          assert.equal(
            service.chains[index].sends.at(-1).userOperationHash,
            request.expectedDigest,
          );
          assert.equal((await decide()).status, 200);
          await service.settle(); // A fresh executor reads its retained exact operation.
          assert.equal(
            service.chains[index].sends.length,
            before[index] + 1,
            "replay cannot resubmit",
          );
        }
        assert.equal((await (await ownerFetch("/demo/inbox")).json()).requests.length, 0);
        await assert.rejects(current.sendCalls(job), { code: "oaath_client_grant_inactive" });
      }
      await revoke(grant, new Set(used ? [chainId, secondChainId] : []));
      if (teammateGrant) {
        assert.equal(
          teammateGrant.state,
          "active",
          "another member's revocation cannot revoke this grant",
        );
        const remainingJob = await teammateGrant.sendCalls({ ...job, chain: secondChainId });
        assert.equal(
          (await remainingJob.wait()).outcome,
          "success",
          "another grant's revocation cannot remove this authority or spend its remaining budget",
        );
        await assert.rejects(teammateGrant.sendCalls({ ...job, chain: secondChainId }), {
          code: "oaath_client_scope_denied",
        });
        const ownChainA = await teammateGrant.sendCalls(job);
        assert.equal((await ownChainA.wait()).outcome, "success");
        await revoke(teammateGrant, new Set([chainId, secondChainId]));
      }
    } finally {
      secret.fill(0);
      await connection?.close();
      await oaath?.close();
      await teammate?.close();
      await service.close();
    }
  });
