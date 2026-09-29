import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createLocalAnvilFixture, openLocalAnvilRecoveryClient } from "../src/anvil.js";
import { softwarePasskey } from "./support-passkey.js";

describe.skipIf(process.env.OAATH_REQUIRE_ANVIL !== "1")("existing v3.3 session fixture", () => {
  it("enables on two chains, recovers without keys, then reuses the installed session", async () => {
    const stateDirectory = await mkdtemp(join(tmpdir(), "oaath-v33-session-"));
    const fixture = await createLocalAnvilFixture({
      chainIds: [143, 480],
      kernelVersion: "0.3.3",
      stateDirectory,
    });
    try {
      const client = await fixture.openClient();
      const connection = await client.connect();
      const grant = await connection.requestPermission({
        chainScope: "all",
        permissions: [
          {
            calls: [{ target: `0x${"44".repeat(20)}`, selectors: ["0x12345678"], valueLimit: "1" }],
          },
        ],
        expiresIn: 3600,
        perChainOperationLimit: 3,
      });
      const account = fixture.recovery?.existingAccount;
      if (!account) throw new Error("fixture account missing");
      const saved: { chain: number; id: string }[] = [];
      const calls = [{ target: `0x${"44".repeat(20)}`, data: "0x12345678", value: "1" }];
      for (const chain of fixture.chainIds) {
        expect(await grant.account(chain)).toBe(account);
        const operation = await grant.sendCalls({ chain, calls });
        saved.push({ chain, id: operation.id });
      }
      expect(fixture.approvalCount).toBe(1);
      expect(fixture.submissionCount).toBe(2);
      await fixture.closeClient();
      const recovery = await openLocalAnvilRecoveryClient({
        recovery: fixture.recovery,
        stateDirectory,
      });
      try {
        const recovered = await (await recovery.connect()).resume();
        if (!recovered) throw new Error("recovered grant missing");
        for (const reference of saved) {
          const operation = await recovered.getOperation(reference);
          if (!operation) throw new Error("recovered operation missing");
          expect((await operation.wait({ attempts: 3 })).status).toBe("finalized");
          expect(await operation.execution()).toMatchObject({ sender: account, calls });
        }
      } finally {
        await recovery.close();
      }
      const reopened = await fixture.openClient();
      const resumed = await (await reopened.connect()).resume();
      if (!resumed) throw new Error("resumed grant missing");
      const next = await resumed.sendCalls({ chain: 143, calls });
      expect((await next.wait({ attempts: 3 })).status).toBe("finalized");
      expect(await next.execution()).toMatchObject({ sender: account, calls });
      await expect(
        resumed.sendCalls({
          chain: 143,
          calls: [{ ...calls[0], target: `0x${"55".repeat(20)}` }],
        }),
      ).rejects.toMatchObject({ code: "oaath_client_scope_denied" });
      expect(fixture.approvalCount).toBe(1);
      expect(fixture.submissionCount).toBe(3);
    } finally {
      await fixture.close();
      await rm(stateDirectory, { recursive: true, force: true });
    }
  }, 60_000);

  it("runs a caller-supplied WebAuthn session Grant through the issuer URL", async () => {
    const fixture = await createLocalAnvilFixture({ chainIds: [143], kernelVersion: "0.3.3" });
    const passkey = await softwarePasskey("https://consumer.example");
    const target = `0x${"44".repeat(20)}` as const;
    const calls = [{ target, data: "0x12345678", value: "1" }];
    try {
      const client = await fixture.openServiceClient({ session: passkey.session });
      const grant = await (await client.connect()).requestPermission({
        chainScope: "all",
        permissions: [{ calls: [{ target, selectors: ["0x12345678"], valueLimit: "1" }] }],
        expiresIn: 3600,
        perChainOperationLimit: 3,
      });
      // The issuer and owner reviewed the passkey, not a generated key.
      expect(client.binding.operatorCredential).toMatchObject({
        kind: "webauthn",
        publicKey: (passkey.session as { credential: { publicKey: string } }).credential.publicKey,
      });
      expect(fixture.approvalCount).toBe(1);
      expect(passkey.assertions).toBe(0);
      const operation = await grant.sendCalls({ chain: 143, calls });
      expect((await operation.wait({ attempts: 3 })).status).toBe("finalized");
      expect(await operation.execution()).toMatchObject({
        sender: await grant.account(143),
        calls,
      });
      expect(passkey.assertions).toBe(1);
      expect(fixture.submissionCount).toBe(1);
      // A disallowed selector is refused before the passkey signs anything.
      await expect(
        grant.sendCalls({ chain: 143, calls: [{ target, data: "0xabcdef01", value: "1" }] }),
      ).rejects.toMatchObject({ code: "oaath_client_scope_denied" });
      expect(passkey.assertions).toBe(1);
      expect(fixture.submissionCount).toBe(1);
    } finally {
      await fixture.close();
    }
  }, 60_000);
});
