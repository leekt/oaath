import { createOAAth, type OaathLocalClient } from "@oaath/sdk";
import { createLocalOwnerAnvilFixture } from "@oaath/testing/anvil";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, describe, expect, it, vi } from "vitest";

const target = `0x${"44".repeat(20)}` as const;
const calls = [{ target, data: "0x12345678", value: "1" }] as const;
const permission = {
  chainScope: "all",
  permissions: [{ calls: [{ target, selectors: ["0x12345678"], valueLimit: "1" }] }],
  expiresIn: 3600,
  perChainOperationLimit: 3,
};
afterEach(() => vi.unstubAllGlobals());

describe.skipIf(process.env.OAATH_REQUIRE_ANVIL !== "1")("issuer-free local mode", () => {
  it("rejects overlapping consent and discards approval after close starts", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const fixture = await createLocalOwnerAnvilFixture();
    let enter!: () => void;
    let release!: () => void;
    const entered = new Promise<void>((resolve) => {
      enter = resolve;
    });
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    const owner = {
      ...fixture.wallet,
      async signTypedData(input: Parameters<typeof fixture.wallet.signTypedData>[0]) {
        enter();
        await released;
        return fixture.wallet.signTypedData(input);
      },
    };
    const open = () =>
      createOAAth({
        mode: "local",
        owner,
        account: fixture.address,
        chains: fixture.createChainPorts(),
        origin: "https://consumer.example",
      });
    let client = open();
    try {
      const connection = await client.connect();
      const pending = connection.requestPermission(permission).then(
        () => "approved",
        () => "rejected",
      );
      await entered;
      await expect(connection.requestPermission(permission)).rejects.toMatchObject({
        code: "oaath_client_state_conflict",
        source: "local_request_pending",
      });
      const closing = client.close();
      await expect(client.connect()).rejects.toMatchObject({ code: "oaath_client_closed" });
      release();
      expect(await pending).toBe("rejected");
      await closing;
      client = open();
      expect(await (await client.connect()).resume()).toBeNull();
      expect(fixture.signatureCount).toBe(1);
      expect(fixture.bundlerSubmissionCount).toBe(0);
    } finally {
      release();
      await client.close();
      await fixture.close();
    }
  });

  it.each([false, true])("disconnect revokes an approval (installed: %s)", async (installed) => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const fixture = await createLocalOwnerAnvilFixture();
    const open = () =>
      createOAAth({
        mode: "local",
        owner: fixture.wallet,
        account: fixture.address,
        chains: fixture.createChainPorts(),
        origin: "https://consumer.example",
      });
    let client = open();
    try {
      const grant = await (await client.connect()).requestPermission(permission);
      if (installed) {
        const operation = await grant.sendCalls({ chain: fixture.chainId, calls });
        expect((await operation.wait({ attempts: 3 })).status).toBe("finalized");
      }
      const result = await client.disconnect(grant);
      expect(result.unfinished).toEqual([]);
      expect(result.failures).toEqual([]);
      expect(result.completed).toContain("revoke");
      expect(fixture.bundlerSubmissionCount).toBe(installed ? 2 : 1);
      expect(fixture.signatureCount).toBe(2);
      client = open();
      expect(await (await client.connect()).resume()).toBeNull();
    } finally {
      await client.close();
      await fixture.close();
    }
  });

  it.each(["local", "browser"] as const)(
    "approves once with a %s wallet, reloads, and executes silently",
    async (walletKind) => {
      vi.stubGlobal("indexedDB", new IDBFactory());
      const fixture = await createLocalOwnerAnvilFixture({ wallet: walletKind });
      let client: Readonly<OaathLocalClient> | undefined;
      try {
        const signTypedData = vi.fn(fixture.wallet.signTypedData);
        const owner = { ...fixture.wallet, signTypedData };
        const open = () =>
          createOAAth({
            mode: "local",
            owner,
            account: fixture.address,
            chains: fixture.createChainPorts(),
            origin: "https://consumer.example",
          });
        client = open();
        const connection = await client.connect();
        expect(await connection.resume()).toBeNull();
        expect(fixture.signatureCount).toBe(0);
        const grant = await connection.requestPermission(permission);
        expect(signTypedData).toHaveBeenCalledTimes(1);
        expect(signTypedData.mock.calls[0]?.[0].domain).toEqual({
          name: "Kernel",
          version: "0.3.3",
          chainId: 0,
          verifyingContract: fixture.address,
        });
        expect(fixture.signatureCount).toBe(1);
        expect(fixture.bundlerSubmissionCount).toBe(0);
        const first = await grant.sendCalls({ chain: fixture.chainId, calls });
        const saved = { chain: first.chainId, id: first.id };
        await client.close();
        client = open();
        const resumed = await (await client.connect()).resume();
        if (!resumed) throw new Error("local grant missing after reload");
        const recovered = await resumed.getOperation(saved);
        if (!recovered) throw new Error("local operation missing after reload");
        expect((await recovered.wait({ attempts: 3 })).status).toBe("finalized");
        expect(await recovered.execution()).toMatchObject({ sender: fixture.address, calls });
        expect(fixture.bundlerSubmissionCount).toBe(1);
        const second = await resumed.sendCalls({ chain: fixture.chainId, calls });
        expect((await second.wait({ attempts: 3 })).status).toBe("finalized");
        expect(fixture.signatureCount).toBe(1);
        expect(fixture.bundlerSubmissionCount).toBe(2);
        await expect(
          resumed.sendCalls({
            chain: fixture.chainId,
            calls: [{ target: `0x${"55".repeat(20)}`, data: "0x12345678", value: "1" }],
          }),
        ).rejects.toMatchObject({ code: "oaath_client_scope_denied" });
        expect(fixture.signatureCount).toBe(1);
        expect(fixture.bundlerSubmissionCount).toBe(2);
        // The same client also exposes the already reviewed root-owner path.
        expect(
          await client
            .account(fixture.address)
            .owner(owner)
            .reviewCalls({ chain: fixture.chainId, calls }),
        ).toMatchObject({ signer: "owner", account: fixture.address });
        expect(fixture.signatureCount).toBe(1);
      } finally {
        await client?.close();
        await fixture.close();
      }
    },
    60_000,
  );

  it("creates no Grant or operation when the wallet rejects consent", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const fixture = await createLocalOwnerAnvilFixture();
    const rejected = vi.fn(async () => {
      throw new Error("private wallet rejection");
    });
    const client = createOAAth({
      mode: "local",
      owner: { ...fixture.wallet, signTypedData: rejected },
      account: fixture.address,
      chains: fixture.createChainPorts(),
      origin: "https://consumer.example",
    });
    try {
      const connection = await client.connect();
      await expect(connection.requestPermission(permission)).rejects.toMatchObject({
        message: "local permission approval failed",
      });
      expect(await connection.resume()).toBeNull();
      expect(rejected).toHaveBeenCalledTimes(1);
      expect(fixture.signatureCount).toBe(0);
      expect(fixture.bundlerSubmissionCount).toBe(0);
    } finally {
      await client.close();
      await fixture.close();
    }
  });

  it("rejects a different root owner before asking for consent", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const fixture = await createLocalOwnerAnvilFixture();
    const consent = vi.fn(fixture.wallet.signTypedData);
    const client = createOAAth({
      mode: "local",
      owner: { ...fixture.wallet, account: { address: target }, signTypedData: consent },
      account: fixture.address,
      chains: fixture.createChainPorts(),
      origin: "https://consumer.example",
    });
    try {
      const connection = await client.connect();
      await expect(connection.requestPermission(permission)).rejects.toMatchObject({
        code: "oaath_client_state_conflict",
      });
      expect(await connection.resume()).toBeNull();
      expect(consent).not.toHaveBeenCalled();
      expect(fixture.bundlerSubmissionCount).toBe(0);
    } finally {
      await client.close();
      await fixture.close();
    }
  });
});
