import { createWalletClient, http } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createOAAth, type OaathLocalConfiguration } from "../src/index.js";
import { createChainFixture, createMemoryStores } from "./support/browser.js";

afterEach(() => vi.unstubAllGlobals());
type OaathStoreConfiguration = NonNullable<OaathLocalConfiguration["stores"]>;

function configuration(stores?: OaathStoreConfiguration) {
  const owner = createWalletClient({
    account: privateKeyToAccount(generatePrivateKey()),
    transport: http("http://127.0.0.1:1"),
  });
  const signTypedData = vi.fn(owner.signTypedData);
  return {
    mode: "local" as const,
    owner: { ...owner, signTypedData },
    account: { kind: "existing" as const, address: `0x${"33".repeat(20)}` as const },
    chains: [createChainFixture().capability],
    origin: "https://consumer.example",
    ...(stores ? { stores } : {}),
  };
}

describe("local realm resources", () => {
  it("reports an unfinished disconnect when the outer store close fails", async () => {
    const original = createMemoryStores();
    const close = vi
      .fn()
      .mockRejectedValueOnce(new Error("private cleanup failure"))
      .mockResolvedValue(undefined);
    const client = createOAAth(
      configuration({ ...original, operations: { ...original.operations, close } }),
    );
    await expect(client.disconnect(null)).rejects.toMatchObject({
      code: "cleanup_incomplete",
      unfinished: ["close"],
    });
    await client.close();
    expect(close).toHaveBeenCalledTimes(2);
  });

  it("requires durable storage outside a browser before requesting authority", async () => {
    vi.stubGlobal("indexedDB", undefined);
    const config = configuration();
    const client = createOAAth(config);
    await expect(client.connect()).rejects.toMatchObject({
      code: "oaath_client_store_unavailable",
    });
    expect(config.owner.signTypedData).not.toHaveBeenCalled();
    await client.close();
  });

  it.each(["keys", "context"] as const)(
    "persists %s before consent and retries a failed open",
    async (port) => {
      const stores = { ...createMemoryStores() };
      const persist = vi.fn().mockRejectedValueOnce(new Error("private storage failure"));
      if (port === "keys") {
        persist.mockImplementationOnce(stores.keys.store);
        stores.keys = { ...stores.keys, store: persist };
      } else {
        persist.mockImplementationOnce(stores.context.write);
        stores.context = { ...stores.context, write: persist };
      }
      const config = configuration(stores);
      const client = createOAAth(config);
      try {
        await expect(client.connect()).rejects.toMatchObject({
          message: "local realm could not be opened",
        });
        expect(config.owner.signTypedData).not.toHaveBeenCalled();
        expect(await (await client.connect()).resume()).toBeNull();
      } finally {
        await client.close();
      }
    },
  );

  const ports = [
    "grants",
    "operations",
    "walletCallBundles",
    "preparedCallContexts",
    "keys",
    "cleanup",
    "context",
  ] as const;
  it.each([...ports, "all"] as const)(
    "attempts every store close when %s fails and retries only failures",
    async (failure) => {
      const original = createMemoryStores();
      const closers = Object.fromEntries(
        ports.map((name) => [
          name,
          vi
            .fn()
            .mockImplementationOnce(async () => {
              if (failure === name || failure === "all") throw new Error("private close failure");
            })
            .mockResolvedValue(undefined),
        ]),
      );
      const stores = Object.fromEntries(
        ports.map((name) => [name, { ...original[name], close: closers[name] }]),
      ) as unknown as OaathStoreConfiguration;
      const client = createOAAth(configuration(stores));
      await client.connect();
      await expect(client.close()).rejects.toMatchObject({
        code: "oaath_client_internal",
        message: "local resources could not all be closed",
      });
      for (const name of ports) expect(closers[name]).toHaveBeenCalledTimes(1);
      await expect(client.connect()).rejects.toMatchObject({ code: "oaath_client_closed" });
      await client.close();
      for (const name of ports)
        expect(closers[name]).toHaveBeenCalledTimes(failure === name || failure === "all" ? 2 : 1);
      await client.close();
    },
  );
});
