import { OAATH_OWNER_CREDENTIAL_PROFILE_VERSION } from "@oaath/protocol";
import { createOAAth, type OaathLocalClient, type OaathLocalSession } from "@oaath/sdk";
import { createLocalOwnerAnvilFixture } from "@oaath/testing/anvil";
import { IDBFactory } from "fake-indexeddb";
import { bytesToHex, concat, hexToBytes, keccak256, sha256, stringToBytes } from "viem";
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

/** A software passkey: WebCrypto P-256 signs exactly what an authenticator signs. */
async function softwarePasskey(origin: string) {
  const rpId = new URL(origin).hostname;
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
  ]);
  const rawId = crypto.getRandomValues(new Uint8Array(16));
  let assertions = 0;
  const session: OaathLocalSession = {
    kind: "webauthn",
    credential: {
      version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
      kind: "webauthn",
      publicKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))),
      authenticatorIdHash: keccak256(rawId),
    },
    credentialId: Buffer.from(rawId).toString("base64url"),
    rpId,
    origin,
    async authenticate(request) {
      assertions++;
      const clientDataJSON = JSON.stringify({
        type: "webauthn.get",
        challenge: request.challenge,
        origin,
        crossOrigin: false,
      });
      const authenticatorData = concat([sha256(stringToBytes(rpId)), "0x0500000001"]);
      const signed = new Uint8Array(
        hexToBytes(concat([authenticatorData, sha256(stringToBytes(clientDataJSON))])),
      );
      const signature = new Uint8Array(
        await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, signed),
      );
      return {
        authenticatorData,
        clientDataJSON,
        responseTypeLocation: String(clientDataJSON.indexOf('"type":"webauthn.get"')),
        r: bytesToHex(signature.slice(0, 32)),
        s: bytesToHex(signature.slice(32)),
      };
    },
  };
  return {
    session,
    get assertions() {
      return assertions;
    },
  };
}

describe.skipIf(process.env.OAATH_REQUIRE_ANVIL !== "1")("issuer-free local mode", () => {
  it.each(["rejected", "unavailable"] as const)(
    "keeps %s session estimation separate from owner execution",
    async (sessionValidation) => {
      vi.stubGlobal("indexedDB", new IDBFactory());
      const fixture = await createLocalOwnerAnvilFixture({ sessionValidation });
      const client = createOAAth({
        mode: "local",
        owner: fixture.wallet,
        account: fixture.address,
        chains: fixture.createChainPorts(),
        origin: "https://consumer.example",
      });
      try {
        const grant = await (await client.connect()).requestPermission(permission);
        const assessment = grant.reviewCalls({ chain: fixture.chainId, calls, estimate: true });
        if (sessionValidation === "unavailable")
          await expect(assessment).rejects.toMatchObject({
            code: "oaath_client_preparation_failed",
          });
        else expect((await assessment).validation).toBe("account-rejected");
        expect(fixture.sessionEstimationCount).toBeGreaterThan(0);
        expect(fixture.signatureCount).toBe(1);
        expect(fixture.bundlerSubmissionCount).toBe(0);
        if (sessionValidation === "rejected") {
          const owner = client.account(fixture.address).owner(fixture.wallet);
          for (let index = 0; index < 2; index++) {
            expect(await owner.reviewCalls({ chain: fixture.chainId, calls })).toMatchObject({
              signer: "owner",
            });
            const operation = await owner.sendCalls({ chain: fixture.chainId, calls });
            expect((await operation.wait({ attempts: 3 })).status).toBe("finalized");
            expect(await operation.execution()).toMatchObject({ sender: fixture.address, calls });
            expect(fixture.signatureCount).toBe(index + 2);
            expect(fixture.bundlerSubmissionCount).toBe(index + 1);
          }
        }
      } finally {
        await client.close();
        await fixture.close();
      }
    },
  );

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

  it("runs a caller-supplied WebAuthn session on an existing v3.3 account", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const fixture = await createLocalOwnerAnvilFixture();
    const origin = "https://consumer.example";
    const passkey = await softwarePasskey(origin);
    const open = () =>
      createOAAth({
        mode: "local",
        owner: fixture.wallet,
        account: fixture.address,
        chains: fixture.createChainPorts(),
        origin,
        session: passkey.session,
      });
    let client = open();
    try {
      const grant = await (await client.connect()).requestPermission(permission);
      // One ECDSA owner consent; the passkey has not signed anything yet.
      expect(fixture.signatureCount).toBe(1);
      expect(passkey.assertions).toBe(0);
      const first = await grant.sendCalls({ chain: fixture.chainId, calls });
      expect((await first.wait({ attempts: 3 })).status).toBe("finalized");
      expect(await first.execution()).toMatchObject({ sender: fixture.address, calls });
      expect(passkey.assertions).toBe(1);
      expect(fixture.bundlerSubmissionCount).toBe(1);
      await expect(
        grant.sendCalls({
          chain: fixture.chainId,
          calls: [{ target, data: "0xabcdef01", value: "1" }],
        }),
      ).rejects.toMatchObject({ code: "oaath_client_scope_denied" });
      expect(passkey.assertions).toBe(1);
      expect(fixture.bundlerSubmissionCount).toBe(1);
      // Recreate every instance; the same passkey resumes the same Grant.
      await client.close();
      client = open();
      const resumed = await (await client.connect()).resume();
      if (!resumed) throw new Error("passkey grant missing after reload");
      expect(await resumed.account(fixture.chainId)).toBe(fixture.address);
      await resumed.revoke();
      if (resumed.state !== "revoked") {
        await fixture.mine();
        await resumed.revoke();
      }
      expect(resumed.state).toBe("revoked");
      expect(fixture.signatureCount).toBe(2);
      expect(passkey.assertions).toBe(1);
      await expect(resumed.sendCalls({ chain: fixture.chainId, calls })).rejects.toMatchObject({
        code: "oaath_client_grant_inactive",
      });
    } finally {
      await client.close();
      await fixture.close();
    }
  }, 60_000);

  it("installs a four-call permission after owner execution and reuses it after reload", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const fixture = await createLocalOwnerAnvilFixture({ wallet: "browser", chainId: 8453 });
    const scope = [
      { target, selectors: ["0x12345678"], valueLimit: "1" },
      { target, selectors: ["0xabcdef01"], valueLimit: "1" },
      { target: `0x${"55".repeat(20)}`, selectors: ["0x12345678"], valueLimit: "1" },
      { target: `0x${"66".repeat(20)}`, selectors: ["0x12345678"], valueLimit: "1" },
    ] as const;
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
      const owner = client.account(fixture.address).owner(fixture.wallet);
      const owned = await owner.sendCalls({ chain: fixture.chainId, calls });
      expect((await owned.wait({ attempts: 3 })).status).toBe("finalized");
      const grant = await (await client.connect()).requestPermission({
        ...permission,
        permissions: [{ calls: scope }],
        perChainOperationLimit: 2,
      });
      const deploymentSizedCalls = [
        { target, data: `0x12345678${"00".repeat(600)}`, value: "0" },
        { target: scope[2].target, data: "0x12345678", value: "0" },
      ] as const;
      const first = await grant.sendCalls({ chain: fixture.chainId, calls: deploymentSizedCalls });
      expect((await first.wait({ attempts: 3 })).status).toBe("finalized");
      expect((await first.execution()).calls).toEqual(deploymentSizedCalls);
      await client.close();
      client = open();
      const restored = await (await client.connect()).resume();
      if (!restored) throw new Error("local grant missing after reload");
      const nextCalls = [{ target: scope[2].target, data: "0x12345678", value: "1" }] as const;
      const next = await restored.sendCalls({ chain: fixture.chainId, calls: nextCalls });
      expect((await next.wait({ attempts: 3 })).status).toBe("finalized");
      expect((await next.execution()).calls).toEqual(nextCalls);
      expect(fixture.signatureCount).toBe(2);
      expect(fixture.bundlerSubmissionCount).toBe(3);
      await expect(
        restored.sendCalls({
          chain: fixture.chainId,
          calls: [{ target: `0x${"77".repeat(20)}`, data: "0x12345678", value: "1" }],
        }),
      ).rejects.toMatchObject({ code: "oaath_client_scope_denied" });
      expect(fixture.bundlerSubmissionCount).toBe(3);
    } finally {
      await client.close();
      await fixture.close();
    }
  }, 60_000);

  it("exposes its fixture RPC bridge and rejects use after close", async () => {
    const fixture = await createLocalOwnerAnvilFixture({ chainId: 8453 });
    const request = () =>
      new Request("http://owner-bundler.test", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
      });
    try {
      expect(await (await fixture.rpcFetch(request())).json()).toEqual({
        jsonrpc: "2.0",
        id: 1,
        result: "0x2105",
      });
      expect(fixture.rpcRequestCount).toBe(1);
      await expect(
        fixture.rpcFetch(new Request("https://unrelated.example", { method: "POST" })),
      ).rejects.toThrow("local_fixture_endpoint_invalid");
      await expect(fixture.rpcFetch(new Request("http://owner-bundler.test"))).rejects.toThrow(
        "local_fixture_request_invalid",
      );
      expect(fixture.signatureCount).toBe(0);
      expect(fixture.bundlerSubmissionCount).toBe(0);
    } finally {
      await fixture.close();
    }
    await expect(fixture.rpcFetch(request())).rejects.toThrow("local_fixture_closed");
  });

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
