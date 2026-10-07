import { createOAAth, type OaathWalletApprovalClient } from "@oaath/sdk";
import type { OaathUsageRequest } from "@oaath/sdk/advanced";
import { kernelKey, OAATH_KERNEL_RATE_LIMIT_POLICY } from "@oaath/sdk/kernel";
import { createLocalOwnerAnvilFixture } from "@oaath/testing/anvil";
import { IDBFactory } from "fake-indexeddb";
import { encodeFunctionData, pad, parseAbi, toFunctionSelector } from "viem";
import { afterEach, describe, expect, it, vi } from "vitest";
import { softwarePasskey } from "./support-passkey.js";

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
  it("runs owner-only and wallet-approved quick starts from plain chain descriptors", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const fixture = await createLocalOwnerAnvilFixture();
    const chains = await fixture.chainDescriptors();
    const ownerOnly = createOAAth({ chains, account: fixture.address });
    const wallet = createOAAth({
      chains,
      account: fixture.address,
      approvals: { kind: "wallet", owner: fixture.wallet },
      origin: "https://consumer.example",
    });
    try {
      const owned = await ownerOnly
        .account(fixture.address)
        .owner(fixture.wallet)
        .sendCalls({ chain: fixture.chainId, calls });
      expect((await owned.wait({ attempts: 3 })).status).toBe("finalized");
      await ownerOnly.close();
      const grant = await (await wallet.connect()).requestPermission(permission);
      const operation = await grant.sendCalls({ chain: fixture.chainId, calls });
      expect((await operation.wait({ attempts: 3 })).status).toBe("finalized");
      expect(fixture.signatureCount).toBe(2);
      expect(fixture.bundlerSubmissionCount).toBe(2);
      expect(() =>
        createOAAth({ chains: { [fixture.chainId]: { publicRpcUrls: [] } } as never }),
      ).toThrowError(
        expect.objectContaining({
          code: "oaath_client_input_invalid",
          source: "oaath_rpc_config_invalid",
        }),
      );
    } finally {
      await ownerOnly.close();
      await wallet.close();
      await fixture.close();
    }
  }, 60_000);

  it("approves once and executes an allowed call on an existing Kernel v4 account", async () => {
    // Non-browser development: memory is named explicitly, with no per-store wiring.
    vi.stubGlobal("indexedDB", undefined);
    const fixture = await createLocalOwnerAnvilFixture({ kernelVersion: "0.4.0" });
    const client = createOAAth({
      approvals: { kind: "wallet", owner: fixture.wallet },
      account: fixture.address,
      chains: fixture.createChainPorts(),
      origin: "https://consumer.example",
      stores: { kind: "memory" },
    });
    try {
      const grant = await (await client.connect()).requestPermission(permission);
      expect(client.binding.account).toMatchObject({
        kernelVersion: "0.4.0",
        address: fixture.address,
      });
      expect(fixture.signatureCount).toBe(1);
      const operation = await grant.sendCalls({ chain: fixture.chainId, calls });
      expect((await operation.wait({ attempts: 3 })).status).toBe("finalized");
      expect(await operation.execution()).toMatchObject({ sender: fixture.address, calls });
      // A call outside the approved scope is refused before any submission.
      await expect(
        grant.sendCalls({
          chain: fixture.chainId,
          calls: [{ target, data: "0x87654321", value: "0" }],
        }),
      ).rejects.toMatchObject({ code: "oaath_client_scope_denied" });
      expect(fixture.signatureCount).toBe(1);
      expect(fixture.bundlerSubmissionCount).toBe(1);
    } finally {
      await client.close();
      await fixture.close();
    }
  });

  it.each(["rejected", "unavailable"] as const)(
    "keeps %s session estimation separate from owner execution",
    async (sessionValidation) => {
      vi.stubGlobal("indexedDB", new IDBFactory());
      const fixture = await createLocalOwnerAnvilFixture({ sessionValidation });
      const client = createOAAth({
        approvals: { kind: "wallet", owner: fixture.wallet },
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
        approvals: { kind: "wallet", owner },
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
        approvals: { kind: "wallet", owner: fixture.wallet },
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
      let client: Readonly<OaathWalletApprovalClient> | undefined;
      try {
        const signTypedData = vi.fn(fixture.wallet.signTypedData);
        const owner = { ...fixture.wallet, signTypedData };
        const open = () =>
          createOAAth({
            approvals: { kind: "wallet", owner },
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
        ).toMatchObject({ signer: "owner", account: { address: fixture.address } });
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
        approvals: { kind: "wallet", owner: fixture.wallet },
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
        approvals: { kind: "wallet", owner: fixture.wallet },
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

  it("refills a windowed per-chain operation limit only after its interval", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const fixture = await createLocalOwnerAnvilFixture();
    let usage: Readonly<OaathUsageRequest> | undefined;
    const client = createOAAth({
      approvals: { kind: "wallet", owner: fixture.wallet },
      account: fixture.address,
      chains: fixture.createChainPorts().map((port) => ({
        ...port,
        usage: (request: Readonly<OaathUsageRequest>) => {
          usage = request;
          return port.usage!(request);
        },
      })),
      origin: "https://consumer.example",
    });
    const rpc = async (method: string, params: unknown[]) =>
      (await (
        await fixture.rpcFetch(
          new Request(fixture.rpcUrl, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
          }),
        )
      ).json()) as { result?: unknown; error?: { data?: unknown } };
    // The pinned module's own validation, called as the account, with the exact
    // installed permission; the operation fields are unused by this policy.
    const validate = () =>
      rpc("eth_call", [
        {
          from: usage!.account,
          to: OAATH_KERNEL_RATE_LIMIT_POLICY,
          data: encodeFunctionData({
            abi: parseAbi([
              "function checkUserOpPolicy(bytes32 id, (address sender, uint256 nonce, bytes initCode, bytes callData, bytes32 accountGasLimits, uint256 preVerificationGas, bytes32 gasFees, bytes paymasterAndData, bytes signature) userOp) payable returns (uint256)",
            ]),
            functionName: "checkUserOpPolicy",
            args: [
              pad(usage!.permissionId, { size: 32, dir: "right" }),
              {
                sender: usage!.account,
                nonce: 0n,
                initCode: "0x",
                callData: "0x",
                accountGasLimits: pad("0x0"),
                preVerificationGas: 0n,
                gasFees: pad("0x0"),
                paymasterAndData: "0x",
                signature: "0x",
              },
            ],
          }),
        },
        "latest",
      ]);
    try {
      const grant = await (await client.connect()).requestPermission({
        ...permission,
        perChainOperationLimit: { count: 2, intervalSeconds: 60 },
      });
      for (let index = 0; index < 2; index++) {
        const operation = await grant.sendCalls({ chain: fixture.chainId, calls });
        expect((await operation.wait({ attempts: 3 })).status).toBe("finalized");
      }
      expect(usage).toMatchObject({ maximumOperations: "2", intervalSeconds: "60" });
      expect(fixture.bundlerSubmissionCount).toBe(2);
      // The third operation is outside the window's quota: the module's validation
      // rejects it, and local accounting refuses it before any submission.
      expect((await validate()).error?.data).toBe(toFunctionSelector("RateLimited()"));
      await expect(grant.sendCalls({ chain: fixture.chainId, calls })).rejects.toMatchObject({
        code: "oaath_client_scope_denied",
        source: "session_calls_uncovered",
      });
      expect(fixture.bundlerSubmissionCount).toBe(2);

      await rpc("evm_increaseTime", [60]);
      await fixture.mine();
      expect((await validate()).error).toBeUndefined();
      const third = await grant.sendCalls({ chain: fixture.chainId, calls });
      expect((await third.wait({ attempts: 3 })).status).toBe("finalized");
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
      approvals: { kind: "wallet", owner: { ...fixture.wallet, signTypedData: rejected } },
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
      approvals: {
        kind: "wallet",
        owner: { ...fixture.wallet, account: { address: target }, signTypedData: consent },
      },
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

  it("sends as owner and approves a Grant with a raw P-256 root owner on an existing v4 account", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const fixture = await createLocalOwnerAnvilFixture({ kernelVersion: "0.4.0", owner: "p256" });
    const ownerKey = fixture.ownerKey!;
    const owned = createOAAth({ chains: fixture.createChainPorts(), account: fixture.address });
    const client = createOAAth({
      approvals: { kind: "wallet", owner: ownerKey },
      account: fixture.address,
      chains: fixture.createChainPorts(),
      origin: "https://consumer.example",
    });
    try {
      // Owner mode: the P-256 key is proven as the account's onchain root owner.
      const direct = await owned
        .account(fixture.address)
        .owner(ownerKey)
        .sendCalls({ chain: fixture.chainId, calls });
      expect((await direct.wait({ attempts: 3 })).status).toBe("finalized");
      expect(await direct.execution()).toMatchObject({ sender: fixture.address, calls });
      expect(fixture.signatureCount).toBe(1);

      // Wallet-approved mode: the same key signs the one Grant approval.
      const grant = await (await client.connect()).requestPermission(permission);
      expect(client.binding.account).toMatchObject({
        kernelVersion: "0.4.0",
        address: fixture.address,
        ownerCredential: { kind: "p256" },
      });
      expect(fixture.signatureCount).toBe(2);
      const first = await grant.sendCalls({ chain: fixture.chainId, calls });
      expect((await first.wait({ attempts: 3 })).status).toBe("finalized");
      expect(await first.execution()).toMatchObject({ sender: fixture.address, calls });
      expect(fixture.signatureCount).toBe(2);
      expect(fixture.bundlerSubmissionCount).toBe(2);
    } finally {
      await owned.close();
      await client.close();
      await fixture.close();
    }
  }, 60_000);

  it("refuses a WebAuthn key on an ECDSA-root account before it signs", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const fixture = await createLocalOwnerAnvilFixture({ kernelVersion: "0.4.0" });
    const passkey = await softwarePasskey("https://consumer.example");
    const { kind: _kind, ...input } = passkey.session;
    const owner = kernelKey({ kind: "webauthn", ...input });
    const owned = createOAAth({ chains: fixture.createChainPorts(), account: fixture.address });
    try {
      await expect(
        owned.account(fixture.address).owner(owner).sendCalls({ chain: fixture.chainId, calls }),
      ).rejects.toMatchObject({
        code: "oaath_client_state_conflict",
        source: "kernel_runtime_binding_mismatch",
      });
      const client = createOAAth({
        approvals: { kind: "wallet", owner },
        account: fixture.address,
        chains: fixture.createChainPorts(),
        origin: "https://consumer.example",
      });
      try {
        await expect((await client.connect()).requestPermission(permission)).rejects.toMatchObject({
          code: "oaath_client_state_conflict",
        });
      } finally {
        await client.close();
      }
      expect(passkey.assertions).toBe(0);
      expect(fixture.bundlerSubmissionCount).toBe(0);
    } finally {
      await owned.close();
      await fixture.close();
    }
  });
});
