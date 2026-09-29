import { IDBFactory } from "fake-indexeddb";
import { createWalletClient, custom } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createOAAth } from "../src/index.js";
import type { KernelV33ReadRequest } from "../src/kernel/deployment/v33.js";
import { kernelDeployment } from "../src/kernel.js";
import type { KernelV4AccountReadRequest } from "../src/kernel-v4.js";
import { createMemoryOperationStoreAdapter } from "../src/testing.js";
import { ACCOUNT, CHAIN_ID, createChainFixture, sendCallsInput } from "./support/browser.js";

afterEach(() => vi.unstubAllGlobals());
function fixture(pending = false, lostReply = false) {
  const owner = privateKeyToAccount(generatePrivateKey());
  let currentOwner = owner.address.toLowerCase();
  let prompts = 0;
  const wallet = createWalletClient({
    account: owner.address,
    transport: custom({
      async request({ method, params }) {
        expect(method).toBe("personal_sign");
        prompts++;
        return owner.signMessage({ message: { raw: (params as [`0x${string}`, string])[0] } });
      },
    }),
  });
  const base = createChainFixture({ withholdReceipt: () => pending, crashOnSend: () => lostReply });
  const deployment = kernelDeployment({ chainId: CHAIN_ID, kernelVersion: "0.3.3" });
  const chain = {
    ...base.capability,
    reads: {
      async read(request: KernelV33ReadRequest | KernelV4AccountReadRequest): Promise<unknown> {
        if (request.type === "code") return "0x6000";
        if (request.type === "kernel_account_implementation") return deployment.implementation;
        if (request.type === "kernel_account_version") return "kernel.advanced.v0.3.3";
        if (request.type === "kernel_account_entrypoint") return deployment.entryPoint.address;
        if (request.type === "kernel_account_root_validator")
          return `0x01${deployment.ecdsaValidator.slice(2)}`;
        if (request.type === "kernel_ecdsa_owner") return currentOwner;
        return base.capability.reads.read(request as KernelV4AccountReadRequest);
      },
    },
  };
  const create = () =>
    createOAAth({
      mode: "owner",
      chains: [chain],
      operations: createMemoryOperationStoreAdapter(),
    });
  return {
    base,
    chain,
    wallet,
    create,
    prompts: () => prompts,
    changeOwner: () => {
      currentOwner = ACCOUNT;
    },
  };
}

describe("owner-direct account calls", () => {
  it("does not report one-operation capacity when estimation fails or creates an operation slot", async () => {
    const { chain, wallet, base, prompts } = fixture();
    let estimates = 0;
    const client = createOAAth({
      mode: "owner",
      operations: createMemoryOperationStoreAdapter(),
      chains: [
        {
          ...chain,
          quote: async (request) => {
            estimates++;
            if (estimates === 1) throw new Error("estimation unavailable");
            return chain.quote(request);
          },
        },
      ],
    });
    try {
      const owner = client.account(ACCOUNT).owner(wallet);
      await expect(owner.reviewCalls(sendCallsInput())).rejects.toMatchObject({
        code: "oaath_client_internal",
      });
      expect(prompts()).toBe(0);
      expect(base.sends).toHaveLength(0);
      const review = await owner.reviewCalls(sendCallsInput());
      expect(review).toMatchObject({
        capacity: {
          kind: "single-operation",
          detail: {
            callGasLimit: "100000",
            verificationGasLimit: "200000",
            preVerificationGas: "50000",
          },
        },
      });
      expect(Object.isFrozen(review.capacity.detail)).toBe(true);
      const operation = await owner.sendCalls(sendCallsInput());
      expect(prompts()).toBe(1);
      expect((await operation.wait()).status).toBe("finalized");
    } finally {
      await client.close();
    }
  });

  it("finalizes an explicitly requested paymaster before the owner prompt", async () => {
    const { chain, wallet, base, prompts } = fixture();
    const stages: string[] = [];
    const paymaster = `0x${"33".repeat(20)}` as const;
    const client = createOAAth({
      mode: "owner",
      operations: createMemoryOperationStoreAdapter(),
      chains: [
        {
          ...chain,
          quote: async (request) => {
            expect(request.purpose).toBe("sponsorship");
            return chain.quote(request);
          },
          sponsorship: {
            kind: "erc7677",
            url: "https://paymaster.test",
            request: async (request) => {
              expect(prompts()).toBe(0);
              stages.push(request.method);
              return request.method === "pm_getPaymasterStubData"
                ? { paymaster, paymasterData: "0x01", paymasterPostOpGasLimit: "0x64" }
                : { paymaster, paymasterData: "0x02" };
            },
            estimate: async (request) => {
              expect(prompts()).toBe(0);
              expect(request.userOperation.signature.length).toBe(132);
              stages.push("estimate");
              return {
                callGasLimit: "200000",
                verificationGasLimit: "300000",
                preVerificationGas: "50000",
                paymasterVerificationGasLimit: "100000",
              };
            },
          },
        },
      ],
    });
    try {
      const owner = client.account(ACCOUNT).owner(wallet);
      const request = {
        ...(sendCallsInput() as Record<string, unknown>),
        payer: { kind: "paymaster-service", url: "https://paymaster.test", context: {} },
      };
      expect(await owner.reviewCalls(request)).toMatchObject({
        paymasterService: { url: "https://paymaster.test" },
      });
      expect(stages).toEqual(["pm_getPaymasterStubData", "estimate", "pm_getPaymasterData"]);
      expect(prompts()).toBe(0);
      stages.length = 0;
      const operation = await owner.sendCalls(request);
      expect(stages).toEqual(["pm_getPaymasterStubData", "estimate", "pm_getPaymasterData"]);
      expect(base.sends[0]?.userOperation.paymaster).toMatchObject({
        address: paymaster,
        data: "0x02",
      });
      expect(base.sends[0]?.userOperation.nonce).toBe("0");
      expect(prompts()).toBe(1);
      expect((await operation.wait()).status).toBe("finalized");
    } finally {
      await client.close();
    }
  });

  it("retains an uncertain send and never opens another signature or submission", async () => {
    const { create, wallet, base, prompts } = fixture(true, true);
    const client = create();
    try {
      const owner = client.account(ACCOUNT).owner(wallet);
      const operation = await owner.sendCalls(sendCallsInput());
      expect(operation.outcome).toMatchObject({ status: "pending", reason: "send_ambiguous" });
      await operation.wait({ attempts: 1 });
      await expect(owner.sendCalls(sendCallsInput())).rejects.toMatchObject({
        code: "oaath_client_state_conflict",
      });
      expect(prompts()).toBe(1);
      expect(base.sends).toHaveLength(1);
    } finally {
      await client.close();
    }
  });

  it("closes during a quote without opening a later wallet prompt", async () => {
    const { chain, wallet, base, prompts } = fixture();
    let release: () => void = () => undefined;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered: () => void = () => undefined;
    const quoted = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const client = createOAAth({
      mode: "owner",
      operations: createMemoryOperationStoreAdapter(),
      chains: [
        {
          ...chain,
          quote: async (request) => {
            entered();
            await blocked;
            return chain.quote(request);
          },
        },
      ],
    });
    const owner = client.account(ACCOUNT).owner(wallet);
    const sending = owner.sendCalls(sendCallsInput());
    await quoted;
    const closing = client.close();
    release();
    await sending;
    await closing;
    expect(prompts()).toBe(0);
    expect(base.sends).toHaveLength(0);
    await expect(owner.sendCalls(sendCallsInput())).rejects.toMatchObject({
      code: "oaath_client_closed",
    });
  });

  it("reviews then executes one root operation without a Grant or enable envelope", async () => {
    const { create, wallet, base, prompts } = fixture();
    const client = create();
    try {
      const owner = client.account(ACCOUNT).owner(wallet);
      const review = await owner.reviewCalls(sendCallsInput());
      expect(review).toMatchObject({
        version: "oaath-calls-review-v1",
        account: { address: ACCOUNT, implementation: "kernel:0.3.3" },
        chainId: CHAIN_ID,
        signer: "owner",
        enforcement: { calls: "none", expiry: "none", operationCount: "none" },
        validation: "estimated",
        route: "erc4337-bundler",
        reasons: ["owner_explicit", "route_available:erc4337-bundler"],
      });
      expect(prompts()).toBe(0);
      expect(base.quotes).toBe(1);
      expect(base.sends).toHaveLength(0);
      const operation = await owner.sendCalls(sendCallsInput());
      expect(prompts()).toBe(1);
      expect(base.sends).toHaveLength(1);
      expect(base.sends[0]?.userOperation.factory).toBeNull();
      expect(base.sends[0]?.userOperation.nonce).toBe("0");
      expect(base.sends[0]?.userOperation.verificationGasLimit).toBe("200000");
      expect(base.signatures[0]?.length).toBe(132);
      expect((await operation.wait()).status).toBe("finalized");
      expect((await owner.sendCalls(sendCallsInput())).id).not.toBe(operation.id);
      expect(
        await client.account(ACCOUNT).getOperation({ chain: CHAIN_ID, id: operation.id }),
      ).not.toBeNull();
    } finally {
      await client.close();
    }
  });

  it("admits only one concurrent send into the account and chain slot", async () => {
    const { create, wallet, prompts, base } = fixture(true);
    const client = create();
    try {
      const one = client.account(ACCOUNT).owner(wallet),
        two = client.account(ACCOUNT).owner(wallet);
      const results = await Promise.allSettled([
        one.sendCalls(sendCallsInput()),
        two.sendCalls(sendCallsInput()),
      ]);
      expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
      expect(prompts()).toBe(1);
      expect(base.sends).toHaveLength(1);
      await expect(one.sendCalls(sendCallsInput())).rejects.toMatchObject({
        code: "oaath_client_state_conflict",
      });
    } finally {
      await client.close();
    }
  });

  it("recreates IndexedDB state and observes without another wallet signature or send", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const { chain, wallet, prompts, base } = fixture(true);
    const first = createOAAth({ mode: "owner", chains: [chain] });
    const operation = await first.account(ACCOUNT).owner(wallet).sendCalls(sendCallsInput());
    await first.close();
    const second = createOAAth({ mode: "owner", chains: [chain] });
    try {
      const restored = await second
        .account(ACCOUNT)
        .getOperation({ chain: CHAIN_ID, id: operation.id });
      expect(restored?.id).toBe(operation.id);
      expect((await restored?.wait({ attempts: 1 }))?.status).toBe("pending");
      await expect(
        second.account(ACCOUNT).owner(wallet).sendCalls(sendCallsInput()),
      ).rejects.toMatchObject({ code: "oaath_client_state_conflict" });
      expect(prompts()).toBe(1);
      expect(base.sends).toHaveLength(1);
    } finally {
      await second.close();
    }
  });

  it("refuses a changed root owner before quoting or prompting", async () => {
    const { create, wallet, changeOwner, prompts, base } = fixture();
    const client = create();
    try {
      const owner = client.account(ACCOUNT).owner(wallet);
      changeOwner();
      await expect(owner.sendCalls(sendCallsInput())).rejects.toMatchObject({
        source: "kernel_runtime_binding_mismatch",
      });
      expect(prompts()).toBe(0);
      expect(base.quotes).toBe(0);
      expect(base.sends).toHaveLength(0);
    } finally {
      await client.close();
    }
  });
});
