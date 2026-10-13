import { custom as cetaneCustom, createWalletClient as createCetaneWalletClient } from "cetane";
import { generatePrivateKey, privateKeyToAccount } from "cetane/accounts";
import { createExecution } from "cetane/execution/evm";
import { createWalletClient, custom, decodeFunctionData } from "viem";
import { entryPoint07Abi, toPackedUserOperation } from "viem/account-abstraction";
import { describe, expect, it, vi } from "vitest";
import { OaathRpcError } from "../src/cetane.js";
import { captureConnectedEoa, withConnectedEoaFallback } from "../src/client/connected-eoa.js";
import { asCetaneUserOperation, prepareUserOperation } from "../src/kernel.js";
import { KERNEL_V4_ENTRY_POINT_V09 } from "../src/kernel-v4.js";
import { OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES } from "../src/routing/erc4337/bundler.js";

const address = `0x${"11".repeat(20)}` as const;
const transactionHash = `0x${"22".repeat(32)}` as const;
const prepared = prepareUserOperation({
  kind: "execution",
  grantId: "fallback",
  chainId: 143,
  entryPoint: { version: "0.9", address: KERNEL_V4_ENTRY_POINT_V09 },
  userOperation: {
    sender: address,
    nonce: "7",
    callData: "0x1234",
    factory: null,
    paymaster: null,
    callGasLimit: "100000",
    verificationGasLimit: "200000",
    preVerificationGas: "50000",
    maxFeePerGas: "100",
    maxPriorityFeePerGas: "1",
  },
});
const request = {
  prepared,
  signature: "0x1234" as const,
  route: "erc4337-bundler" as const,
  feePayer: null,
};

function fixture(
  input: {
    reject?: unknown;
    pending?: Promise<unknown>;
    walletChain?: string;
    walletAccounts?: readonly string[];
    walletReject?: boolean;
    transactionHash?: string;
  } = {},
) {
  let sends = 0,
    closes = 0;
  const walletMethods: string[] = [];
  const wallet = createWalletClient({
    account: address,
    transport: custom({
      request: async ({ method, params }) => {
        walletMethods.push(method);
        if (method === "eth_chainId") return input.walletChain ?? "0x8f";
        if (method === "eth_accounts") return input.walletAccounts ?? [address];
        expect(method).toBe("eth_sendTransaction");
        const [transaction] = params as [
          { from: string; to: string; data: `0x${string}`; value: string; chainId: string },
        ];
        expect(transaction).toMatchObject({
          from: address,
          to: KERNEL_V4_ENTRY_POINT_V09,
          value: "0x0",
          chainId: "0x8f",
        });
        const decoded = decodeFunctionData({ abi: entryPoint07Abi, data: transaction.data });
        expect(decoded.functionName).toBe("handleOps");
        expect(decoded.args).toEqual([
          [
            toPackedUserOperation({
              ...asCetaneUserOperation(prepared.userOperation),
              signature: request.signature,
            }),
          ],
          address,
        ]);
        if (input.walletReject)
          throw Object.assign(new Error("private wallet text"), { code: 4001 });
        return input.transactionHash ?? transactionHash;
      },
    }),
  });
  const payer = captureConnectedEoa({ kind: "connected-eoa", wallet }, new WeakSet());
  const session = withConnectedEoaFallback(
    {
      submit: async () => {
        sends++;
        if (input.pending) return input.pending;
        if (input.reject !== undefined) throw input.reject;
        return { userOperationHash: prepared.userOperationHash };
      },
      close: async () => {
        closes++;
      },
    },
    request,
    payer,
  );
  return { session, payer, walletMethods, sends: () => sends, closes: () => closes };
}

describe("connected EOA fallback", () => {
  it("captures a Cetane local signer with a lazy address without contacting the wallet", () => {
    const signer = privateKeyToAccount(generatePrivateKey());
    expect(Object.getOwnPropertyDescriptor(signer, "address")?.get).toBeTypeOf("function");
    const rpc = vi.fn(async () => {
      throw new Error("wallet must not be contacted during capture");
    });
    const wallet = createCetaneWalletClient({
      chain: { id: 143, name: "Fixture", nativeAA: false, execution: createExecution() },
      account: { address: signer.address },
      signer,
      transport: cetaneCustom({ request: rpc }),
    });
    const payer = captureConnectedEoa({ kind: "connected-eoa", wallet }, new WeakSet());
    expect(payer.address).toBe(signer.address.toLowerCase());
    expect(payer.localSend).toBeTypeOf("function");
    expect(Object.isFrozen(payer)).toBe(true);
    expect(rpc).not.toHaveBeenCalled();
  });

  it("reads only the signer capability once and captures the local send", async () => {
    const sign = vi.fn();
    const readSign = vi.fn(() => sign);
    const readAddress = vi.fn(() => {
      throw new Error("unrelated signer field must not be read");
    });
    const signer = Object.defineProperties(
      {},
      {
        sign: { get: readSign },
        address: { get: readAddress },
      },
    );
    const rpc = vi.fn();
    const send = vi.fn(async () => transactionHash);
    const wallet = { account: { address }, signer, request: rpc, sendTransaction: send };
    const payer = captureConnectedEoa({ kind: "connected-eoa", wallet }, new WeakSet());
    wallet.sendTransaction = vi.fn(async () => {
      throw new Error("replaced send must not be used");
    });
    expect(await payer.localSend?.({ to: address, data: "0x", value: 0n })).toBe(transactionHash);
    expect(send).toHaveBeenCalledTimes(1);
    expect(readSign).toHaveBeenCalledTimes(1);
    expect(readAddress).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();
    expect(rpc).not.toHaveBeenCalled();
  });

  it.each([null, "signer", 1, {}, { sign: undefined }, { sign: "sign" }])(
    "rejects an invalid signer before contacting the wallet: %s",
    (signer) => {
      const rpc = vi.fn();
      const send = vi.fn();
      expect(() =>
        captureConnectedEoa(
          {
            kind: "connected-eoa",
            wallet: { account: { address }, signer, request: rpc, sendTransaction: send },
          },
          new WeakSet(),
        ),
      ).toThrowError(expect.objectContaining({ code: "oaath_client_input_invalid" }));
      expect(rpc).not.toHaveBeenCalled();
      expect(send).not.toHaveBeenCalled();
    },
  );

  it("rejects an unreadable signer capability without retaining its error", () => {
    const readSign = vi.fn(() => {
      throw new Error("private signer details");
    });
    const signer = Object.defineProperty({}, "sign", { get: readSign });
    expect(() =>
      captureConnectedEoa(
        {
          kind: "connected-eoa",
          wallet: { account: { address }, signer, request: vi.fn(), sendTransaction: vi.fn() },
        },
        new WeakSet(),
      ),
    ).toThrowError(
      expect.objectContaining({
        code: "oaath_client_input_invalid",
        message: "connected fee payer signer is invalid",
      }),
    );
    expect(readSign).toHaveBeenCalledTimes(1);
  });

  it("still requires a local send capability when a signer is present", () => {
    expect(() =>
      captureConnectedEoa(
        {
          kind: "connected-eoa",
          wallet: { account: { address }, signer: { sign: vi.fn() }, request: vi.fn() },
        },
        new WeakSet(),
      ),
    ).toThrowError(
      expect.objectContaining({
        code: "oaath_client_input_invalid",
        message: "local fee payer sendTransaction is missing",
      }),
    );
  });

  it.each(["wallet", "account"])("keeps the %s data boundary strict", (boundary) => {
    const read = vi.fn();
    const wallet = { account: { address }, request: vi.fn() };
    Object.defineProperty(boundary === "wallet" ? wallet : wallet.account, "extra", {
      enumerable: true,
      get: read,
    });
    expect(() =>
      captureConnectedEoa({ kind: "connected-eoa", wallet }, new WeakSet()),
    ).toThrowError(expect.objectContaining({ code: "oaath_client_input_invalid" }));
    expect(read).not.toHaveBeenCalled();
  });

  it.each([true, false])(
    "uses the local wallet only after a conclusive rejection: %s",
    async (conclusive) => {
      const rpc = vi.fn(async ({ method }: { method: string }) => {
        expect(method).toBe("eth_chainId");
        return "0x8f";
      });
      const localSend = vi.fn(async () => transactionHash);
      const payer = captureConnectedEoa(
        {
          kind: "connected-eoa",
          wallet: { account: { address, type: "local" }, request: rpc, sendTransaction: localSend },
        },
        new WeakSet(),
      );
      const rejection = new OaathRpcError("oaath_rpc_rejected", conclusive ? -32500 : -32603);
      const session = withConnectedEoaFallback(
        {
          submit: async () => {
            throw rejection;
          },
          close: async () => {},
        },
        request,
        payer,
      );
      if (conclusive) {
        await session.submit();
        await session.submit();
        expect(localSend).toHaveBeenCalledTimes(1);
        expect(localSend).toHaveBeenCalledWith(
          expect.objectContaining({ to: KERNEL_V4_ENTRY_POINT_V09, value: 0n }),
        );
        expect(rpc).toHaveBeenCalledTimes(1);
      } else {
        await expect(session.submit()).rejects.toBe(rejection);
        expect(localSend).not.toHaveBeenCalled();
        expect(rpc).not.toHaveBeenCalled();
      }
    },
  );
  it.each(OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES)(
    "submits the same signed bytes once after conclusive rejection %s",
    async (code) => {
      const test = fixture({ reject: new OaathRpcError("oaath_rpc_rejected", code) });
      expect(test.walletMethods).toEqual([]);
      const [first, second] = await Promise.all([test.session.submit(), test.session.submit()]);
      expect(first).toEqual({
        userOperationHash: prepared.userOperationHash,
        submission: { route: "erc4337-handleops", transactionHash },
      });
      expect(second).toEqual(first);
      expect(test.sends()).toBe(1);
      expect(test.walletMethods.filter((method) => method === "eth_sendTransaction")).toHaveLength(
        1,
      );
      await test.session.close();
      expect(test.closes()).toBe(1);
    },
  );
  it.each([
    new OaathRpcError("oaath_rpc_unavailable"),
    new OaathRpcError("oaath_rpc_rejected", -32603),
    new OaathRpcError("oaath_rpc_rejected", -32000),
    new Error("-32500"),
    { code: -32500 },
  ])("never falls back after inconclusive failure", async (reject) => {
    const test = fixture({ reject });
    await expect(test.session.submit()).rejects.toBe(reject);
    await expect(test.session.submit()).rejects.toBe(reject);
    expect(test.sends()).toBe(1);
    expect(test.walletMethods).toEqual([]);
  });
  it("does not contact the wallet after acceptance", async () => {
    const test = fixture();
    await test.session.submit();
    expect(test.walletMethods).toEqual([]);
  });
  it("does not start fallback when a rejection arrives after the session closed", async () => {
    let reject!: (error: unknown) => void;
    const pending = new Promise<never>((_, fail) => {
      reject = fail;
    });
    const test = fixture({ pending });
    const sent = test.session.submit();
    await test.session.close();
    reject(new OaathRpcError("oaath_rpc_rejected", -32500));
    await expect(sent).rejects.toBeDefined();
    expect(test.walletMethods).toEqual([]);
  });
  it.each([{ walletChain: "0x1" }, { walletAccounts: [] }])(
    "checks connected chain and account before any send",
    async (options) => {
      const test = fixture({ ...options, reject: new OaathRpcError("oaath_rpc_rejected", -32500) });
      await expect(test.session.submit()).rejects.toMatchObject({
        code: "oaath_client_state_conflict",
      });
      expect(test.walletMethods).not.toContain("eth_sendTransaction");
    },
  );
  it.each([{ walletReject: true }, { transactionHash: "0x12" }])(
    "never repeats an uncertain or rejected wallet transaction",
    async (options) => {
      const test = fixture({ ...options, reject: new OaathRpcError("oaath_rpc_rejected", -32500) });
      await expect(test.session.submit()).rejects.toMatchObject({
        code: "oaath_client_capability_invalid",
      });
      await expect(test.session.submit()).rejects.toBeDefined();
      expect(test.walletMethods.filter((method) => method === "eth_sendTransaction")).toHaveLength(
        1,
      );
    },
  );
});
