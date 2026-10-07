import { getAddress } from "viem";
import { describe, expect, it } from "vitest";
import { hashErc7902StaticPaymasterConfiguration } from "../src/advanced.js";
import { kernelKey, prepareUserOperation } from "../src/kernel.js";
import { parseWalletCallBundleKey } from "../src/persistence/interfaces.js";
import {
  captureWalletSendCallsParams,
  hashCapturedWalletSendCallsRequest,
} from "../src/provider/capture.js";
import { captureErc7902StaticPaymasterConfiguration } from "../src/provider/erc7902.js";

const lower = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
const checked = getAddress(lower);
const upper = `0x${lower.slice(2).toUpperCase()}` as const;
const wrong = checked.replace(/[a-f]/u, (letter) => letter.toUpperCase()) as `0x${string}`;
const preparation = (address: `0x${string}`) => ({
  kind: "execution",
  grantId: "checksum-proof",
  chainId: 143,
  entryPoint: { version: "0.9", address },
  userOperation: {
    sender: address,
    nonce: "0",
    callData: "0x",
    callGasLimit: "100000",
    verificationGasLimit: "200000",
    preVerificationGas: "50000",
    maxFeePerGas: "1",
    maxPriorityFeePerGas: "1",
    factory: { address, data: "0x" },
    paymaster: { address, data: "0x", verificationGasLimit: "10000", postOpGasLimit: "10000" },
  },
});
const paymaster = (address: `0x${string}`) => ({
  paymaster: address,
  paymasterData: "0x",
  paymasterValidationGasLimit: "0x10000",
  paymasterPostOpGasLimit: "0x10000",
});

describe("SDK address inputs", () => {
  it("uses the same durable bundle key for every valid address form", () => {
    const key = (account: `0x${string}`) => ({
      providerScopeId: `0x${"11".repeat(32)}`,
      account,
      id: "same-key",
    });
    for (const address of [checked, upper])
      expect(parseWalletCallBundleKey(key(address))).toEqual(parseWalletCallBundleKey(key(lower)));
    expect(() => parseWalletCallBundleKey(key(wrong))).toThrow(/bundle account.*checksum/u);
  });
  it("normalizes a wallet paymaster before computing request identity", () => {
    const capture = (address: `0x${string}`) =>
      captureWalletSendCallsParams(
        [
          {
            version: "2.0.0",
            chainId: "0x8f",
            from: lower,
            atomicRequired: true,
            calls: [{ to: lower }],
            capabilities: { staticPaymasterConfiguration: paymaster(address) },
          },
        ],
        143,
      );
    const expected = hashCapturedWalletSendCallsRequest(capture(lower), "same-paymaster");
    for (const address of [checked, upper])
      expect(hashCapturedWalletSendCallsRequest(capture(address), "same-paymaster")).toBe(expected);
    expect(() => capture(wrong)).toThrowError(
      expect.objectContaining({
        code: -32602,
        data: {
          address: { field: "paymaster", reason: "checksum" },
          message: "paymaster has an invalid EIP-55 checksum",
        },
      }),
    );
  });
  it("normalizes wallet-call addresses and reports invalid checksums without reflecting input", () => {
    const input = (address: `0x${string}`) => [
      {
        version: "2.0.0",
        chainId: "0x8f",
        from: address,
        atomicRequired: true,
        calls: [{ to: address, data: "0x12345678", value: "0x0" }],
      },
    ];
    const canonical = captureWalletSendCallsParams(input(lower), 143);
    for (const address of [checked, upper]) {
      const captured = captureWalletSendCallsParams(input(address), 143);
      expect(captured).toEqual(canonical);
      expect(hashCapturedWalletSendCallsRequest(captured, "checksum")).toBe(
        hashCapturedWalletSendCallsRequest(canonical, "checksum"),
      );
    }
    expect(() => captureWalletSendCallsParams(input(wrong), 143)).toThrowError(
      expect.objectContaining({
        code: -32602,
        message: "Invalid params",
        data: {
          address: { field: "from", reason: "checksum" },
          message: "from has an invalid EIP-55 checksum",
        },
      }),
    );
    const invalidTarget = input(lower);
    const call = invalidTarget[0]?.calls[0];
    if (!call) throw new Error("missing call");
    call.to = wrong;
    expect(() => captureWalletSendCallsParams(invalidTarget, 143)).toThrowError(
      expect.objectContaining({
        code: -32602,
        data: {
          address: { field: "to", reason: "checksum" },
          message: "to has an invalid EIP-55 checksum",
        },
      }),
    );
  });
  it("preserves the exact prepared operation and hash across address forms", () => {
    for (const address of [checked, upper]) {
      expect(prepareUserOperation(preparation(address))).toEqual(
        prepareUserOperation(preparation(lower)),
      );
    }
    expect(() => prepareUserOperation(preparation(wrong))).toThrow(/EntryPoint address.*checksum/u);
  });
  it("normalizes static paymasters and preserves their configuration hashes", () => {
    for (const address of [checked, upper]) {
      expect(captureErc7902StaticPaymasterConfiguration(paymaster(address))).toEqual(
        captureErc7902StaticPaymasterConfiguration(paymaster(lower)),
      );
      expect(hashErc7902StaticPaymasterConfiguration(paymaster(address))).toBe(
        hashErc7902StaticPaymasterConfiguration(paymaster(lower)),
      );
    }
    expect(() => captureErc7902StaticPaymasterConfiguration(paymaster(wrong))).toThrow(
      /paymaster.*checksum/u,
    );
  });
  it("rejects an invalid wallet account before requesting a signature", () => {
    let signatures = 0;
    const key = (address: `0x${string}`) =>
      kernelKey({
        validator: lower,
        wallet: {
          account: { address },
          signMessage: async () => {
            signatures++;
            throw new Error("not requested");
          },
        },
      });
    expect(key(checked).publicMaterial).toBe(lower);
    expect(key(upper).publicMaterial).toBe(lower);
    expect(() => key(wrong)).toThrow(/address.*checksum/u);
    expect(signatures).toBe(0);
  });
});
