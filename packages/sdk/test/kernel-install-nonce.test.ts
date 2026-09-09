import { decodeFunctionData, parseAbi } from "viem";
import { describe, expect, it } from "vitest";
import {
  encodeKernelV4InstallNonceInvalidationCall,
  encodeKernelV4InstallNonceRead,
  kernelPermissionInstallNonce,
} from "../src/kernel.js";

const account = `0x${"66".repeat(20)}` as const;
const nonceAbi = parseAbi([
  "function nonce(uint192 key) view returns (uint256)",
  "function setNonce(uint192 nonceKey, uint64 seq)",
]);

describe("permission install nonce derivation", () => {
  it("uses the first 192 request-hash bits as the key, starting at sequence zero", () => {
    const requestHash = `0x${"12".repeat(24)}${"34".repeat(8)}` as const;
    const nonce = BigInt(kernelPermissionInstallNonce(requestHash));
    expect(nonce >> 64n).toBe(BigInt(`0x${"12".repeat(24)}`));
    expect(nonce & ((1n << 64n) - 1n)).toBe(0n);
    expect(kernelPermissionInstallNonce(requestHash)).toBe(nonce.toString(10));
    expect(kernelPermissionInstallNonce(`0x${"ff".repeat(32)}`)).toBe(
      (((1n << 192n) - 1n) << 64n).toString(10),
    );
  });

  it.each(["0x", `0x${"11".repeat(31)}`, `0x${"11".repeat(33)}`, "request-1"])(
    "refuses a non-hash input",
    (input) => {
      expect(() => kernelPermissionInstallNonce(input as `0x${string}`)).toThrowError(
        expect.objectContaining({ code: "kernel_runtime_input_invalid" }),
      );
    },
  );
});

describe("Kernel install nonce invalidation codecs", () => {
  it("targets the same install key at the next sequence with a zero-value self-call", () => {
    const key = (1n << 192n) - 1n;
    const installNonce = ((key << 64n) | 7n).toString(10);
    const call = encodeKernelV4InstallNonceInvalidationCall({ account, installNonce });
    expect(call.target).toBe(account);
    expect(call.value).toBe("0");
    expect(decodeFunctionData({ abi: nonceAbi, data: call.data })).toEqual({
      functionName: "setNonce",
      args: [key, 8n],
    });
    expect(
      decodeFunctionData({
        abi: nonceAbi,
        data: encodeKernelV4InstallNonceRead({ key: key.toString(10) }),
      }),
    ).toEqual({ functionName: "nonce", args: [key] });
  });

  it("refuses an exhausted sequence instead of overflowing into another install key", () => {
    expect(() =>
      encodeKernelV4InstallNonceInvalidationCall({
        account,
        installNonce: ((9n << 64n) | ((1n << 64n) - 1n)).toString(10),
      }),
    ).toThrowError(expect.objectContaining({ code: "signing_request_invalid" }));
  });
});
