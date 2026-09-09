import { describe, expect, it } from "vitest";
import { kernelPermissionInstallNonce } from "../src/kernel.js";

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
