/** Closed wallet capability registry behavior. */
import { describe, expect, it } from "vitest";
import {
  advertiseWalletCapabilities,
  applyWalletCapabilities,
  captureAtomicCapability,
  isHandledWalletCapability,
} from "../src/provider/capabilities.js";
import {
  ATOMICITY_UNSUPPORTED,
  INVALID_PARAMS,
  OaathProviderRpcError,
} from "../src/provider/errors.js";

const CALL = Object.freeze({
  to: `0x${"ab".repeat(20)}` as const,
  data: "0x1234" as const,
});

describe("closed wallet capability registry", () => {
  it("owns Final atomic capture, application, and advertisement", () => {
    const atomic = captureAtomicCapability(true);
    const calls = Object.freeze([CALL]);
    const effect = applyWalletCapabilities({
      atomic,
      calls,
      chainId: 421_614,
      atomicExecution: true,
    });

    expect(atomic).toEqual({ atomicRequired: true });
    expect(Object.isFrozen(atomic)).toBe(true);
    expect(effect).toEqual({ atomic: true, calls });
    expect(effect.calls).toBe(calls);
    expect(Object.isFrozen(effect)).toBe(true);
    expect(advertiseWalletCapabilities({ atomicExecution: true })).toEqual({
      atomic: { status: "supported" },
    });
    expect(advertiseWalletCapabilities({ atomicExecution: false })).toEqual({});
  });

  it("does not reinterpret atomicRequired as arbitrary capability metadata", () => {
    expect(isHandledWalletCapability("atomic", "bundle")).toBe(false);
    expect(isHandledWalletCapability("atomic", "call")).toBe(false);
    expect(isHandledWalletCapability("paymasterService", "bundle")).toBe(false);
  });

  it("rejects invalid atomic input and unsupported required execution", () => {
    for (const value of [undefined, null, 0, "true"]) {
      expect(() => captureAtomicCapability(value)).toThrowError(
        expect.objectContaining({ code: INVALID_PARAMS }),
      );
    }

    expect(() =>
      applyWalletCapabilities({
        atomic: captureAtomicCapability(true),
        calls: Object.freeze([CALL]),
        chainId: 421_614,
        atomicExecution: false,
      }),
    ).toThrowError(expect.objectContaining({ code: ATOMICITY_UNSUPPORTED }));
    try {
      applyWalletCapabilities({
        atomic: captureAtomicCapability(true),
        calls: Object.freeze([CALL]),
        chainId: 421_614,
        atomicExecution: false,
      });
    } catch (error) {
      expect(error).toBeInstanceOf(OaathProviderRpcError);
    }
  });
});
