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
      registeredPaymasterServiceUrl: null,
    });

    expect(atomic).toEqual({ atomicRequired: true });
    expect(Object.isFrozen(atomic)).toBe(true);
    expect(effect).toEqual({ atomic: true, calls, paymasterService: null });
    expect(effect.calls).toBe(calls);
    expect(Object.isFrozen(effect)).toBe(true);
    expect(advertiseWalletCapabilities({ atomicExecution: true })).toEqual({
      atomic: { status: "supported" },
    });
    expect(advertiseWalletCapabilities({ atomicExecution: true, paymasterService: true })).toEqual({
      atomic: { status: "supported" },
      paymasterService: { supported: true },
    });
    expect(advertiseWalletCapabilities({ atomicExecution: false })).toEqual({});
  });

  it("scopes metadata handlers to one wallet method and location", () => {
    expect(isHandledWalletCapability("atomic", "wallet_sendCalls", "bundle")).toBe(false);
    expect(isHandledWalletCapability("atomic", "wallet_sendCalls", "call")).toBe(false);
    expect(isHandledWalletCapability("paymasterService", "wallet_sendCalls", "bundle")).toBe(true);
    expect(isHandledWalletCapability("paymasterService", "wallet_sendCalls", "call")).toBe(false);
    expect(isHandledWalletCapability("paymasterService", "wallet_prepareCalls", "bundle")).toBe(
      false,
    );
    expect(
      isHandledWalletCapability("paymasterService", "wallet_sendPreparedCalls", "bundle"),
    ).toBe(false);
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
        registeredPaymasterServiceUrl: null,
      }),
    ).toThrowError(expect.objectContaining({ code: ATOMICITY_UNSUPPORTED }));
    try {
      applyWalletCapabilities({
        atomic: captureAtomicCapability(true),
        calls: Object.freeze([CALL]),
        chainId: 421_614,
        atomicExecution: false,
        registeredPaymasterServiceUrl: null,
      });
    } catch (error) {
      expect(error).toBeInstanceOf(OaathProviderRpcError);
    }
  });

  it("selects only the registered paymaster URL and fails closed for required mismatches", () => {
    const url = "https://relay.example/chains/421614/paymaster";
    const context = Object.freeze({ policy: "sponsored" });
    const capabilities = Object.freeze({
      values: Object.freeze({}),
      ignored: Object.freeze([]),
      paymasterService: Object.freeze({ url, context, optional: false }),
    });
    const selected = applyWalletCapabilities({
      atomic: captureAtomicCapability(false),
      calls: Object.freeze([CALL]),
      chainId: 421_614,
      atomicExecution: true,
      capabilities,
      registeredPaymasterServiceUrl: url,
    });
    expect(selected.paymasterService).toEqual({ url, context });
    expect(selected.paymasterService?.context).toBe(context);
    expect(Object.isFrozen(selected.paymasterService)).toBe(true);

    for (const registeredPaymasterServiceUrl of [null, "https://other.example/paymaster"]) {
      expect(() =>
        applyWalletCapabilities({
          atomic: captureAtomicCapability(false),
          calls: Object.freeze([CALL]),
          chainId: 421_614,
          atomicExecution: true,
          capabilities,
          registeredPaymasterServiceUrl,
        }),
      ).toThrowError(expect.objectContaining({ code: 5700 }));

      expect(
        applyWalletCapabilities({
          atomic: captureAtomicCapability(false),
          calls: Object.freeze([CALL]),
          chainId: 421_614,
          atomicExecution: true,
          capabilities: Object.freeze({
            ...capabilities,
            paymasterService: Object.freeze({
              ...capabilities.paymasterService,
              optional: true,
            }),
          }),
          registeredPaymasterServiceUrl,
        }).paymasterService,
      ).toBeNull();
    }
  });
});
