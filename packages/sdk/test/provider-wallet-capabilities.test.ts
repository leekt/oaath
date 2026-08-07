/** Closed wallet capability registry behavior. */
import { describe, expect, it } from "vitest";
import {
  advertiseWalletCapabilities,
  applyWalletCapabilities,
  captureAtomicCapability,
  captureStaticPaymasterConfigurationCapability,
  isHandledWalletCapability,
} from "../src/provider/capabilities.js";
import {
  ATOMICITY_UNSUPPORTED,
  INVALID_PARAMS,
  OaathProviderRpcError,
  UNSUPPORTED_CAPABILITY,
} from "../src/provider/errors.js";

const CALL = Object.freeze({
  to: `0x${"ab".repeat(20)}` as const,
  data: "0x1234" as const,
});
const STATIC_PAYMASTER_HASH = `0x${"11".repeat(32)}` as `0x${string}`;

function staticPaymasterConfiguration(optional = false) {
  return Object.freeze({
    paymaster: `0x${"33".repeat(20)}`,
    paymasterData: "0xdeadbeef",
    paymasterValidationGasLimit: "0x9c40",
    paymasterPostOpGasLimit: "0xc350",
    ...(optional ? { optional: true } : {}),
  });
}

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
      staticPaymasterConfigurationHash: null,
    });

    expect(atomic).toEqual({ atomicRequired: true });
    expect(Object.isFrozen(atomic)).toBe(true);
    expect(effect).toEqual({ atomic: true, calls, paymaster: null });
    expect(effect.calls).toBe(calls);
    expect(Object.isFrozen(effect)).toBe(true);
    expect(
      advertiseWalletCapabilities({
        atomicExecution: true,
        staticPaymasterConfigurationHash: null,
      }),
    ).toEqual({
      atomic: { status: "supported" },
    });
    expect(
      advertiseWalletCapabilities({
        atomicExecution: true,
        paymasterService: true,
        staticPaymasterConfigurationHash: STATIC_PAYMASTER_HASH,
      }),
    ).toEqual({
      atomic: { status: "supported" },
      paymasterService: { supported: true },
      staticPaymasterConfiguration: { supported: true, status: "experimental" },
    });
    expect(
      advertiseWalletCapabilities({
        atomicExecution: false,
        staticPaymasterConfigurationHash: null,
      }),
    ).toEqual({});
  });

  it("scopes metadata handlers to one wallet method and location", () => {
    expect(isHandledWalletCapability("atomic", "wallet_sendCalls", "bundle")).toBe(false);
    expect(isHandledWalletCapability("atomic", "wallet_sendCalls", "call")).toBe(false);
    expect(isHandledWalletCapability("paymasterService", "wallet_sendCalls", "bundle")).toBe(true);
    expect(isHandledWalletCapability("paymasterService", "wallet_sendCalls", "call")).toBe(false);
    expect(isHandledWalletCapability("paymasterService", "wallet_prepareCalls", "bundle")).toBe(
      true,
    );
    expect(
      isHandledWalletCapability("paymasterService", "wallet_sendPreparedCalls", "bundle"),
    ).toBe(true);
    expect(isHandledWalletCapability("paymasterService", "wallet_prepareCalls", "call")).toBe(
      false,
    );
    expect(isHandledWalletCapability("paymasterService", "wallet_sendPreparedCalls", "call")).toBe(
      false,
    );
    expect(
      isHandledWalletCapability("staticPaymasterConfiguration", "wallet_sendCalls", "bundle"),
    ).toBe(true);
    expect(
      isHandledWalletCapability("staticPaymasterConfiguration", "wallet_sendCalls", "call"),
    ).toBe(false);
    expect(
      isHandledWalletCapability("staticPaymasterConfiguration", "wallet_prepareCalls", "bundle"),
    ).toBe(false);
    expect(
      isHandledWalletCapability(
        "staticPaymasterConfiguration",
        "wallet_sendPreparedCalls",
        "bundle",
      ),
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
        staticPaymasterConfigurationHash: null,
      }),
    ).toThrowError(expect.objectContaining({ code: ATOMICITY_UNSUPPORTED }));
    try {
      applyWalletCapabilities({
        atomic: captureAtomicCapability(true),
        calls: Object.freeze([CALL]),
        chainId: 421_614,
        atomicExecution: false,
        registeredPaymasterServiceUrl: null,
        staticPaymasterConfigurationHash: null,
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
      staticPaymasterConfigurationHash: null,
    });
    expect(selected.paymaster).toEqual({ kind: "erc7677", url, context });
    expect(selected.paymaster?.kind === "erc7677" && selected.paymaster.context).toBe(context);
    expect(Object.isFrozen(selected.paymaster)).toBe(true);

    for (const registeredPaymasterServiceUrl of [null, "https://other.example/paymaster"]) {
      expect(() =>
        applyWalletCapabilities({
          atomic: captureAtomicCapability(false),
          calls: Object.freeze([CALL]),
          chainId: 421_614,
          atomicExecution: true,
          capabilities,
          registeredPaymasterServiceUrl,
          staticPaymasterConfigurationHash: null,
        }),
      ).toThrowError(expect.objectContaining({ code: UNSUPPORTED_CAPABILITY }));

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
          staticPaymasterConfigurationHash: null,
        }).paymaster,
      ).toBeNull();
    }
  });

  it("selects only the authenticated static configuration and rejects competing sources", () => {
    const configuration = staticPaymasterConfiguration();
    const captured = captureStaticPaymasterConfigurationCapability(configuration);
    const capabilities = Object.freeze({
      values: Object.freeze({ staticPaymasterConfiguration: configuration }),
      ignored: Object.freeze([]),
      staticPaymasterConfiguration: captured,
    });
    const selected = applyWalletCapabilities({
      atomic: captureAtomicCapability(false),
      calls: Object.freeze([CALL]),
      chainId: 421_614,
      atomicExecution: true,
      capabilities,
      registeredPaymasterServiceUrl: null,
      staticPaymasterConfigurationHash: captured.configurationHash,
    });

    expect(selected.paymaster).toEqual({ kind: "erc7902-static", configuration });
    expect(selected.paymaster?.kind === "erc7902-static" && selected.paymaster.configuration).toBe(
      configuration,
    );
    expect(Object.isFrozen(selected.paymaster)).toBe(true);
    expect(Object.isFrozen(captured)).toBe(true);
    expect(Object.isFrozen(captured.paymaster)).toBe(true);

    for (const staticPaymasterConfigurationHash of [null, STATIC_PAYMASTER_HASH]) {
      expect(() =>
        applyWalletCapabilities({
          atomic: captureAtomicCapability(false),
          calls: Object.freeze([CALL]),
          chainId: 421_614,
          atomicExecution: true,
          capabilities,
          registeredPaymasterServiceUrl: null,
          staticPaymasterConfigurationHash,
        }),
      ).toThrowError(expect.objectContaining({ code: UNSUPPORTED_CAPABILITY }));
    }

    const optionalConfiguration = staticPaymasterConfiguration(true);
    expect(
      applyWalletCapabilities({
        atomic: captureAtomicCapability(false),
        calls: Object.freeze([CALL]),
        chainId: 421_614,
        atomicExecution: true,
        capabilities: Object.freeze({
          values: Object.freeze({ staticPaymasterConfiguration: optionalConfiguration }),
          ignored: Object.freeze([]),
          staticPaymasterConfiguration:
            captureStaticPaymasterConfigurationCapability(optionalConfiguration),
        }),
        registeredPaymasterServiceUrl: null,
        staticPaymasterConfigurationHash: STATIC_PAYMASTER_HASH,
      }).paymaster,
    ).toBeNull();

    const url = "https://relay.example/chains/421614/paymaster";
    const context = Object.freeze({ policy: "competing" });
    expect(() =>
      applyWalletCapabilities({
        atomic: captureAtomicCapability(false),
        calls: Object.freeze([CALL]),
        chainId: 421_614,
        atomicExecution: true,
        capabilities: Object.freeze({
          ...capabilities,
          paymasterService: Object.freeze({ url, context, optional: true }),
        }),
        registeredPaymasterServiceUrl: "https://other.example/paymaster",
        staticPaymasterConfigurationHash: null,
      }),
    ).toThrowError(expect.objectContaining({ code: INVALID_PARAMS }));
  });
});
