/**
 * Exact hostile-input capture for OAAth's experimental ERC-7836 profile.
 *
 * @author taek <leekt216@gmail.com>
 */
import { describe, expect, it } from "vitest";
import { applyWalletCapabilities, captureAtomicCapability } from "../src/provider/capabilities.js";
import {
  captureWalletPrepareCallsParams,
  captureWalletSendPreparedCallsParams,
  ERC7836_CAPTURE_LIMITS,
  hashCapturedWalletPrepareCallsRequest,
  hashCapturedWalletSendPreparedCallsRequest,
  OAATH_PREPARED_CALL_CONTEXT_TOKEN_VERSION,
} from "../src/provider/capture.js";
import {
  BUNDLE_TOO_LARGE,
  CONTRACT_CREATION_UNSUPPORTED,
  INVALID_PARAMS,
  OAATH_PROVIDER_ERROR_MESSAGES,
  type OaathProviderErrorCode,
  UNSUPPORTED_CAPABILITY,
  UNSUPPORTED_CHAIN,
} from "../src/provider/errors.js";

const CHAIN = 421_614;
const CHAIN_ID = `0x${CHAIN.toString(16)}`;
const TARGET_A = `0x${"ab".repeat(20)}`;
const TARGET_B = `0x${"cd".repeat(20)}`;
const SECP256K1_PUBLIC_KEY = `0x04${"11".repeat(64)}`;
const WEBAUTHN_PUBLIC_KEY = `0x${"22".repeat(65)}`;
const CONTEXT_ID = `0x${"33".repeat(32)}`;

function secp256k1Key(): Record<string, unknown> {
  return {
    type: "secp256k1",
    publicKey: SECP256K1_PUBLIC_KEY,
    prehash: false,
  };
}

function webauthnKey(publicKey: string = WEBAUTHN_PUBLIC_KEY): Record<string, unknown> {
  return {
    type: "webauthn-p256",
    publicKey,
    prehash: false,
  };
}

function basePrepare(overrides: Readonly<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    version: "1",
    calls: [{ to: TARGET_A }],
    key: secp256k1Key(),
    ...overrides,
  };
}

function baseSend(overrides: Readonly<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    version: "1",
    chainId: CHAIN_ID,
    capabilities: {},
    context: {
      version: OAATH_PREPARED_CALL_CONTEXT_TOKEN_VERSION,
      id: CONTEXT_ID,
    },
    key: secp256k1Key(),
    signature: "0x44",
    ...overrides,
  };
}

function capturePrepare(value: unknown = basePrepare(), chainId: number = CHAIN) {
  return captureWalletPrepareCallsParams([value], chainId);
}

function captureSend(value: unknown = baseSend(), chainId: number = CHAIN) {
  return captureWalletSendPreparedCallsParams([value], chainId);
}

function expectRpcError(action: () => unknown, code: OaathProviderErrorCode): void {
  expect(action).toThrowError(
    expect.objectContaining({
      name: "OaathProviderRpcError",
      code,
      message: OAATH_PROVIDER_ERROR_MESSAGES[code],
    }),
  );
}

function expectDeepFrozen(value: unknown, seen: WeakSet<object> = new WeakSet()): void {
  if (value === null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  expect(Object.isFrozen(value)).toBe(true);
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if ("value" in descriptor) expectDeepFrozen(descriptor.value, seen);
  }
}

describe("wallet_prepareCalls experimental capture", () => {
  it("captures one exact v1 request and preserves capability dispositions for application", () => {
    const captured = capturePrepare(
      basePrepare({
        from: `0x${"AB".repeat(20)}`,
        calls: [
          {
            to: `0x${"CD".repeat(20)}`,
            data: "0xAABB",
            value: "0x0",
            capabilities: {
              callHint: { optional: true, label: "keep-call" },
            },
          },
          { to: TARGET_A, value: "0x1" },
        ],
        capabilities: {
          bundleHint: { optional: true, nested: { label: "keep-bundle" } },
        },
      }),
    );

    expect(captured).toEqual({
      version: "1",
      chainId: CHAIN_ID,
      from: TARGET_A,
      calls: [
        {
          to: TARGET_B,
          data: "0xaabb",
          value: "0x0",
          capabilities: {
            values: { callHint: { optional: true, label: "keep-call" } },
            ignored: ["callHint"],
          },
        },
        { to: TARGET_A, value: "0x1" },
      ],
      capabilities: {
        values: { bundleHint: { optional: true, nested: { label: "keep-bundle" } } },
        ignored: ["bundleHint"],
      },
      key: {
        type: "secp256k1",
        publicKey: SECP256K1_PUBLIC_KEY,
        prehash: false,
      },
    });
    expect(Object.hasOwn(captured, "id")).toBe(false);
    expect(Object.hasOwn(captured, "atomicRequired")).toBe(false);
    expect(Object.getPrototypeOf(captured)).toBeNull();
    expectDeepFrozen(captured);

    const applied = applyWalletCapabilities({
      atomic: captureAtomicCapability(true),
      calls: captured.calls,
      chainId: CHAIN,
      atomicExecution: true,
      registeredPaymasterServiceUrl: null,
      staticPaymasterConfigurationHash: null,
    });
    expect(applied.calls).toBe(captured.calls);
  });

  it("binds hashes to ordered normalized calls, capabilities, and the requested key", () => {
    const first = capturePrepare(
      basePrepare({
        calls: [{ to: TARGET_A }, { to: TARGET_B, data: "0x12" }],
        capabilities: { hint: { optional: true, value: 1 } },
      }),
    );
    const equivalent = capturePrepare({
      key: secp256k1Key(),
      calls: [{ to: TARGET_A }, { data: "0x12", to: TARGET_B }],
      capabilities: { hint: { value: 1, optional: true } },
      chainId: `0x${CHAIN_ID.slice(2).toUpperCase()}`,
      version: "1",
    });
    const reversed = capturePrepare(
      basePrepare({ calls: [{ to: TARGET_B, data: "0x12" }, { to: TARGET_A }] }),
    );

    const hash = hashCapturedWalletPrepareCallsRequest(first);
    expect(hash).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(hashCapturedWalletPrepareCallsRequest(equivalent)).toBe(hash);
    expect(hashCapturedWalletPrepareCallsRequest(reversed)).not.toBe(hash);
  });

  it("requires only version, calls, and key while rejecting Draft aliases", () => {
    for (const key of ["version", "calls", "key"]) {
      const input = basePrepare();
      Reflect.deleteProperty(input, key);
      expectRpcError(() => capturePrepare(input), INVALID_PARAMS);
    }
    for (const input of [
      basePrepare({ version: "2.0.0" }),
      basePrepare({ chainId: undefined }),
      basePrepare({ from: undefined }),
      basePrepare({ capabilities: undefined }),
      basePrepare({ id: "app-id" }),
      basePrepare({ atomicRequired: true }),
      basePrepare({ calls: [] }),
    ]) {
      expectRpcError(() => capturePrepare(input), INVALID_PARAMS);
    }

    expect(capturePrepare(basePrepare({ chainId: CHAIN_ID })).chainId).toBe(CHAIN_ID);
    expect(capturePrepare(basePrepare({ chainId: "0xA" }), 10).chainId).toBe("0xa");
    for (const chainId of ["0x0", "0x01", "0x0A", "0X1"]) {
      expectRpcError(() => capturePrepare(basePrepare({ chainId })), INVALID_PARAMS);
    }
    expectRpcError(() => capturePrepare(basePrepare({ chainId: "0xA" }), 11), UNSUPPORTED_CHAIN);

    expectRpcError(() => captureWalletPrepareCallsParams([], CHAIN), INVALID_PARAMS);
    expectRpcError(
      () => captureWalletPrepareCallsParams([basePrepare(), basePrepare()], CHAIN),
      INVALID_PARAMS,
    );
    const sparse: unknown[] = new Array(1);
    expectRpcError(() => captureWalletPrepareCallsParams(sparse, CHAIN), INVALID_PARAMS);
  });

  it("reuses the closed EIP-5792 call grammar and limits", () => {
    const exactCalls = Array.from({ length: 64 }, () => ({ to: TARGET_A }));
    expect(capturePrepare(basePrepare({ calls: exactCalls })).calls).toHaveLength(64);
    expectRpcError(
      () => capturePrepare(basePrepare({ calls: [...exactCalls, { to: TARGET_A }] })),
      BUNDLE_TOO_LARGE,
    );
    expectRpcError(
      () => capturePrepare(basePrepare({ calls: [{ to: TARGET_A, gas: "0x1" }] })),
      INVALID_PARAMS,
    );
    expectRpcError(
      () => capturePrepare(basePrepare({ calls: [{ data: "0x6000" }] })),
      CONTRACT_CREATION_UNSUPPORTED,
    );
    expectRpcError(
      () => capturePrepare(basePrepare({ capabilities: { required: {} } })),
      UNSUPPORTED_CAPABILITY,
    );
  });

  it("does not enable paymasterService for experimental prepared calls", () => {
    const paymasterService = {
      url: "https://relay.example/chains/421614/paymaster",
      context: {},
    };
    expectRpcError(
      () => capturePrepare(basePrepare({ capabilities: { paymasterService } })),
      UNSUPPORTED_CAPABILITY,
    );
    expect(
      capturePrepare(
        basePrepare({
          capabilities: { paymasterService: { ...paymasterService, optional: true } },
        }),
      ).capabilities,
    ).toEqual({
      values: { paymasterService: { ...paymasterService, optional: true } },
      ignored: ["paymasterService"],
    });

    expectRpcError(
      () => captureSend(baseSend({ capabilities: { paymasterService } })),
      UNSUPPORTED_CAPABILITY,
    );
    expect(
      captureSend(
        baseSend({
          capabilities: { paymasterService: { ...paymasterService, optional: true } },
        }),
      ).capabilities,
    ).toEqual({
      values: { paymasterService: { ...paymasterService, optional: true } },
      ignored: ["paymasterService"],
    });
  });

  it("does not enable static paymasters for experimental prepared calls", () => {
    const staticPaymasterConfiguration = {
      paymaster: `0x${"33".repeat(20)}`,
      paymasterData: "0xdeadbeef",
      paymasterValidationGasLimit: "0x9c40",
      paymasterPostOpGasLimit: "0xc350",
    };
    for (const capture of [capturePrepare, captureSend]) {
      expectRpcError(
        () =>
          capture(
            capture === capturePrepare
              ? basePrepare({ capabilities: { staticPaymasterConfiguration } })
              : baseSend({ capabilities: { staticPaymasterConfiguration } }),
          ),
        UNSUPPORTED_CAPABILITY,
      );
      const optional = { ...staticPaymasterConfiguration, optional: true };
      const captured = capture(
        capture === capturePrepare
          ? basePrepare({ capabilities: { staticPaymasterConfiguration: optional } })
          : baseSend({ capabilities: { staticPaymasterConfiguration: optional } }),
      );
      expect(captured.capabilities).toEqual({
        values: { staticPaymasterConfiguration: optional },
        ignored: ["staticPaymasterConfiguration"],
      });
    }
  });
});

describe("prepared-call key capture", () => {
  it("accepts exact uncompressed secp256k1 and bounded lowercase WebAuthn bytes", () => {
    expect(capturePrepare().key.publicKey).toBe(SECP256K1_PUBLIC_KEY);
    const exactWebAuthn = `0x${"ab".repeat(ERC7836_CAPTURE_LIMITS.webauthnPublicKeyBytes)}`;
    expect(capturePrepare(basePrepare({ key: webauthnKey(exactWebAuthn) })).key).toEqual({
      type: "webauthn-p256",
      publicKey: exactWebAuthn,
      prehash: false,
    });
  });

  it("rejects key aliases, unsupported types, prehashing, and noncanonical material", () => {
    const invalidKeys: readonly unknown[] = [
      { type: "secp256k1", publicKey: SECP256K1_PUBLIC_KEY },
      { ...secp256k1Key(), prehash: true },
      { ...secp256k1Key(), type: "p256" },
      { ...secp256k1Key(), extra: true },
      { ...secp256k1Key(), publicKey: `0x03${"11".repeat(64)}` },
      { ...secp256k1Key(), publicKey: `0x04${"11".repeat(63)}` },
      { ...secp256k1Key(), publicKey: SECP256K1_PUBLIC_KEY.toUpperCase() },
      webauthnKey("0x"),
      webauthnKey("0xabc"),
      webauthnKey("0xAA"),
      webauthnKey(`0x${"ab".repeat(ERC7836_CAPTURE_LIMITS.webauthnPublicKeyBytes + 1)}`),
    ];
    for (const key of invalidKeys) {
      expectRpcError(() => capturePrepare(basePrepare({ key })), INVALID_PARAMS);
    }
  });

  it("does not invoke hostile key accessors", () => {
    let invoked = false;
    const key = secp256k1Key();
    Object.defineProperty(key, "publicKey", {
      enumerable: true,
      get() {
        invoked = true;
        return SECP256K1_PUBLIC_KEY;
      },
    });
    expectRpcError(() => capturePrepare(basePrepare({ key })), INVALID_PARAMS);
    expect(invoked).toBe(false);
  });
});

describe("wallet_sendPreparedCalls experimental capture", () => {
  it("captures the exact echoed envelope, opaque token, key, and strict signature", () => {
    const captured = captureSend(
      baseSend({
        capabilities: { hint: { optional: true, label: "echo" } },
        key: webauthnKey(),
        signature: "0xaabb",
      }),
    );

    expect(captured).toEqual({
      version: "1",
      chainId: CHAIN_ID,
      capabilities: {
        values: { hint: { optional: true, label: "echo" } },
        ignored: ["hint"],
      },
      context: {
        version: OAATH_PREPARED_CALL_CONTEXT_TOKEN_VERSION,
        id: CONTEXT_ID,
      },
      key: {
        type: "webauthn-p256",
        publicKey: WEBAUTHN_PUBLIC_KEY,
        prehash: false,
      },
      signature: "0xaabb",
    });
    expect(Object.getPrototypeOf(captured)).toBeNull();
    expectDeepFrozen(captured);

    const hash = hashCapturedWalletSendPreparedCallsRequest(captured);
    const equivalent = captureSend(
      baseSend({
        chainId: `0x${CHAIN_ID.slice(2).toUpperCase()}`,
        capabilities: { hint: { label: "echo", optional: true } },
        key: webauthnKey(),
        signature: "0xaabb",
      }),
    );
    const changed = captureSend(baseSend({ signature: "0xaabc" }));
    expect(hash).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(equivalent).toEqual(captured);
    expect(hashCapturedWalletSendPreparedCallsRequest(equivalent)).toBe(hash);
    expect(hashCapturedWalletSendPreparedCallsRequest(changed)).not.toBe(hash);
  });

  it("requires one object with every exact echoed field", () => {
    for (const key of ["version", "chainId", "capabilities", "context", "key", "signature"]) {
      const input = baseSend();
      Reflect.deleteProperty(input, key);
      expectRpcError(() => captureSend(input), INVALID_PARAMS);
    }
    for (const input of [
      baseSend({ version: "2" }),
      baseSend({ digest: CONTEXT_ID }),
      baseSend({ calls: [{ to: TARGET_A }] }),
    ]) {
      expectRpcError(() => captureSend(input), INVALID_PARAMS);
    }
    expect(captureSend(baseSend({ chainId: "0xA" }), 10).chainId).toBe("0xa");
    for (const chainId of ["0x0", "0x01", "0x0A", "0X1"]) {
      expectRpcError(() => captureSend(baseSend({ chainId })), INVALID_PARAMS);
    }
    expectRpcError(() => captureSend(baseSend({ chainId: "0xA" }), 11), UNSUPPORTED_CHAIN);

    expectRpcError(() => captureWalletSendPreparedCallsParams([], CHAIN), INVALID_PARAMS);
    expectRpcError(
      () => captureWalletSendPreparedCallsParams([baseSend(), baseSend()], CHAIN),
      INVALID_PARAMS,
    );
    const sparse: unknown[] = new Array(1);
    expectRpcError(() => captureWalletSendPreparedCallsParams(sparse, CHAIN), INVALID_PARAMS);
  });

  it("accepts only the exact lowercase context token and nonempty bounded signature bytes", () => {
    const exactSignature = `0x${"ab".repeat(ERC7836_CAPTURE_LIMITS.signatureBytes)}`;
    expect(captureSend(baseSend({ signature: exactSignature })).signature).toBe(exactSignature);

    const invalidContexts: readonly unknown[] = [
      { version: OAATH_PREPARED_CALL_CONTEXT_TOKEN_VERSION, id: CONTEXT_ID, extra: true },
      { version: "oaath.prepared-call-context-token/v2", id: CONTEXT_ID },
      { version: OAATH_PREPARED_CALL_CONTEXT_TOKEN_VERSION, id: `0x${"AA".repeat(32)}` },
      { version: OAATH_PREPARED_CALL_CONTEXT_TOKEN_VERSION, id: "0x12" },
    ];
    for (const context of invalidContexts) {
      expectRpcError(() => captureSend(baseSend({ context })), INVALID_PARAMS);
    }
    for (const signature of [
      "0x",
      "0xabc",
      "0xAA",
      `0x${"ab".repeat(ERC7836_CAPTURE_LIMITS.signatureBytes + 1)}`,
    ]) {
      expectRpcError(() => captureSend(baseSend({ signature })), INVALID_PARAMS);
    }
    expectRpcError(
      () => captureSend(baseSend({ capabilities: { required: {} } })),
      UNSUPPORTED_CAPABILITY,
    );
  });
});
