/**
 * Final EIP-5792 `wallet_sendCalls` capture at the hostile provider boundary.
 *
 * @author taek <leekt216@gmail.com>
 */
import { describe, expect, it } from "vitest";
import {
  captureWalletGetCapabilitiesParams,
  captureWalletSendCallsParams,
  EIP5792_CAPTURE_LIMITS,
  hashCapturedWalletSendCallsRequest,
  isCanonicalChainId,
  isCanonicalQuantity,
  isHexBytes,
  isWalletAddress,
} from "../src/provider/capture.js";
import {
  ATOMIC_UPGRADE_REJECTED,
  ATOMICITY_UNSUPPORTED,
  BUNDLE_TOO_LARGE,
  CONTRACT_CREATION_UNSUPPORTED,
  DUPLICATE_ID,
  INTERNAL_ERROR,
  INVALID_PARAMS,
  OAATH_PROVIDER_ERROR_MESSAGES,
  type OaathProviderErrorCode,
  OaathProviderRpcError,
  rpcFail,
  UNAUTHORIZED,
  UNKNOWN_BUNDLE_ID,
  UNSUPPORTED_CAPABILITY,
  UNSUPPORTED_CHAIN,
  UNSUPPORTED_METHOD,
  USER_REJECTED_REQUEST,
} from "../src/provider/errors.js";

const CHAIN = 421_614;
const CHAIN_ID = `0x${CHAIN.toString(16)}`;
const TARGET_A = `0x${"ab".repeat(20)}`;
const TARGET_B = `0x${"cd".repeat(20)}`;

function baseBundle(overrides: Readonly<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    version: "2.0.0",
    chainId: CHAIN_ID,
    atomicRequired: true,
    calls: [{ to: TARGET_A }],
    ...overrides,
  };
}

function captureBundle(bundle: unknown = baseBundle(), configuredChain: number = CHAIN) {
  return captureWalletSendCallsParams([bundle], configuredChain);
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

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function optionalCapabilityMapOfSize(bytes: number): Record<string, unknown> {
  const capability = { optional: true, payload: "" };
  const map = { feature: capability };
  const fixedBytes = utf8Bytes(JSON.stringify(map));
  if (fixedBytes > bytes) throw new Error("capability test target is too small");
  capability.payload = "x".repeat(bytes - fixedBytes);
  return map;
}

function bundleOfJsonSize(bytes: number): Record<string, unknown> {
  const call = { to: TARGET_A, value: "0x1" };
  const bundle = baseBundle({ calls: [call] });
  const fixedBytes = utf8Bytes(JSON.stringify(bundle));
  if (fixedBytes > bytes) throw new Error("bundle test target is too small");
  call.value = `0x1${"0".repeat(bytes - fixedBytes)}`;
  return bundle;
}

describe("provider error ownership", () => {
  it("owns every required numeric code with one fixed sanitized message", () => {
    const codes: readonly OaathProviderErrorCode[] = [
      CONTRACT_CREATION_UNSUPPORTED,
      INVALID_PARAMS,
      INTERNAL_ERROR,
      USER_REJECTED_REQUEST,
      UNAUTHORIZED,
      UNSUPPORTED_METHOD,
      UNSUPPORTED_CAPABILITY,
      UNSUPPORTED_CHAIN,
      DUPLICATE_ID,
      UNKNOWN_BUNDLE_ID,
      BUNDLE_TOO_LARGE,
      ATOMIC_UPGRADE_REJECTED,
      ATOMICITY_UNSUPPORTED,
    ];

    expect(Object.isFrozen(OAATH_PROVIDER_ERROR_MESSAGES)).toBe(true);
    for (const code of codes) {
      expectRpcError(() => rpcFail(code, "secret internal owner failure"), code);
      try {
        rpcFail(code, "secret internal owner failure");
      } catch (error) {
        expect(error).toBeInstanceOf(OaathProviderRpcError);
        if (!(error instanceof OaathProviderRpcError)) throw error;
        expect(error.message).toBe(OAATH_PROVIDER_ERROR_MESSAGES[code]);
        expect(error.message).not.toContain("secret");
      }
    }
  });
});

describe("wallet_sendCalls exact capture", () => {
  it("captures the complete Final shape, exact capability JSON, and call order", () => {
    const id = " app:\u0000/日本語/😀/not-hex ";
    const captured = captureBundle({
      version: "2.0.0",
      id,
      from: `0x${"AB".repeat(20)}`,
      chainId: CHAIN_ID,
      atomicRequired: false,
      calls: [
        {
          to: `0x${"CD".repeat(20)}`,
          data: "0xAABB",
          value: "0x0",
          capabilities: {
            callFeature: {
              optional: true,
              label: "Preserve Me",
              nested: [null, false, 1.25, { exact: "値" }],
            },
          },
        },
        { to: TARGET_A, data: "0x", value: "0xabc" },
      ],
      capabilities: {
        topFeature: {
          optional: true,
          text: "Case-Sensitive",
          object: { enabled: true },
        },
      },
    });

    expect(captured).toEqual({
      version: "2.0.0",
      id,
      from: `0x${"ab".repeat(20)}`,
      chainId: CHAIN_ID,
      atomicRequired: false,
      calls: [
        {
          to: TARGET_B,
          data: "0xaabb",
          value: "0x0",
          capabilities: {
            values: {
              callFeature: {
                optional: true,
                label: "Preserve Me",
                nested: [null, false, 1.25, { exact: "値" }],
              },
            },
            ignored: ["callFeature"],
          },
        },
        { to: TARGET_A, data: "0x", value: "0xabc" },
      ],
      capabilities: {
        values: {
          topFeature: {
            optional: true,
            text: "Case-Sensitive",
            object: { enabled: true },
          },
        },
        ignored: ["topFeature"],
      },
    });
    expect(captured.id).toBe(id);
    expect(captured.calls.map((call) => call.to)).toEqual([TARGET_B, TARGET_A]);
  });

  it("detaches from the input and deeply freezes the ordered output", () => {
    const nestedItems = ["before"];
    const capability = { optional: true, nested: { items: nestedItems } };
    const call = {
      to: TARGET_A,
      data: "0x12",
      capabilities: { feature: capability },
    };
    const calls = [call];
    const input = baseBundle({ calls, capabilities: { top: capability } });
    expectRpcError(() => captureBundle(input), INVALID_PARAMS);

    const independentTop = { optional: true, nested: { items: ["top-before"] } };
    input.capabilities = { top: independentTop };
    const captured = captureBundle(input);
    call.data = "0x34";
    nestedItems[0] = "after";
    independentTop.nested.items[0] = "top-after";
    calls.reverse();

    expect(captured.calls[0]?.data).toBe("0x12");
    const callCapabilities = captured.calls[0]?.capabilities;
    const topCapabilities = captured.capabilities;
    if (callCapabilities === undefined || topCapabilities === undefined) {
      throw new Error("expected captured capabilities");
    }
    expect(callCapabilities.values.feature?.nested).toEqual({ items: ["before"] });
    expect(topCapabilities.values.top?.nested).toEqual({ items: ["top-before"] });
    expect(Object.getPrototypeOf(captured)).toBeNull();
    expect(Object.getPrototypeOf(callCapabilities.values.feature)).toBeNull();
    expectDeepFrozen(captured);
    expect(Reflect.set(captured, "chainId", "0x1")).toBe(false);
    expect(Reflect.set(callCapabilities.values.feature ?? {}, "optional", false)).toBe(false);
  });

  it("requires the v2 fields and exact top-level and call key sets", () => {
    for (const key of ["version", "chainId", "atomicRequired", "calls"]) {
      const value = baseBundle();
      Reflect.deleteProperty(value, key);
      expectRpcError(() => captureBundle(value), INVALID_PARAMS);
    }
    for (const value of [
      baseBundle({ version: "1.0.0" }),
      baseBundle({ version: undefined }),
      baseBundle({ chainId: undefined }),
      baseBundle({ atomicRequired: undefined }),
      baseBundle({ atomicRequired: 1 }),
      baseBundle({ calls: undefined }),
      baseBundle({ calls: [] }),
      baseBundle({ unexpected: true }),
      baseBundle({ calls: [{ to: TARGET_A, gas: "0x1" }] }),
      baseBundle({ calls: [{ to: TARGET_A, data: undefined }] }),
      baseBundle({ id: undefined }),
      baseBundle({ from: undefined }),
      baseBundle({ capabilities: undefined }),
    ]) {
      expectRpcError(() => captureBundle(value), INVALID_PARAMS);
    }
  });

  it("requires an ordinary dense one-element params array", () => {
    expectRpcError(() => captureWalletSendCallsParams(undefined, CHAIN), INVALID_PARAMS);
    expectRpcError(() => captureWalletSendCallsParams({}, CHAIN), INVALID_PARAMS);
    expectRpcError(() => captureWalletSendCallsParams([], CHAIN), INVALID_PARAMS);
    expectRpcError(
      () => captureWalletSendCallsParams([baseBundle(), baseBundle()], CHAIN),
      INVALID_PARAMS,
    );

    const sparseParams: unknown[] = new Array(1);
    expectRpcError(() => captureWalletSendCallsParams(sparseParams, CHAIN), INVALID_PARAMS);
    const extraParams = [baseBundle()];
    Object.defineProperty(extraParams, "extra", { value: true, enumerable: true });
    expectRpcError(() => captureWalletSendCallsParams(extraParams, CHAIN), INVALID_PARAMS);
  });
});

describe("canonical fields and identifiers", () => {
  it("recognizes addresses, byte strings, canonical quantities, and positive chain ids", () => {
    expect(isWalletAddress(TARGET_A)).toBe(true);
    expect(isWalletAddress(`0x${"AB".repeat(20)}`)).toBe(true);
    expect(isWalletAddress("0x1")).toBe(false);
    expect(isHexBytes("0x")).toBe(true);
    expect(isHexBytes("0xAAbb")).toBe(true);
    expect(isHexBytes("0xabc")).toBe(false);
    expect(isCanonicalQuantity("0x0")).toBe(true);
    expect(isCanonicalQuantity("0xabc")).toBe(true);
    expect(isCanonicalQuantity("0x00")).toBe(false);
    expect(isCanonicalChainId("0x1")).toBe(true);
    expect(isCanonicalChainId("0xabc")).toBe(true);
    expect(isCanonicalChainId("0xAbC")).toBe(true);
    expect(isCanonicalChainId("0x0")).toBe(false);
  });

  it("accepts compact positive chain ids and normalizes mixed-case digits once", () => {
    expect(captureBundle(baseBundle({ chainId: "0x1" }), 1).chainId).toBe("0x1");
    const lowercase = captureBundle(baseBundle({ chainId: "0xabcdef" }), 0xab_cdef);
    const mixedCase = captureBundle(baseBundle({ chainId: "0xAbCdEf" }), 0xab_cdef);
    expect(lowercase.chainId).toBe("0xabcdef");
    expect(mixedCase.chainId).toBe("0xabcdef");
    expect(hashCapturedWalletSendCallsRequest(mixedCase, "same-id")).toBe(
      hashCapturedWalletSendCallsRequest(lowercase, "same-id"),
    );
    expect(captureWalletGetCapabilitiesParams([TARGET_A, ["0xA", "0xAbCdEf"]]).chainIds).toEqual([
      "0xa",
      "0xabcdef",
    ]);
    for (const chainId of ["0x0", "0x00", "0x01", "0x0A", "0X1", "1", "0x", "0x-1", 1]) {
      expectRpcError(() => captureBundle(baseBundle({ chainId }), 1), INVALID_PARAMS);
    }
  });

  it("accepts canonical quantities and even hex bytes while normalizing byte case", () => {
    for (const value of ["0x0", "0x1", "0xabcdef"]) {
      expect(captureBundle(baseBundle({ calls: [{ to: TARGET_A, value }] })).calls[0]?.value).toBe(
        value,
      );
    }
    expect(
      captureBundle(baseBundle({ calls: [{ to: `0x${"AB".repeat(20)}`, data: "0xAa00" }] }))
        .calls[0],
    ).toEqual({ to: `0x${"ab".repeat(20)}`, data: "0xaa00" });

    for (const value of ["0x", "0x00", "0x01", "0xA", "1", 0, -1]) {
      expectRpcError(
        () => captureBundle(baseBundle({ calls: [{ to: TARGET_A, value }] })),
        INVALID_PARAMS,
      );
    }
    for (const data of ["0x0", "0xabc", "0xgg", "00", 0, null]) {
      expectRpcError(
        () => captureBundle(baseBundle({ calls: [{ to: TARGET_A, data }] })),
        INVALID_PARAMS,
      );
    }
    for (const to of ["0x", `0x${"ab".repeat(19)}`, `0x${"gg".repeat(20)}`, null, 1]) {
      expectRpcError(() => captureBundle(baseBundle({ calls: [{ to }] })), INVALID_PARAMS);
    }
  });

  it("preserves arbitrary nonempty app IDs and enforces the UTF-8 byte boundary", () => {
    for (const id of [" ", "not hex", "\u0000", "日本語/😀/A"]) {
      expect(captureBundle(baseBundle({ id })).id).toBe(id);
    }
    const exact = "😀".repeat(EIP5792_CAPTURE_LIMITS.idUtf8Bytes / 4);
    expect(utf8Bytes(exact)).toBe(EIP5792_CAPTURE_LIMITS.idUtf8Bytes);
    expect(captureBundle(baseBundle({ id: exact })).id).toBe(exact);
    expectRpcError(() => captureBundle(baseBundle({ id: `${exact}a` })), BUNDLE_TOO_LARGE);
    expectRpcError(() => captureBundle(baseBundle({ id: "" })), INVALID_PARAMS);
    expectRpcError(() => captureBundle(baseBundle({ id: 1 })), INVALID_PARAMS);

    const generatedOutsideThisBoundary = captureBundle();
    expect(Object.hasOwn(generatedOutsideThisBoundary, "id")).toBe(false);
  });
});

describe("owned capture limits", () => {
  it("accepts 64 calls and classifies the 65th as a valid oversized bundle", () => {
    const exact = Array.from({ length: EIP5792_CAPTURE_LIMITS.calls }, (_, index) => ({
      to: index % 2 === 0 ? TARGET_A : TARGET_B,
    }));
    expect(captureBundle(baseBundle({ calls: exact })).calls).toHaveLength(
      EIP5792_CAPTURE_LIMITS.calls,
    );
    expectRpcError(
      () => captureBundle(baseBundle({ calls: [...exact, { to: TARGET_A }] })),
      BUNDLE_TOO_LARGE,
    );
  });

  it("enforces the inclusive 128 KiB aggregate decoded-calldata boundary", () => {
    const half = EIP5792_CAPTURE_LIMITS.calldataBytes / 2;
    const exactCalls = [
      { to: TARGET_A, data: `0x${"aa".repeat(half)}` },
      { to: TARGET_B, data: `0x${"bb".repeat(half)}` },
    ];
    expect(captureBundle(baseBundle({ calls: exactCalls })).calls).toHaveLength(2);
    expectRpcError(
      () =>
        captureBundle(
          baseBundle({
            calls: [
              { to: TARGET_A, data: `0x${"aa".repeat(EIP5792_CAPTURE_LIMITS.calldataBytes + 1)}` },
            ],
          }),
        ),
      BUNDLE_TOO_LARGE,
    );
  });

  it("enforces the inclusive 64 KiB aggregate capability-JSON boundary", () => {
    const half = EIP5792_CAPTURE_LIMITS.capabilityJsonBytes / 2;
    const captured = captureBundle(
      baseBundle({
        calls: [{ to: TARGET_A, capabilities: optionalCapabilityMapOfSize(half) }],
        capabilities: optionalCapabilityMapOfSize(half),
      }),
    );
    expect(captured.capabilities?.ignored).toEqual(["feature"]);
    expectRpcError(
      () =>
        captureBundle(
          baseBundle({
            calls: [{ to: TARGET_A, capabilities: optionalCapabilityMapOfSize(half) }],
            capabilities: optionalCapabilityMapOfSize(half + 1),
          }),
        ),
      BUNDLE_TOO_LARGE,
    );
  });

  it("classifies a structurally valid oversized request before capability support", () => {
    expectRpcError(
      () =>
        captureBundle(
          baseBundle({
            calls: [
              { to: TARGET_A, capabilities: { required: {} } },
              {
                to: TARGET_B,
                data: `0x${"aa".repeat(EIP5792_CAPTURE_LIMITS.calldataBytes + 1)}`,
              },
            ],
          }),
        ),
      BUNDLE_TOO_LARGE,
    );
  });

  it("enforces the inclusive 256 KiB aggregate captured-bundle boundary", () => {
    const exact = bundleOfJsonSize(EIP5792_CAPTURE_LIMITS.bundleBytes);
    expect(captureBundle(exact).calls[0]?.value).toMatch(/^0x1[0]+$/u);
    expectRpcError(
      () => captureBundle(bundleOfJsonSize(EIP5792_CAPTURE_LIMITS.bundleBytes + 1)),
      BUNDLE_TOO_LARGE,
    );
  });
});

describe("capability semantics", () => {
  it("captures one exact bundle paymaster selection and retains its request hash material", () => {
    const url = "https://relay.example/chains/421614/paymaster";
    const context = { policy: "sponsored", nested: { quota: 2 } };
    const captured = captureBundle(
      baseBundle({
        capabilities: {
          paymasterService: { url, context, optional: true },
        },
      }),
    );

    expect(captured.capabilities).toEqual({
      values: {
        paymasterService: { url, context, optional: true },
      },
      ignored: [],
      paymasterService: { url, context, optional: true },
    });
    expectDeepFrozen(captured.capabilities);

    const hash = hashCapturedWalletSendCallsRequest(captured, "paymaster-request");
    const changedContext = captureBundle(
      baseBundle({
        capabilities: {
          paymasterService: { url, context: { policy: "self-funded" }, optional: true },
        },
      }),
    );
    const required = captureBundle(
      baseBundle({ capabilities: { paymasterService: { url, context } } }),
    );
    expect(hashCapturedWalletSendCallsRequest(changedContext, "paymaster-request")).not.toBe(hash);
    expect(hashCapturedWalletSendCallsRequest(required, "paymaster-request")).not.toBe(hash);

    expect(
      captureBundle(
        baseBundle({
          capabilities: {
            paymasterService: {
              url: "http://localhost:8787/chains/421614/paymaster",
              context: {},
            },
          },
        }),
      ).capabilities?.paymasterService?.url,
    ).toBe("http://localhost:8787/chains/421614/paymaster");
  });

  it("rejects malformed handled paymaster selections at the bundle boundary", () => {
    const url = "https://relay.example/chains/421614/paymaster";
    for (const paymasterService of [
      { context: {} },
      { url },
      { url, context: {}, extra: true },
      { url: `${url}/`, context: {} },
      { url: "https://Relay.example/chains/421614/paymaster", context: {} },
      { url: "http://relay.example/chains/421614/paymaster", context: {} },
      { url: `${url}?mode=test`, context: {} },
      { url, context: null },
      { url, context: [] },
      { url, context: "opaque" },
    ]) {
      expectRpcError(
        () => captureBundle(baseBundle({ capabilities: { paymasterService } })),
        INVALID_PARAMS,
      );
    }
  });

  it("keeps paymasterService unsupported at call scope", () => {
    const paymasterService = {
      url: "https://relay.example/chains/421614/paymaster",
      context: {},
    };
    expectRpcError(
      () =>
        captureBundle(
          baseBundle({ calls: [{ to: TARGET_A, capabilities: { paymasterService } }] }),
        ),
      UNSUPPORTED_CAPABILITY,
    );

    const captured = captureBundle(
      baseBundle({
        calls: [
          {
            to: TARGET_A,
            capabilities: { paymasterService: { ...paymasterService, optional: true } },
          },
        ],
      }),
    );
    expect(captured.calls[0]?.capabilities).toEqual({
      values: { paymasterService: { ...paymasterService, optional: true } },
      ignored: ["paymasterService"],
    });
  });

  it("retains unknown optional top-level and call capabilities explicitly as ignored", () => {
    const captured = captureBundle(
      baseBundle({
        calls: [
          {
            to: TARGET_A,
            capabilities: {
              callUnknown: { optional: true, scope: "call", nested: { count: 2 } },
            },
          },
        ],
        capabilities: {
          topUnknown: { optional: true, scope: "bundle" },
          atomic: { optional: true, requested: "still-no-handler" },
        },
      }),
    );
    expect(captured.capabilities).toEqual({
      values: {
        topUnknown: { optional: true, scope: "bundle" },
        atomic: { optional: true, requested: "still-no-handler" },
      },
      ignored: ["topUnknown", "atomic"],
    });
    expect(captured.calls[0]?.capabilities).toEqual({
      values: { callUnknown: { optional: true, scope: "call", nested: { count: 2 } } },
      ignored: ["callUnknown"],
    });
    expect(Object.keys(captured.capabilities ?? {})).toEqual(["values", "ignored"]);
  });

  it("returns 5700 for every unknown capability not explicitly optional", () => {
    for (const capability of [{}, { optional: false }]) {
      expectRpcError(
        () => captureBundle(baseBundle({ capabilities: { required: capability } })),
        UNSUPPORTED_CAPABILITY,
      );
      expectRpcError(
        () =>
          captureBundle(
            baseBundle({ calls: [{ to: TARGET_A, capabilities: { required: capability } }] }),
          ),
        UNSUPPORTED_CAPABILITY,
      );
    }
  });

  it("requires each capability to be a plain object with a boolean optional field", () => {
    for (const capability of [null, [], "optional", 1, true]) {
      expectRpcError(
        () => captureBundle(baseBundle({ capabilities: { feature: capability } })),
        INVALID_PARAMS,
      );
    }
    for (const optional of [null, "true", 1, {}, []]) {
      expectRpcError(
        () => captureBundle(baseBundle({ capabilities: { feature: { optional } } })),
        INVALID_PARAMS,
      );
    }
    expect(captureBundle(baseBundle({ capabilities: {} })).capabilities).toEqual({
      values: {},
      ignored: [],
    });
  });

  it("accepts only recursively JSON-compatible capability values", () => {
    for (const invalid of [undefined, 1n, Symbol("x"), () => undefined, Number.NaN, Infinity]) {
      expectRpcError(
        () => captureBundle(baseBundle({ capabilities: { feature: { optional: true, invalid } } })),
        INVALID_PARAMS,
      );
    }
    for (const invalid of [new Date(), new Map(), new Set()]) {
      expectRpcError(
        () => captureBundle(baseBundle({ capabilities: { feature: { optional: true, invalid } } })),
        INVALID_PARAMS,
      );
    }
  });

  it("captures deeply nested JSON without exposing the JavaScript call stack", () => {
    const depth = 10_000;
    let nested: unknown = "leaf";
    for (let index = 0; index < depth; index += 1) nested = [nested];
    const captured = captureBundle(
      baseBundle({ capabilities: { feature: { optional: true, nested } } }),
    );
    let current: unknown = captured.capabilities?.values.feature?.nested;
    for (let index = 0; index < depth; index += 1) {
      expect(Array.isArray(current)).toBe(true);
      if (!Array.isArray(current)) throw new Error("expected nested captured array");
      expect(Object.isFrozen(current)).toBe(true);
      current = current[0];
    }
    expect(current).toBe("leaf");
  });
});

describe("hostile object rejection", () => {
  it("does not invoke accessors and never exposes their messages", () => {
    let invoked = false;
    const bundle = baseBundle();
    Object.defineProperty(bundle, "id", {
      enumerable: true,
      get() {
        invoked = true;
        throw new Error("secret getter failure");
      },
    });
    expectRpcError(() => captureBundle(bundle), INVALID_PARAMS);
    expect(invoked).toBe(false);

    const nested: Record<string, unknown> = {};
    Object.defineProperty(nested, "secret", {
      enumerable: true,
      get() {
        invoked = true;
        return "secret";
      },
    });
    expectRpcError(
      () =>
        captureBundle(
          baseBundle({
            capabilities: { feature: { optional: true, nested } },
          }),
        ),
      INVALID_PARAMS,
    );
    expect(invoked).toBe(false);
  });

  it("rejects prototypes, symbols, non-enumerable fields, and revoked proxies", () => {
    const inheritedBundle = Object.assign(Object.create({ inherited: true }), baseBundle());
    expectRpcError(() => captureBundle(inheritedBundle), INVALID_PARAMS);

    const inheritedCapability = Object.assign(Object.create({ inherited: true }), {
      optional: true,
    });
    expectRpcError(
      () => captureBundle(baseBundle({ capabilities: { feature: inheritedCapability } })),
      INVALID_PARAMS,
    );

    const symbolBundle = baseBundle();
    Object.defineProperty(symbolBundle, Symbol("secret"), { value: true, enumerable: true });
    expectRpcError(() => captureBundle(symbolBundle), INVALID_PARAMS);

    const nonEnumerableCall = { to: TARGET_A };
    Object.defineProperty(nonEnumerableCall, "hidden", { value: true, enumerable: false });
    expectRpcError(() => captureBundle(baseBundle({ calls: [nonEnumerableCall] })), INVALID_PARAMS);

    const revoked = Proxy.revocable(baseBundle(), {});
    revoked.revoke();
    expectRpcError(() => captureBundle(revoked.proxy), INVALID_PARAMS);
  });

  it("rejects sparse arrays, array extensions, and aliases throughout the graph", () => {
    const sparseCalls: unknown[] = new Array(1);
    expectRpcError(() => captureBundle(baseBundle({ calls: sparseCalls })), INVALID_PARAMS);

    const extendedCalls = [{ to: TARGET_A }];
    Object.defineProperty(extendedCalls, "extra", { value: true, enumerable: true });
    expectRpcError(() => captureBundle(baseBundle({ calls: extendedCalls })), INVALID_PARAMS);

    const sparseJson: unknown[] = new Array(2);
    sparseJson[1] = "present";
    expectRpcError(
      () =>
        captureBundle(
          baseBundle({
            capabilities: { feature: { optional: true, sparseJson } },
          }),
        ),
      INVALID_PARAMS,
    );

    const sharedCall = { to: TARGET_A };
    expectRpcError(
      () => captureBundle(baseBundle({ calls: [sharedCall, sharedCall] })),
      INVALID_PARAMS,
    );

    const sharedJson = { exact: true };
    expectRpcError(
      () =>
        captureBundle(
          baseBundle({
            capabilities: {
              feature: { optional: true, left: sharedJson, right: sharedJson },
            },
          }),
        ),
      INVALID_PARAMS,
    );
  });
});

describe("semantic EIP-5792 refusals", () => {
  it("classifies a valid configured-chain mismatch as 5710", () => {
    expectRpcError(() => captureBundle(baseBundle({ chainId: "0xA" }), 11), UNSUPPORTED_CHAIN);
  });

  it("uses the generic execution refusal for syntactically valid contract creation", () => {
    expectRpcError(
      () => captureBundle(baseBundle({ calls: [{ data: "0x6000", value: "0x0" }] })),
      CONTRACT_CREATION_UNSUPPORTED,
    );
    expectRpcError(
      () => captureBundle(baseBundle({ calls: [{ to: undefined, data: "0x6000" }] })),
      INVALID_PARAMS,
    );
    expectRpcError(
      () => captureBundle(baseBundle({ calls: [{ data: "0x6000", gas: "0x1" }] })),
      INVALID_PARAMS,
    );
  });
});
