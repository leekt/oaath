import { encodeFunctionData, getAddress } from "viem";
import { entryPoint07Abi, toPackedUserOperation } from "viem/account-abstraction";
import { describe, expect, it } from "vitest";
import {
  captureRoutingCapabilities,
  classifyBundlerAcceptance,
  classifyBundlerProbe,
  decideExecution,
  deriveHandleOpsRequirement,
  deriveOperationPrefund,
  encodeHandleOps,
  OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES,
  OAATH_HANDLE_OPS_OVERHEAD_GAS,
  type OaathBundlerCapability,
  type OaathBundlerProbeRequest,
  type OaathFeePayerDescriptor,
  type OaathRouteFact,
  type OaathSessionCoverage,
  probeBundlerCapability,
} from "../src/advanced.js";
import {
  asViemUserOperation,
  KERNEL_V4_ENTRY_POINT_V07,
  prepareUserOperation,
} from "../src/kernel.js";
import { supportsBundlerSponsorship } from "../src/routing/decide.js";

const chainId = 421_614;
const account = "0x00000000000000000000000000000000000000a1" as const;
const feePayerAddress = "0x00000000000000000000000000000000000000b2" as const;
const beneficiary = "0x00000000000000000000000000000000000000c3" as const;
const signature = `0x${"11".repeat(65)}` as const;

const gas = Object.freeze({
  callGasLimit: "900000",
  verificationGasLimit: "3000000",
  preVerificationGas: "150000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
});

function prepared(overrides: Record<string, unknown> = {}) {
  return prepareUserOperation({
    kind: "execution",
    grantId: "routing-test",
    chainId,
    entryPoint: { version: "0.7", address: KERNEL_V4_ENTRY_POINT_V07 },
    userOperation: {
      sender: account,
      nonce: "7",
      callData: "0xdeadbeef",
      ...gas,
      factory: null,
      paymaster: null,
      ...overrides,
    },
  });
}

const kinds = ["execution", "revocation"] as const;
const coverages: readonly OaathSessionCoverage[] = ["covered", "uncovered", "unreadable"];
const bundlers: readonly OaathBundlerCapability[] = [
  "available",
  "absent",
  "unsupported",
  "unreadable",
];
const feePayer: Readonly<OaathFeePayerDescriptor> = Object.freeze({
  address: feePayerAddress,
  balance: "1000000000000000000",
});

/**
 * The bundler + handleOps-fallback configuration expressed as ordered routes:
 * the bundler first, then the handleOps route exactly when a fee payer exists.
 */
function fallbackRoutes(
  bundler: OaathBundlerCapability,
  payer: Readonly<OaathFeePayerDescriptor> | null,
): readonly OaathRouteFact[] {
  return [
    { kind: "erc4337-bundler", bundler },
    ...(payer === null ? [] : [{ kind: "erc4337-handleops" as const, feePayer: payer }]),
  ];
}

/**
 * The full pre-sign decision table. Every row is `kind/coverage/bundler/feePayer
 * -> signer/route`, and the array is the exhaustive product of the closed fact
 * space, written out instead of recomputed so a decision change fails here.
 */
const DECISION_TABLE: readonly string[] = [
  "execution/covered/available/payer -> session/erc4337-bundler",
  "execution/covered/available/none -> session/erc4337-bundler",
  "execution/covered/absent/payer -> session/erc4337-handleops",
  "execution/covered/absent/none -> session/none",
  "execution/covered/unsupported/payer -> session/erc4337-handleops",
  "execution/covered/unsupported/none -> session/none",
  "execution/covered/unreadable/payer -> session/erc4337-bundler",
  "execution/covered/unreadable/none -> session/erc4337-bundler",
  // Owner authority is wider than the approved session scope, so uncovered or
  // inconclusively covered execution selects no authority and no route at all.
  "execution/uncovered/available/payer -> none/none",
  "execution/uncovered/available/none -> none/none",
  "execution/uncovered/absent/payer -> none/none",
  "execution/uncovered/absent/none -> none/none",
  "execution/uncovered/unsupported/payer -> none/none",
  "execution/uncovered/unsupported/none -> none/none",
  "execution/uncovered/unreadable/payer -> none/none",
  "execution/uncovered/unreadable/none -> none/none",
  "execution/unreadable/available/payer -> none/none",
  "execution/unreadable/available/none -> none/none",
  "execution/unreadable/absent/payer -> none/none",
  "execution/unreadable/absent/none -> none/none",
  "execution/unreadable/unsupported/payer -> none/none",
  "execution/unreadable/unsupported/none -> none/none",
  "execution/unreadable/unreadable/payer -> none/none",
  "execution/unreadable/unreadable/none -> none/none",
  "revocation/covered/available/payer -> owner/erc4337-bundler",
  "revocation/covered/available/none -> owner/erc4337-bundler",
  "revocation/covered/absent/payer -> owner/erc4337-handleops",
  "revocation/covered/absent/none -> owner/none",
  "revocation/covered/unsupported/payer -> owner/erc4337-handleops",
  "revocation/covered/unsupported/none -> owner/none",
  "revocation/covered/unreadable/payer -> owner/erc4337-bundler",
  "revocation/covered/unreadable/none -> owner/erc4337-bundler",
  "revocation/uncovered/available/payer -> owner/erc4337-bundler",
  "revocation/uncovered/available/none -> owner/erc4337-bundler",
  "revocation/uncovered/absent/payer -> owner/erc4337-handleops",
  "revocation/uncovered/absent/none -> owner/none",
  "revocation/uncovered/unsupported/payer -> owner/erc4337-handleops",
  "revocation/uncovered/unsupported/none -> owner/none",
  "revocation/uncovered/unreadable/payer -> owner/erc4337-bundler",
  "revocation/uncovered/unreadable/none -> owner/erc4337-bundler",
  "revocation/unreadable/available/payer -> owner/erc4337-bundler",
  "revocation/unreadable/available/none -> owner/erc4337-bundler",
  "revocation/unreadable/absent/payer -> owner/erc4337-handleops",
  "revocation/unreadable/absent/none -> owner/none",
  "revocation/unreadable/unsupported/payer -> owner/erc4337-handleops",
  "revocation/unreadable/unsupported/none -> owner/none",
  "revocation/unreadable/unreadable/payer -> owner/erc4337-bundler",
  "revocation/unreadable/unreadable/none -> owner/erc4337-bundler",
];

function everyFactCombination() {
  return kinds.flatMap((operationKind) =>
    coverages.flatMap((sessionCoverage) =>
      bundlers.flatMap((bundler) =>
        [feePayer, null].map((payer) => ({
          facts: { bundler, feePayer: payer },
          input: { operationKind, sessionCoverage, routes: fallbackRoutes(bundler, payer) },
        })),
      ),
    ),
  );
}

describe("routing decision", () => {
  it("selects root authority only when explicitly requested for execution", () => {
    const facts = {
      operationKind: "execution" as const,
      sessionCoverage: "uncovered" as const,
      routes: fallbackRoutes("available", null),
    };
    expect(decideExecution(facts).signer).toBe("none");
    expect(decideExecution({ ...facts, signer: "session" }).signer).toBe("none");
    expect(decideExecution({ ...facts, signer: "owner" })).toMatchObject({
      signer: "owner",
      route: "erc4337-bundler",
      reasons: ["owner_explicit", "route_available:erc4337-bundler"],
    });
    expect(() => decideExecution({ ...facts, signer: "auto" } as never)).toThrowError(
      expect.objectContaining({ code: "routing_input_invalid" }),
    );
  });
  it("selects sponsorship exactly for bundler routes", () => {
    expect(
      bundlers.map((bundler) => [
        bundler,
        supportsBundlerSponsorship(fallbackRoutes(bundler, feePayer)),
      ]),
    ).toEqual([
      ["available", true],
      ["absent", false],
      ["unsupported", false],
      ["unreadable", true],
    ]);
  });

  it("decides every fact combination exactly as the reviewed table", () => {
    const rows = everyFactCombination().map(({ facts, input }) => {
      const decision = decideExecution(input);
      const payer = facts.feePayer === null ? "none" : "payer";
      return `${input.operationKind}/${input.sessionCoverage}/${facts.bundler}/${payer} -> ${decision.signer}/${decision.route}`;
    });
    expect(rows).toEqual(DECISION_TABLE);
    expect(rows).toHaveLength(48);
  });

  it("carries closed reason codes for every combination", () => {
    for (const { facts, input } of everyFactCombination()) {
      const decision = decideExecution(input);
      const [signerReason, bundlerReason, handleOpsReason] = decision.reasons;
      expect(signerReason).toBe(
        input.operationKind === "revocation"
          ? "root_operation_requires_owner"
          : input.sessionCoverage === "covered"
            ? "session_covers_calls"
            : input.sessionCoverage === "uncovered"
              ? "session_calls_uncovered"
              : "session_coverage_unreadable",
      );
      if (input.operationKind === "execution" && input.sessionCoverage !== "covered") {
        // A denied decision carries only the denial: no route reason, no fee
        // payer reason, no submission surface to explain.
        expect(decision.reasons).toHaveLength(1);
        continue;
      }
      expect(bundlerReason).toBe(`route_${facts.bundler}:erc4337-bundler`);
      if (
        facts.bundler === "available" ||
        facts.bundler === "unreadable" ||
        facts.feePayer === null
      ) {
        // An inconclusive or healthy bundler never consults a later route.
        expect(decision.reasons).toHaveLength(2);
        expect(handleOpsReason).toBeUndefined();
      } else {
        expect(handleOpsReason).toBe("route_available:erc4337-handleops");
      }
    }
  });

  it("exposes no operation-mutation surface and stays frozen", () => {
    const decision = decideExecution({
      operationKind: "execution",
      sessionCoverage: "covered",
      routes: fallbackRoutes("absent", feePayer),
    });
    expect(Object.keys(decision).sort()).toEqual(["feePayer", "reasons", "route", "signer"]);
    expect(Object.isFrozen(decision)).toBe(true);
    expect(Object.isFrozen(decision.reasons)).toBe(true);
    expect(Object.values(decision).some((value) => typeof value === "function")).toBe(false);
    expect(decision.feePayer).toEqual({ address: feePayerAddress, balance: feePayer.balance });
    expect(Object.isFrozen(decision.feePayer)).toBe(true);
  });

  it("never authorizes the fallback from an unreadable bundler", () => {
    for (const sessionCoverage of coverages) {
      for (const operationKind of kinds) {
        const decision = decideExecution({
          operationKind,
          sessionCoverage,
          routes: fallbackRoutes("unreadable", feePayer),
        });
        // A denied signer denies the route; otherwise an unreadable bundler
        // stays on the bundler route. Neither authorizes the fallback.
        expect(decision.route).toBe(
          operationKind === "execution" && sessionCoverage !== "covered"
            ? "none"
            : "erc4337-bundler",
        );
        expect(decision.feePayer).toBeNull();
        expect(decision.reasons).not.toContain("route_available:erc4337-handleops");
      }
    }
  });

  it("returns a fee payer exactly when the route is the handleOps fallback", () => {
    for (const { input } of everyFactCombination()) {
      const decision = decideExecution(input);
      expect(decision.feePayer !== null).toBe(decision.route === "erc4337-handleops");
    }
  });

  it("returns none with a structured reason when a chain offers no route", () => {
    for (const operationKind of kinds) {
      expect(
        decideExecution({ operationKind, sessionCoverage: "covered", routes: [] }),
      ).toMatchObject({
        signer: operationKind === "revocation" ? "owner" : "session",
        route: "none",
        feePayer: null,
        reasons: [
          operationKind === "revocation" ? "root_operation_requires_owner" : "session_covers_calls",
          "route_none_configured",
        ],
      });
    }
    expect(supportsBundlerSponsorship([])).toBe(false);
  });

  it("honors the configured route order and never probes past an unreadable bundler", () => {
    const handleOps = { kind: "erc4337-handleops" as const, feePayer };
    const covered = { operationKind: "execution" as const, sessionCoverage: "covered" as const };
    // A pinned handleOps route selects it without any bundler fact.
    expect(decideExecution({ ...covered, routes: [handleOps] })).toMatchObject({
      route: "erc4337-handleops",
      reasons: ["session_covers_calls", "route_available:erc4337-handleops"],
    });
    expect(
      decideExecution({
        ...covered,
        routes: [handleOps, { kind: "erc4337-bundler", bundler: "available" }],
      }).route,
    ).toBe("erc4337-handleops");
    expect(
      decideExecution({ ...covered, routes: [{ kind: "erc4337-bundler", bundler: "absent" }] }),
    ).toMatchObject({
      route: "none",
      reasons: ["session_covers_calls", "route_absent:erc4337-bundler"],
    });
  });

  it("fails closed on hostile decision input", () => {
    const base = { operationKind: "execution", sessionCoverage: "covered" };
    const bundlerRoute = { kind: "erc4337-bundler", bundler: "available" };
    const cases: unknown[] = [
      null,
      "execution",
      [],
      base,
      { ...base, routes: [bundlerRoute], extra: 1 },
      { ...base, bundler: "available", feePayer: null },
      { ...base, operationKind: "install", routes: [bundlerRoute] },
      { ...base, sessionCoverage: "denied", routes: [bundlerRoute] },
      { ...base, routes: [{ kind: "erc4337-bundler", bundler: "healthy" }] },
      { ...base, routes: [{ kind: "eip8141" }] },
      { ...base, routes: [bundlerRoute, { ...bundlerRoute }] },
      { ...base, routes: [{ ...bundlerRoute, feePayer }] },
      { ...base, routes: [{ kind: "erc4337-handleops", feePayer: null }] },
      {
        ...base,
        routes: [
          { kind: "erc4337-handleops", feePayer: { address: feePayerAddress, balance: "-1" } },
        ],
      },
      {
        ...base,
        routes: [
          {
            kind: "erc4337-handleops",
            feePayer: { address: `0x${"00".repeat(20)}`, balance: "1" },
          },
        ],
      },
      {
        ...base,
        routes: [
          {
            kind: "erc4337-handleops",
            feePayer: { address: feePayerAddress, balance: "1", extra: true },
          },
        ],
      },
      Object.defineProperty({ sessionCoverage: "covered", routes: [] }, "operationKind", {
        get: () => "execution",
        enumerable: true,
      }),
      Object.assign(Object.create({ operationKind: "execution" }), {
        sessionCoverage: "covered",
        routes: [],
      }),
    ];
    for (const value of cases) {
      expect(() => decideExecution(value as never)).toThrowError(
        expect.objectContaining({ code: "routing_input_invalid" }),
      );
    }
  });
});

describe("routing capabilities", () => {
  it("captures one chain's facts exactly and canonicalizes the fee payer", () => {
    const checksummed = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" as const;
    const captured = captureRoutingCapabilities({
      chainId,
      routes: fallbackRoutes("available", { address: checksummed, balance: "0" }),
      sessionCoverage: "covered",
    });
    expect(captured).toEqual({
      chainId,
      routes: fallbackRoutes("available", {
        address: checksummed.toLowerCase() as `0x${string}`,
        balance: "0",
      }),
      sessionCoverage: "covered",
    });
    expect(Object.isFrozen(captured)).toBe(true);
    expect(Object.isFrozen(captured.routes)).toBe(true);
  });

  it("accepts a chain with no route", () => {
    expect(
      captureRoutingCapabilities({ chainId, routes: [], sessionCoverage: "unreadable" }).routes,
    ).toEqual([]);
  });

  it("fails closed on hostile capability descriptors", () => {
    const routes = fallbackRoutes("available", null);
    const cases: unknown[] = [
      undefined,
      { chainId, sessionCoverage: "covered" },
      { chainId: 0, routes, sessionCoverage: "covered" },
      { chainId: 1.5, routes, sessionCoverage: "covered" },
      {
        chainId,
        routes: [{ kind: "erc4337-bundler", bundler: "present" }],
        sessionCoverage: "covered",
      },
      { chainId, routes, sessionCoverage: "yes" },
      { chainId, routes: undefined, sessionCoverage: "covered" },
      { chainId, bundler: "available", sessionCoverage: "covered", feePayer: null },
      {
        chainId,
        routes: [{ kind: "erc4337-handleops", feePayer: { address: "0xnothex", balance: "1" } }],
        sessionCoverage: "covered",
      },
      {
        chainId,
        routes: [
          { kind: "erc4337-handleops", feePayer: { address: feePayerAddress, balance: "01" } },
        ],
        sessionCoverage: "covered",
      },
      new Proxy(
        { chainId, routes, sessionCoverage: "covered" },
        {
          getOwnPropertyDescriptor() {
            throw new Error("hostile descriptor");
          },
        },
      ),
    ];
    for (const value of cases) {
      expect(() => captureRoutingCapabilities(value as never)).toThrowError(
        expect.objectContaining({ code: "routing_capability_invalid" }),
      );
    }
  });
});

describe("bundler classification", () => {
  const request: Readonly<OaathBundlerProbeRequest> = Object.freeze({
    chainId,
    entryPoint: KERNEL_V4_ENTRY_POINT_V07,
  });

  it("classifies a healthy compatible bundler as available", () => {
    expect(
      classifyBundlerProbe(
        {
          accepting: true,
          chainId,
          supportedEntryPoints: [getAddress(KERNEL_V4_ENTRY_POINT_V07)],
        },
        request,
      ),
    ).toBe("available");
  });

  it("classifies conclusive self-reported unavailability as absent", () => {
    expect(
      classifyBundlerProbe(
        { accepting: false, chainId, supportedEntryPoints: [KERNEL_V4_ENTRY_POINT_V07] },
        request,
      ),
    ).toBe("absent");
  });

  it("classifies a foreign chain or unsupported EntryPoint as unsupported", () => {
    expect(
      classifyBundlerProbe(
        { accepting: true, chainId: 1, supportedEntryPoints: [KERNEL_V4_ENTRY_POINT_V07] },
        request,
      ),
    ).toBe("unsupported");
    expect(
      classifyBundlerProbe({ accepting: true, chainId, supportedEntryPoints: [] }, request),
    ).toBe("unsupported");
    expect(
      classifyBundlerProbe({ accepting: true, chainId, supportedEntryPoints: [account] }, request),
    ).toBe("unsupported");
  });

  it("classifies malformed or hostile probe evidence as unreadable", () => {
    const evidence: unknown[] = [
      undefined,
      null,
      "ok",
      [],
      { accepting: true, chainId },
      { accepting: true, chainId, supportedEntryPoints: [KERNEL_V4_ENTRY_POINT_V07], extra: 1 },
      { accepting: "true", chainId, supportedEntryPoints: [KERNEL_V4_ENTRY_POINT_V07] },
      { accepting: true, chainId: "421614", supportedEntryPoints: [KERNEL_V4_ENTRY_POINT_V07] },
      { accepting: true, chainId, supportedEntryPoints: KERNEL_V4_ENTRY_POINT_V07 },
      { accepting: true, chainId, supportedEntryPoints: [null] },
      {
        accepting: true,
        chainId,
        supportedEntryPoints: Array.from({ length: 33 }, () => KERNEL_V4_ENTRY_POINT_V07),
      },
      // A malformed field never downgrades to the conclusive `absent` fact.
      { accepting: false, chainId, supportedEntryPoints: [null] },
    ];
    for (const value of evidence) {
      expect(classifyBundlerProbe(value, request)).toBe("unreadable");
    }
  });

  it("rejects a probe request that is not bound to a chain and EntryPoint", () => {
    expect(() =>
      classifyBundlerProbe(
        { accepting: true, chainId, supportedEntryPoints: [] },
        {
          chainId: 0,
          entryPoint: KERNEL_V4_ENTRY_POINT_V07,
        },
      ),
    ).toThrowError(expect.objectContaining({ code: "routing_input_invalid" }));
  });

  it("treats only closed ERC-4337 rejection codes as conclusive", () => {
    expect(classifyBundlerAcceptance({ outcome: "accepted", code: null })).toBe("available");
    for (const code of OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES) {
      expect(classifyBundlerAcceptance({ outcome: "rejected", code })).toBe("unsupported");
    }
    const inconclusive: unknown[] = [
      { outcome: "rejected", code: null },
      { outcome: "rejected", code: -32603 },
      { outcome: "rejected", code: -32000 },
      { outcome: "rejected", code: -32602 },
      { outcome: "rejected", code: 1.5 },
      { outcome: "rejected", code: "-32500" },
      { outcome: "accepted", code: -32500 },
      { outcome: "timeout", code: null },
      { outcome: "rejected" },
      undefined,
      "rejected",
    ];
    for (const value of inconclusive) {
      expect(classifyBundlerAcceptance(value)).toBe("unreadable");
    }
  });

  it("classifies a throwing, hanging, or hostile probe capability as unreadable", async () => {
    const request2 = { chainId, entryPoint: KERNEL_V4_ENTRY_POINT_V07 };
    await expect(
      probeBundlerCapability({
        capability: {
          probe: () => {
            throw new Error("transport disconnected");
          },
        },
        request: request2,
        timeoutMs: 50,
      }),
    ).resolves.toBe("unreadable");
    await expect(
      probeBundlerCapability({
        capability: { probe: async () => Promise.reject(new Error("socket closed")) },
        request: request2,
        timeoutMs: 50,
      }),
    ).resolves.toBe("unreadable");
    await expect(
      probeBundlerCapability({
        capability: { probe: () => new Promise(() => {}) },
        request: request2,
        timeoutMs: 20,
      }),
    ).resolves.toBe("unreadable");
  });

  it("classifies a probe that answers in time", async () => {
    await expect(
      probeBundlerCapability({
        capability: {
          probe: async (probeRequest) => ({
            accepting: true,
            chainId: probeRequest.chainId,
            supportedEntryPoints: [probeRequest.entryPoint],
          }),
        },
        request: { chainId, entryPoint: KERNEL_V4_ENTRY_POINT_V07 },
        timeoutMs: 1_000,
      }),
    ).resolves.toBe("available");
  });

  it("fails closed on an invalid probe capability or timeout", async () => {
    await expect(
      probeBundlerCapability({
        capability: { probe: "send" as never },
        request: { chainId, entryPoint: KERNEL_V4_ENTRY_POINT_V07 },
        timeoutMs: 50,
      }),
    ).rejects.toMatchObject({ code: "routing_capability_invalid" });
    await expect(
      probeBundlerCapability({
        capability: { probe: async () => ({}), extra: 1 } as never,
        request: { chainId, entryPoint: KERNEL_V4_ENTRY_POINT_V07 },
        timeoutMs: 50,
      }),
    ).rejects.toMatchObject({ code: "routing_capability_invalid" });
    await expect(
      probeBundlerCapability({
        capability: { probe: async () => ({}) },
        request: { chainId, entryPoint: KERNEL_V4_ENTRY_POINT_V07 },
        timeoutMs: 0,
      }),
    ).rejects.toMatchObject({ code: "routing_input_invalid" });
    await expect(
      probeBundlerCapability({
        capability: { probe: async () => ({}) },
        request: { chainId, entryPoint: KERNEL_V4_ENTRY_POINT_V07 },
        timeoutMs: 60_001,
      }),
    ).rejects.toMatchObject({ code: "routing_input_invalid" });
    await expect(
      probeBundlerCapability({
        capability: { probe: async () => ({}) },
        request: { chainId, entryPoint: `0x${"00".repeat(20)}` },
        timeoutMs: 50,
      }),
    ).rejects.toMatchObject({ code: "routing_input_invalid" });
  });
});

describe("EntryPoint 0.7 prefund", () => {
  it("derives (verification + call + preVerification) * maxFeePerGas bound to the identity", () => {
    const operation = prepared();
    const prefund = deriveOperationPrefund(operation);
    const totalGas = 3_000_000n + 900_000n + 150_000n;
    expect(prefund).toEqual({
      chainId,
      entryPoint: KERNEL_V4_ENTRY_POINT_V07,
      account,
      userOperationHash: operation.userOperationHash,
      totalGas: totalGas.toString(10),
      maxFeePerGas: gas.maxFeePerGas,
      requiredPrefund: (totalGas * 2_000_000_000n).toString(10),
    });
    expect(Object.isFrozen(prefund)).toBe(true);
  });

  it("prices the documented uint120 ceiling without overflowing", () => {
    const ceiling = ((1n << 120n) - 1n).toString(10);
    const prefund = deriveOperationPrefund(
      prepared({
        callGasLimit: ceiling,
        verificationGasLimit: ceiling,
        preVerificationGas: ceiling,
        maxFeePerGas: ceiling,
        maxPriorityFeePerGas: "0",
      }),
    );
    expect(BigInt(prefund.requiredPrefund)).toBe(3n * ((1n << 120n) - 1n) ** 2n);
    expect(BigInt(prefund.requiredPrefund) < 1n << 256n).toBe(true);
  });

  it("refuses paymaster-sponsored operations and non-exact operations", () => {
    expect(() =>
      deriveOperationPrefund(
        prepared({
          paymaster: {
            address: feePayerAddress,
            verificationGasLimit: "1000",
            postOpGasLimit: "1000",
            data: "0x",
          },
        }),
      ),
    ).toThrowError(expect.objectContaining({ code: "routing_paymaster_unsupported" }));
    for (const value of [null, {}, { ...prepared(), userOperationHash: `0x${"00".repeat(32)}` }]) {
      expect(() => deriveOperationPrefund(value)).toThrowError(
        expect.objectContaining({ code: "routing_operation_invalid" }),
      );
    }
  });
});

describe("handleOps fee payer requirement", () => {
  it("requires the operation gas plus the reviewed overhead", () => {
    const operation = prepared();
    const requirement = deriveHandleOpsRequirement({
      prepared: operation,
      feePayer,
      overheadGas: OAATH_HANDLE_OPS_OVERHEAD_GAS,
    });
    const totalGas = 3_000_000n + 900_000n + 150_000n;
    expect(requirement).toEqual({
      status: "funded",
      chainId,
      entryPoint: KERNEL_V4_ENTRY_POINT_V07,
      account,
      userOperationHash: operation.userOperationHash,
      feePayer: feePayerAddress,
      requiredPrefund: (totalGas * 2_000_000_000n).toString(10),
      overheadGas: OAATH_HANDLE_OPS_OVERHEAD_GAS,
      requiredFeePayerBalance: ((totalGas + 60_000n) * 2_000_000_000n).toString(10),
    });
  });

  it("reports an underfunded fee payer without changing the route", () => {
    const requirement = deriveHandleOpsRequirement({
      prepared: prepared(),
      feePayer: { address: feePayerAddress, balance: "1" },
      overheadGas: OAATH_HANDLE_OPS_OVERHEAD_GAS,
    });
    expect(requirement.status).toBe("underfunded");
    expect(BigInt(requirement.requiredFeePayerBalance) > 1n).toBe(true);
    expect(Object.keys(requirement)).not.toContain("route");
  });

  it("treats an exactly sufficient balance as funded", () => {
    const totalGas = 3_000_000n + 900_000n + 150_000n;
    expect(
      deriveHandleOpsRequirement({
        prepared: prepared(),
        feePayer: {
          address: feePayerAddress,
          balance: ((totalGas + 60_000n) * 2_000_000_000n).toString(10),
        },
        overheadGas: OAATH_HANDLE_OPS_OVERHEAD_GAS,
      }).status,
    ).toBe("funded");
  });

  it("fails closed on hostile requirement input", () => {
    const cases: unknown[] = [
      null,
      { prepared: prepared(), feePayer },
      { prepared: prepared(), feePayer, overheadGas: "60000", extra: 1 },
      { prepared: prepared(), feePayer, overheadGas: -1 },
      { prepared: prepared(), feePayer, overheadGas: "0x1" },
      { prepared: prepared(), feePayer: { address: feePayerAddress }, overheadGas: "60000" },
      {
        prepared: prepared(),
        feePayer: { address: feePayerAddress, balance: "1", extra: 1 },
        overheadGas: "60000",
      },
    ];
    for (const value of cases) {
      expect(() => deriveHandleOpsRequirement(value as never)).toThrowError(
        expect.objectContaining({ code: "routing_input_invalid" }),
      );
    }
  });
});

describe("handleOps encoding", () => {
  it("encodes handleOps([op], beneficiary) and preserves the operation identity", () => {
    const operation = prepared();
    const call = encodeHandleOps({ prepared: operation, signature, beneficiary });
    expect(call.userOperationHash).toBe(operation.userOperationHash);
    expect(call).toEqual({
      chainId,
      entryPoint: KERNEL_V4_ENTRY_POINT_V07,
      account,
      userOperationHash: operation.userOperationHash,
      beneficiary,
      data: encodeFunctionData({
        abi: entryPoint07Abi,
        functionName: "handleOps",
        args: [
          [toPackedUserOperation({ ...asViemUserOperation(operation.userOperation), signature })],
          beneficiary,
        ],
      }),
    });
    expect(Object.isFrozen(call)).toBe(true);
    // Encoding is a pure function of the prepared operation and the signature.
    expect(encodeHandleOps({ prepared: operation, signature, beneficiary }).data).toBe(call.data);
  });

  it("encodes the same identity for both routes even with a deploying factory", () => {
    const operation = prepared({
      factory: { address: feePayerAddress, data: "0xabcd" },
    });
    const call = encodeHandleOps({ prepared: operation, signature, beneficiary });
    expect(call.userOperationHash).toBe(operation.userOperationHash);
    expect(call.data.startsWith("0x765e827f")).toBe(true);
  });

  it("fails closed on an invalid signature, beneficiary, operation, or paymaster", () => {
    const operation = prepared();
    for (const value of [
      { prepared: operation, signature: "0x", beneficiary },
      { prepared: operation, signature: "0x1", beneficiary },
      { prepared: operation, signature: 1, beneficiary },
      { prepared: operation, signature, beneficiary: `0x${"00".repeat(20)}` },
      { prepared: operation, signature },
      { prepared: operation, signature, beneficiary, extra: 1 },
    ]) {
      expect(() => encodeHandleOps(value as never)).toThrowError(
        expect.objectContaining({ code: "routing_input_invalid" }),
      );
    }
    expect(() =>
      encodeHandleOps({
        prepared: { ...operation, chainId: chainId + 1 },
        signature,
        beneficiary,
      }),
    ).toThrowError(expect.objectContaining({ code: "routing_operation_invalid" }));
    expect(() =>
      encodeHandleOps({
        prepared: prepared({
          paymaster: {
            address: feePayerAddress,
            verificationGasLimit: "1000",
            postOpGasLimit: "1000",
            data: "0x",
          },
        }),
        signature,
        beneficiary,
      }),
    ).toThrowError(expect.objectContaining({ code: "routing_paymaster_unsupported" }));
  });
});
