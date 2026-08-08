/**
 * ERC-7902 validity ranges through the genuine wallet/Grant execution path.
 *
 * @author taek <leekt216@gmail.com>
 */
import { describe, expect, it } from "vitest";
import type {
  Erc7677GasEstimationRequest,
  Erc7677PaymasterServiceRequest,
  OaathChainCapability,
  OaathRegisteredPaymasterService,
} from "../src/advanced.js";
import { hashErc7902StaticPaymasterConfiguration } from "../src/advanced.js";
import {
  grantProviderPort,
  type OaathProviderOperationPointer,
} from "../src/client/grant-handle.js";
import { encodeKernelV4Execution, OAATH_KERNEL_V4_VALIDITY_POLICY } from "../src/kernel.js";
import {
  OAATH_PROVIDER_ERROR_MESSAGES,
  type OaathProviderErrorCode,
} from "../src/provider/errors.js";
import { type OaathProviderInput, oaathProvider } from "../src/viem.js";
import {
  CALL_DATA,
  CHAIN_ID,
  type ChainFixture,
  createChainFixture,
  createClock,
  createRealm,
  permissionInput,
  TARGET,
} from "./support/browser.js";

const CHAIN_HEX = `0x${CHAIN_ID.toString(16)}`;
const REQUEST_HASH = `0x${"ab".repeat(32)}` as const;
const SERVICE_URL = `https://issuer.example/chains/${CHAIN_ID}/paymaster`;
const PAYMASTER = `0x${"33".repeat(20)}` as const;

function quantity(value: number | bigint): `0x${string}` {
  return `0x${BigInt(value).toString(16)}`;
}

function validity(
  validAfter: number | bigint,
  validUntil: number | bigint,
  optional = false,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    validAfter: quantity(validAfter),
    validUntil: quantity(validUntil),
    ...(optional ? { optional: true } : {}),
  });
}

function bundle(
  account: `0x${string}`,
  id: string,
  validityTimeRange: Readonly<Record<string, unknown>>,
  otherCapabilities: Readonly<Record<string, unknown>> = {},
): Record<string, unknown> {
  return {
    version: "2.0.0",
    id,
    from: account,
    chainId: CHAIN_HEX,
    atomicRequired: true,
    calls: [{ to: TARGET, data: CALL_DATA }],
    capabilities: { validityTimeRange, ...otherCapabilities },
  };
}

function replaceChain(base: ChainFixture, overrides: Partial<OaathChainCapability>): ChainFixture {
  const capability = Object.freeze({ ...base.capability, ...overrides });
  return Object.freeze({
    capability,
    sends: base.sends,
    signatures: base.signatures,
    get quotes() {
      return base.quotes;
    },
  });
}

function observingPolicyReads(
  base: ChainFixture,
  observedHash?: `0x${string}`,
): Readonly<{ chain: ChainFixture; reads: () => number }> {
  let reads = 0;
  return Object.freeze({
    chain: replaceChain(base, {
      reads: Object.freeze({
        async read(request: Parameters<OaathChainCapability["reads"]["read"]>[0]) {
          if (
            request.type === "runtime_code_hash" &&
            request.address === OAATH_KERNEL_V4_VALIDITY_POLICY
          ) {
            reads += 1;
            if (observedHash !== undefined) return observedHash;
          }
          return base.capability.reads.read(request);
        },
      }),
    }),
    reads: () => reads,
  });
}

async function activeProvider(
  input: Readonly<{
    chain?: ChainFixture;
    clock?: ReturnType<typeof createClock>;
    confirmCalls?: NonNullable<OaathProviderInput["confirmCalls"]>;
  }> = {},
) {
  const realm = createRealm({
    ...(input.chain === undefined ? {} : { chain: input.chain }),
    ...(input.clock === undefined ? {} : { clock: input.clock }),
  });
  const connection = await realm.oaath.connect();
  const grant = await connection.requestPermission(permissionInput());
  const provider = oaathProvider({
    grant,
    chain: CHAIN_ID,
    ...(input.confirmCalls === undefined ? {} : { confirmCalls: input.confirmCalls }),
  });
  const account = await grant.account(CHAIN_ID);
  return { realm, connection, grant, provider, account };
}

async function providerError(
  promise: Promise<unknown>,
  code: OaathProviderErrorCode,
): Promise<void> {
  await expect(promise).rejects.toMatchObject({
    name: "OaathProviderRpcError",
    code,
    message: OAATH_PROVIDER_ERROR_MESSAGES[code],
  });
}

async function expectNoEffects(
  active: Awaited<ReturnType<typeof activeProvider>>,
  id: string,
): Promise<void> {
  const port = grantProviderPort(active.grant);
  await expect(
    port.walletCallBundles.get({
      providerScopeId: port.providerScopeId as `0x${string}`,
      account: active.account,
      id,
    }),
  ).resolves.toBeUndefined();
  expect(active.realm.chain.quotes).toBe(0);
  expect(active.realm.chain.signatures).toHaveLength(0);
  expect(active.realm.chain.sends).toHaveLength(0);
}

function providerCallsInput(admission: unknown): Readonly<Record<string, unknown>> {
  return Object.freeze({
    chain: CHAIN_ID,
    calls: Object.freeze([Object.freeze({ target: TARGET, value: "0", data: CALL_DATA })]),
    requestHash: REQUEST_HASH,
    paymaster: null,
    validityAdmission: admission,
  });
}

const publication = Object.freeze({
  async reserve(_operation: OaathProviderOperationPointer) {},
  async confirm(_operation: OaathProviderOperationPointer) {},
  async abandon(_operation: OaathProviderOperationPointer) {},
});

function staticConfiguration(): Readonly<Record<string, unknown>> {
  return Object.freeze({
    paymaster: PAYMASTER,
    paymasterData: "0x01020304",
    paymasterValidationGasLimit: "0x32",
    paymasterPostOpGasLimit: "0x3c",
  });
}

function registeredService(): Readonly<{
  service: Readonly<OaathRegisteredPaymasterService>;
  stages: readonly string[];
}> {
  const stages: string[] = [];
  const service = Object.freeze({
    url: SERVICE_URL,
    async request(request: Readonly<Erc7677PaymasterServiceRequest>) {
      stages.push(request.method === "pm_getPaymasterStubData" ? "stub" : "final");
      return request.method === "pm_getPaymasterStubData"
        ? {
            paymaster: PAYMASTER,
            paymasterData: "0x01020304",
            paymasterPostOpGasLimit: "0x3c",
          }
        : { paymaster: PAYMASTER, paymasterData: "0x01020305" };
    },
    async estimate(_request: Readonly<Erc7677GasEstimationRequest>) {
      stages.push("estimate");
      return {
        callGasLimit: "100",
        verificationGasLimit: "200",
        preVerificationGas: "30",
        paymasterVerificationGasLimit: "50",
      };
    },
  });
  return Object.freeze({ service, stages });
}

describe("wallet_sendCalls ERC-7902 validity admission", () => {
  it("requires a confirmer while an optional unsupported range stays in default mode", async () => {
    const active = await activeProvider();
    const after = active.realm.clock.now() + 10;
    const until = after + 90;
    const id = "validity-needs-confirmer";

    await providerError(
      active.provider.request({
        method: "wallet_sendCalls",
        params: [bundle(active.account, id, validity(after, until))],
      }),
      5700,
    );
    await expectNoEffects(active, id);

    await expect(
      active.provider.request({
        method: "wallet_sendCalls",
        params: [bundle(active.account, id, validity(after, until, true))],
      }),
    ).resolves.toEqual({ id });
    expect(active.realm.chain.sends).toHaveLength(1);
    expect(active.realm.chain.sends[0]?.userOperation.callData).not.toContain("1ba8f415");
    await active.connection.close();
  });

  it("refuses a required outside ceiling while optional falls back to generic confirmation", async () => {
    let presentations = 0;
    let presented: unknown;
    const active = await activeProvider({
      confirmCalls: async (confirmation) => {
        presentations += 1;
        presented = confirmation;
        return "approved" as const;
      },
    });
    const id = "validity-outside-ceiling";
    const after = active.realm.clock.now();

    await providerError(
      active.provider.request({
        method: "wallet_sendCalls",
        params: [bundle(active.account, id, validity(after, after + 1_800))],
      }),
      5700,
    );
    expect(presentations).toBe(0);
    await expectNoEffects(active, id);

    await expect(
      active.provider.request({
        method: "wallet_sendCalls",
        params: [bundle(active.account, id, validity(after, after + 1_800, true))],
      }),
    ).resolves.toEqual({ id });
    expect(presentations).toBe(1);
    expect(presented).toEqual({
      account: active.account,
      chainId: CHAIN_HEX,
      calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
    });
    expect(active.realm.chain.sends[0]?.userOperation.callData).not.toContain("1ba8f415");
    await active.connection.close();
  });

  it("refuses a wrong policy runtime hash before presentation or execution effects", async () => {
    const base = createChainFixture();
    const observed = observingPolicyReads(base, `0x${"ff".repeat(32)}`);
    let presentations = 0;
    const active = await activeProvider({
      chain: observed.chain,
      confirmCalls: async () => {
        presentations += 1;
        return "approved" as const;
      },
    });
    const id = "validity-wrong-code";
    const after = active.realm.clock.now() + 10;

    await providerError(
      active.provider.request({
        method: "wallet_sendCalls",
        params: [bundle(active.account, id, validity(after, after + 90))],
      }),
      5700,
    );
    expect(observed.reads()).toBe(1);
    expect(presentations).toBe(0);
    await expectNoEffects(active, id);
    await active.connection.close();
  });

  it("refuses an unrenderable in-ceiling endpoint before presentation or effects", async () => {
    const clock = createClock(8_640_000_000_000);
    let presentations = 0;
    const active = await activeProvider({
      clock,
      confirmCalls: async () => {
        presentations += 1;
        return "approved" as const;
      },
    });
    const id = "validity-unrenderable";

    await providerError(
      active.provider.request({
        method: "wallet_sendCalls",
        params: [bundle(active.account, id, validity(clock.now(), clock.now() + 100))],
      }),
      5700,
    );
    expect(presentations).toBe(0);
    await expectNoEffects(active, id);
    await active.connection.close();
  });

  it("presents exact inclusive seconds and UTC, and rejection returns 4001 with zero effects", async () => {
    let presented: unknown;
    const active = await activeProvider({
      confirmCalls: async (confirmation) => {
        presented = confirmation;
        return "rejected" as const;
      },
    });
    const after = active.realm.clock.now() + 10;
    const until = after + 90;
    const id = "validity-rejected";

    await providerError(
      active.provider.request({
        method: "wallet_sendCalls",
        params: [bundle(active.account, id, validity(after, until))],
      }),
      4001,
    );
    expect(presented).toEqual({
      account: active.account,
      chainId: CHAIN_HEX,
      calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
      validityTimeRange: {
        validAfter: String(after),
        validUntil: String(until),
        validAfterUtc: "2027-01-15T08:00:10.000Z",
        validUntilUtc: "2027-01-15T08:01:40.000Z",
        inclusive: true,
      },
    });
    expect(Object.isFrozen(presented)).toBe(true);
    expect(
      Object.isFrozen(
        (presented as { readonly validityTimeRange: Readonly<Record<string, unknown>> })
          .validityTimeRange,
      ),
    ).toBe(true);
    await expectNoEffects(active, id);
    await active.connection.close();
  });

  it("binds one admitted range into exact calldata and durable hash without a second policy read", async () => {
    const base = createChainFixture();
    const observed = observingPolicyReads(base);
    let readsAtPresentation = 0;
    const active = await activeProvider({
      chain: observed.chain,
      confirmCalls: async () => {
        readsAtPresentation = observed.reads();
        return "approved" as const;
      },
    });
    const after = active.realm.clock.now() + 10;
    const until = after + 90;
    const id = "validity-accepted";

    await expect(
      active.provider.request({
        method: "wallet_sendCalls",
        params: [bundle(active.account, id, validity(after, until))],
      }),
    ).resolves.toEqual({ id });

    const range = { validAfter: String(after), validUntil: String(until) };
    expect(readsAtPresentation).toBe(1);
    expect(observed.reads()).toBe(1);
    expect(base.quotes).toBe(1);
    expect(base.signatures).toHaveLength(1);
    expect(base.sends).toHaveLength(1);
    expect(base.sends[0]?.userOperation.callData).toBe(
      encodeKernelV4Execution({
        calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
        validityTimeRange: range,
      }),
    );
    const port = grantProviderPort(active.grant);
    const retained = await port.walletCallBundles.get({
      providerScopeId: port.providerScopeId as `0x${string}`,
      account: active.account,
      id,
    });
    expect(retained?.value.operation?.identity.userOperationHash).toBe(
      base.sends[0]?.userOperationHash,
    );
    await active.connection.close();
  });

  it("admits only one concurrent request for the same explicit ID", async () => {
    const base = createChainFixture();
    const observed = observingPolicyReads(base);
    let release!: () => void;
    let entered!: () => void;
    const decision = new Promise<"approved">((resolve) => {
      release = () => resolve("approved");
    });
    const presentationEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let presentations = 0;
    const active = await activeProvider({
      chain: observed.chain,
      confirmCalls: async () => {
        presentations += 1;
        entered();
        return decision;
      },
    });
    const after = active.realm.clock.now() + 10;
    const request = {
      method: "wallet_sendCalls",
      params: [bundle(active.account, "validity-concurrent", validity(after, after + 90))],
    };

    const first = active.provider.request(request);
    await presentationEntered;
    await providerError(active.provider.request(request), 5720);
    expect(presentations).toBe(1);
    expect(observed.reads()).toBe(1);
    release();
    await expect(first).resolves.toEqual({ id: "validity-concurrent" });
    expect(base.sends).toHaveLength(1);
    await active.connection.close();
  });

  it("rejects forged and consumed admission tokens before another quote", async () => {
    const active = await activeProvider();
    const port = grantProviderPort(active.grant);
    const after = active.realm.clock.now() + 10;
    const admitted = await port.admitValidityTimeRange({
      chain: CHAIN_ID,
      range: { validAfter: String(after), validUntil: String(after + 90) },
    });
    if (admitted.status !== "accepted") throw new Error("expected validity admission");

    await expect(
      port.startCalls(providerCallsInput({ kind: admitted.admission.kind }), publication),
    ).rejects.toMatchObject({ code: "oaath_client_capability_invalid" });
    expect(active.realm.chain.quotes).toBe(0);

    const first = port.startCalls(providerCallsInput(admitted.admission), publication);
    await expect(
      port.startCalls(providerCallsInput(admitted.admission), publication),
    ).rejects.toMatchObject({ code: "oaath_client_capability_invalid" });
    await first;
    expect(active.realm.chain.quotes).toBe(1);
    expect(active.realm.chain.sends).toHaveLength(1);
    await active.connection.close();
  });

  it("retains the range through static and ERC-7677 sponsored final preparation", async () => {
    const staticBase = createChainFixture();
    const configuration = staticConfiguration();
    const staticChain = replaceChain(staticBase, {
      staticPaymasterConfigurationHash: hashErc7902StaticPaymasterConfiguration(configuration),
    });
    const staticActive = await activeProvider({
      chain: staticChain,
      confirmCalls: async () => "approved" as const,
    });
    const after = staticActive.realm.clock.now() + 10;
    const range = validity(after, after + 90);

    await expect(
      staticActive.provider.request({
        method: "wallet_sendCalls",
        params: [
          bundle(staticActive.account, "validity-static", range, {
            staticPaymasterConfiguration: configuration,
          }),
        ],
      }),
    ).resolves.toEqual({ id: "validity-static" });
    await staticActive.connection.close();

    const dynamicBase = createChainFixture();
    const registered = registeredService();
    const dynamicActive = await activeProvider({
      chain: replaceChain(dynamicBase, { paymasterService: registered.service }),
      confirmCalls: async () => "approved" as const,
    });
    await expect(
      dynamicActive.provider.request({
        method: "wallet_sendCalls",
        params: [
          bundle(dynamicActive.account, "validity-dynamic", range, {
            paymasterService: { url: SERVICE_URL, context: {} },
          }),
        ],
      }),
    ).resolves.toEqual({ id: "validity-dynamic" });

    const expectedCallData = encodeKernelV4Execution({
      calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
      validityTimeRange: { validAfter: String(after), validUntil: String(after + 90) },
    });
    expect(staticBase.sends).toHaveLength(1);
    expect(staticBase.sends[0]?.userOperation.callData).toBe(expectedCallData);
    expect(staticBase.sends[0]?.userOperation.paymaster?.data).toBe("0x01020304");
    expect(dynamicBase.sends).toHaveLength(1);
    expect(dynamicBase.sends[0]?.userOperation.callData).toBe(expectedCallData);
    expect(dynamicBase.sends[0]?.userOperation.paymaster?.data).toBe("0x01020305");
    expect(registered.stages).toEqual(["stub", "estimate", "final"]);
    await dynamicActive.connection.close();
  });
});
