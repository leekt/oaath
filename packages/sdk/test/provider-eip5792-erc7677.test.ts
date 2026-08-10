/**
 * ERC-7677 through the genuine EIP-5792 and Grant execution owners.
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
import { grantProviderPort } from "../src/client/grant-handle.js";
import {
  OAATH_PROVIDER_ERROR_MESSAGES,
  type OaathProviderErrorCode,
} from "../src/provider/errors.js";
import { oaathProvider } from "../src/viem.js";
import {
  CALL_DATA,
  CHAIN_ID,
  type ChainFixture,
  createChainFixture,
  createRealm,
  createUrlRealm,
  ISSUER_URL,
  permissionInput,
  TARGET,
} from "./support/browser.js";

const CHAIN_HEX = `0x${CHAIN_ID.toString(16)}`;
const SERVICE_URL = `https://issuer.example/chains/${CHAIN_ID}/paymaster`;
const FOREIGN_URL = "https://attacker.example/paymaster";
const PAYMASTER = `0x${"33".repeat(20)}` as const;
const SPONSOR = Object.freeze({
  name: "Example Sponsor",
  icon: "data:image/png;base64,AQ==",
});
const RESULT_CAPABILITIES = Object.freeze({
  paymasterService: Object.freeze({ sponsor: SPONSOR }),
});

function bundle(
  account: `0x${string}`,
  id: string,
  paymasterService: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  return {
    version: "2.0.0",
    id,
    from: account,
    chainId: CHAIN_HEX,
    atomicRequired: true,
    calls: [{ to: TARGET, data: CALL_DATA }],
    capabilities: { paymasterService },
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

function registeredService(
  options: Readonly<{
    malformedEstimate?: boolean;
    sponsor?: Readonly<{ name: string; icon?: string }>;
  }> = {},
): Readonly<{
  service: Readonly<OaathRegisteredPaymasterService>;
  stages: readonly string[];
  serviceRequests: readonly Readonly<Erc7677PaymasterServiceRequest>[];
  estimatorRequests: readonly Readonly<Erc7677GasEstimationRequest>[];
}> {
  const stages: string[] = [];
  const serviceRequests: Readonly<Erc7677PaymasterServiceRequest>[] = [];
  const estimatorRequests: Readonly<Erc7677GasEstimationRequest>[] = [];
  const service: Readonly<OaathRegisteredPaymasterService> = Object.freeze({
    url: SERVICE_URL,
    async request(request: Readonly<Erc7677PaymasterServiceRequest>) {
      serviceRequests.push(request);
      stages.push(request.method === "pm_getPaymasterStubData" ? "stub" : "final");
      if (request.method === "pm_getPaymasterStubData") {
        return {
          ...(options.sponsor === undefined ? {} : { sponsor: options.sponsor }),
          paymaster: PAYMASTER,
          paymasterData: "0x01020304",
          paymasterPostOpGasLimit: "0x3c",
        };
      }
      return { paymaster: PAYMASTER, paymasterData: "0x01020305" };
    },
    async estimate(request: Readonly<Erc7677GasEstimationRequest>) {
      estimatorRequests.push(request);
      stages.push("estimate");
      if (options.malformedEstimate) return { callGasLimit: "not-a-quantity" };
      return {
        callGasLimit: "100",
        verificationGasLimit: "200",
        preVerificationGas: "30",
        paymasterVerificationGasLimit: "50",
      };
    },
  });
  return Object.freeze({ service, stages, serviceRequests, estimatorRequests });
}

async function activeProvider(chain: ChainFixture) {
  const realm = createRealm({ chain });
  const connection = await realm.oaath.connect();
  const grant = await connection.requestPermission(permissionInput());
  const provider = oaathProvider({ grant, chain: CHAIN_ID });
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

describe("wallet_sendCalls ERC-7677 orchestration", () => {
  it("finalizes sponsorship before durable identity, signing, and one submission", async () => {
    const base = createChainFixture();
    const registered = registeredService({ sponsor: SPONSOR });
    const chain = replaceChain(base, { paymasterService: registered.service });
    const { connection, grant, provider, account } = await activeProvider(chain);

    await expect(
      provider.request({
        method: "wallet_sendCalls",
        params: [
          bundle(account, "sponsored", {
            url: SERVICE_URL,
            context: { policyId: "policy-a" },
          }),
        ],
      }),
    ).resolves.toEqual({ id: "sponsored", capabilities: RESULT_CAPABILITIES });

    expect(registered.stages).toEqual(["stub", "estimate", "final"]);
    expect(registered.serviceRequests).toHaveLength(2);
    expect(registered.estimatorRequests).toHaveLength(1);
    expect(registered.estimatorRequests[0]?.userOperation.signature).toMatch(/^0x[0-9a-f]+$/u);
    expect(base.quotes).toBe(1);
    expect(base.signatures).toHaveLength(1);
    expect(base.sends).toHaveLength(1);
    expect(registered.estimatorRequests[0]?.userOperation.signature).not.toBe(base.signatures[0]);
    const submitted = base.sends[0];
    expect(submitted?.userOperation).toMatchObject({
      callGasLimit: "100",
      verificationGasLimit: "200",
      preVerificationGas: "30",
      paymaster: {
        address: PAYMASTER,
        verificationGasLimit: "50",
        postOpGasLimit: "60",
        data: "0x01020305",
      },
    });
    const port = grantProviderPort(grant);
    const retained = await port.walletCallBundles.get({
      providerScopeId: port.providerScopeId as `0x${string}`,
      account,
      id: "sponsored",
    });
    expect(retained?.value.operation?.identity.userOperationHash).toBe(
      submitted?.userOperationHash,
    );
    expect(retained?.value.operation?.resultCapabilities).toEqual(RESULT_CAPABILITIES);
    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["sponsored"] }),
    ).resolves.toMatchObject({
      id: "sponsored",
      status: 200,
      capabilities: RESULT_CAPABILITIES,
    });
    await connection.close();
  });

  it("rejects an unregistered required URL before bundle or execution effects", async () => {
    const base = createChainFixture();
    const registered = registeredService();
    const chain = replaceChain(base, { paymasterService: registered.service });
    const { connection, grant, provider, account } = await activeProvider(chain);

    await providerError(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, "foreign-service", { url: FOREIGN_URL, context: {} })],
      }),
      5700,
    );
    const port = grantProviderPort(grant);
    await expect(
      port.walletCallBundles.get({
        providerScopeId: port.providerScopeId as `0x${string}`,
        account,
        id: "foreign-service",
      }),
    ).resolves.toBeUndefined();
    expect(registered.stages).toEqual([]);
    expect(base.quotes).toBe(0);
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);

    await expect(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, "foreign-service", { url: SERVICE_URL, context: {} })],
      }),
    ).resolves.toEqual({ id: "foreign-service" });
    expect(base.sends).toHaveLength(1);
    await connection.close();
  });

  it("ignores an unavailable optional service without attempting sponsorship", async () => {
    const base = createChainFixture();
    const registered = registeredService();
    const chain = replaceChain(base, { paymasterService: registered.service });
    const { connection, provider, account } = await activeProvider(chain);

    await expect(
      provider.request({
        method: "wallet_sendCalls",
        params: [
          bundle(account, "optional-service", {
            url: FOREIGN_URL,
            context: {},
            optional: true,
          }),
        ],
      }),
    ).resolves.toEqual({ id: "optional-service" });
    expect(registered.stages).toEqual([]);
    expect(base.quotes).toBe(1);
    expect(base.signatures).toHaveLength(1);
    expect(base.sends).toHaveLength(1);
    expect(base.sends[0]?.userOperation.paymaster).toBeNull();
    await connection.close();
  });

  it("never falls back to an unsponsored identity after invalid estimator evidence", async () => {
    const base = createChainFixture();
    const registered = registeredService({ malformedEstimate: true });
    const chain = replaceChain(base, { paymasterService: registered.service });
    const { connection, provider, account } = await activeProvider(chain);

    await providerError(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, "invalid-estimate", { url: SERVICE_URL, context: {} })],
      }),
      -32603,
    );
    expect(registered.stages).toEqual(["stub", "estimate"]);
    expect(base.quotes).toBe(1);
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);
    await connection.close();
  });

  it("omits a direct route, refuses required sponsorship, and ignores optional sponsorship", async () => {
    let probes = 0;
    const base = createChainFixture({
      bundler: "absent",
      feePayer: { address: `0x${"77".repeat(20)}`, balance: "1000000000000000000" },
    });
    const registered = registeredService();
    const chain = replaceChain(base, {
      bundler: Object.freeze({
        async probe(request: Parameters<OaathChainCapability["bundler"]["probe"]>[0]) {
          probes += 1;
          return base.capability.bundler.probe(request);
        },
      }),
      paymasterService: registered.service,
    });
    const { connection, grant, provider, account } = await activeProvider(chain);
    const id = "no-direct-sponsor";

    await expect(
      provider.request({ method: "wallet_getCapabilities", params: [account] }),
    ).resolves.toEqual({
      [CHAIN_HEX]: { atomic: { status: "supported" } },
    });

    await providerError(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, id, { url: SERVICE_URL, context: {} })],
      }),
      5700,
    );
    const port = grantProviderPort(grant);
    await expect(
      port.walletCallBundles.get({
        providerScopeId: port.providerScopeId as `0x${string}`,
        account,
        id,
      }),
    ).resolves.toBeUndefined();
    expect(registered.stages).toEqual([]);
    expect(base.quotes).toBe(0);
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);

    await expect(
      provider.request({
        method: "wallet_sendCalls",
        params: [
          bundle(account, id, {
            url: SERVICE_URL,
            context: {},
            optional: true,
          }),
        ],
      }),
    ).resolves.toEqual({ id });
    expect(probes).toBe(3);
    expect(registered.stages).toEqual([]);
    expect(base.quotes).toBe(1);
    expect(base.signatures).toHaveLength(1);
    expect(base.sends).toHaveLength(1);
    expect(base.sends[0]?.userOperation.paymaster).toBeNull();
    await connection.close();
  });

  it("advertises the official capability only for a registered chain", async () => {
    const registered = registeredService();
    const supported = await activeProvider(
      replaceChain(createChainFixture(), { paymasterService: registered.service }),
    );
    await expect(
      supported.provider.request({
        method: "wallet_getCapabilities",
        params: [supported.account],
      }),
    ).resolves.toEqual({
      [CHAIN_HEX]: {
        atomic: { status: "supported" },
        paymasterService: { supported: true },
      },
    });
    await supported.connection.close();

    const unavailable = await activeProvider(
      replaceChain(createChainFixture(), { paymasterService: null }),
    );
    await expect(
      unavailable.provider.request({
        method: "wallet_getCapabilities",
        params: [unavailable.account],
      }),
    ).resolves.toEqual({
      [CHAIN_HEX]: { atomic: { status: "supported" } },
    });
    await unavailable.connection.close();
  });

  it("uses only the authenticated same-service proxy and observes after realm recreation", async () => {
    const stages: string[] = [];
    const base = createChainFixture({
      paymasterService: Object.freeze({
        url: SERVICE_URL,
        async request() {
          throw new Error("the synthetic chain never owns paymaster HTTP");
        },
        async estimate() {
          stages.push("estimate");
          return {
            callGasLimit: "100",
            verificationGasLimit: "200",
            preVerificationGas: "30",
            paymasterVerificationGasLimit: "50",
          };
        },
      }),
    });
    const first = createUrlRealm({
      chain: base,
      paymasterService: {
        providerId: "paymaster-primary",
        requestTimeoutMs: 1_000,
        provider: {
          async getPaymasterStubData() {
            stages.push("stub");
            return {
              sponsor: SPONSOR,
              paymaster: PAYMASTER,
              paymasterData: "0x01020304",
              paymasterPostOpGasLimit: "0x3c",
            };
          },
          async getPaymasterData() {
            stages.push("final");
            return { paymaster: PAYMASTER, paymasterData: "0x01020305" };
          },
        },
      },
    });
    const connection = await first.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });

    await providerError(
      provider.request({
        method: "wallet_sendCalls",
        params: [
          bundle(account, "url-foreign", {
            url: FOREIGN_URL,
            context: { policyId: "attacker-selected" },
          }),
        ],
      }),
      5700,
    );
    expect(first.fetched.some((entry) => entry.includes("attacker.example"))).toBe(false);
    expect(stages).toEqual([]);
    expect(base.sends).toHaveLength(0);

    await expect(
      provider.request({
        method: "wallet_sendCalls",
        params: [
          bundle(account, "url-sponsored", {
            url: `${ISSUER_URL}/chains/${CHAIN_ID}/paymaster`,
            context: { policyId: "same-service" },
          }),
        ],
      }),
    ).resolves.toEqual({
      id: "url-sponsored",
      capabilities: RESULT_CAPABILITIES,
    });
    expect(stages).toEqual(["stub", "estimate", "final"]);
    expect(first.fetched.filter((entry) => entry.endsWith("/paymaster/stub-data"))).toHaveLength(1);
    expect(first.fetched.filter((entry) => entry.endsWith("/paymaster/data"))).toHaveLength(1);
    expect(first.fetched.filter((entry) => entry.endsWith("/bundler"))).toHaveLength(2);
    expect(base.sends).toHaveLength(1);
    const exactHash = base.sends[0]?.userOperationHash;
    await connection.close();

    const second = createUrlRealm({
      chain: base,
      stores: first.stores,
      clock: first.clock,
      relay: first.relay,
    });
    const reconnected = await second.oaath.connect();
    const resumed = await reconnected.resume();
    if (resumed === null) throw new Error("expected the sponsored Grant to resume");
    const presented: unknown[] = [];
    const resumedProvider = oaathProvider({
      grant: resumed,
      chain: CHAIN_ID,
      showCallsStatus(status) {
        presented.push(status);
      },
    });
    const status = await resumedProvider.request({
      method: "wallet_getCallsStatus",
      params: ["url-sponsored"],
    });
    expect(status).toMatchObject({
      id: "url-sponsored",
      status: 200,
      capabilities: RESULT_CAPABILITIES,
    });
    await expect(
      resumedProvider.request({ method: "wallet_showCallsStatus", params: ["url-sponsored"] }),
    ).resolves.toBeUndefined();
    expect(presented).toEqual([status]);
    expect(stages).toEqual(["stub", "estimate", "final"]);
    expect(base.signatures).toHaveLength(1);
    expect(base.sends).toHaveLength(1);
    expect(base.sends[0]?.userOperationHash).toBe(exactHash);
    await reconnected.close();
  });
});
