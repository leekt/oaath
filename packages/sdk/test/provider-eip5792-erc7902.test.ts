/**
 * Draft ERC-7902 static paymasters through the genuine wallet/Grant path.
 *
 * @author taek <leekt216@gmail.com>
 */
import { describe, expect, it } from "vitest";
import type { OaathChainCapability, OaathQuoteRequest } from "../src/advanced.js";
import { hashErc7902StaticPaymasterConfiguration } from "../src/advanced.js";
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
  createUrlRealm,
  permissionInput,
  TARGET,
} from "./support/browser.js";

const CHAIN_HEX = `0x${CHAIN_ID.toString(16)}`;
const PAYMASTER = `0x${"33".repeat(20)}` as const;

function configuration(
  overrides: Readonly<Record<string, unknown>> = {},
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    paymaster: PAYMASTER,
    paymasterData: "0x01020304",
    paymasterValidationGasLimit: "0x32",
    paymasterPostOpGasLimit: "0x3c",
    ...overrides,
  });
}

function bundle(
  account: `0x${string}`,
  id: string,
  staticPaymasterConfiguration: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  return {
    version: "2.0.0",
    id,
    from: account,
    chainId: CHAIN_HEX,
    atomicRequired: true,
    calls: [{ to: TARGET, data: CALL_DATA }],
    capabilities: { staticPaymasterConfiguration },
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

function staticChain(
  input: Readonly<{
    base?: ChainFixture;
    approved: Readonly<Record<string, unknown>>;
    quoteRequests?: Readonly<OaathQuoteRequest>[];
  }>,
): ChainFixture {
  const base = input.base ?? createChainFixture();
  const quoteRequests = input.quoteRequests as OaathQuoteRequest[] | undefined;
  return replaceChain(base, {
    staticPaymasterConfigurationHash: hashErc7902StaticPaymasterConfiguration(input.approved),
    async quote(request) {
      quoteRequests?.push(request);
      return base.capability.quote(request);
    },
  });
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

describe("wallet_sendCalls ERC-7902 static paymaster orchestration", () => {
  it("binds the authenticated configuration into quote, preparation, one send, and reload", async () => {
    const approved = configuration();
    const quoteRequests: OaathQuoteRequest[] = [];
    const base = createChainFixture();
    const chain = staticChain({ base, approved, quoteRequests });
    const first = createUrlRealm({ chain });
    const connection = await first.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });

    await expect(
      provider.request({
        method: "wallet_getCapabilities",
        params: [account],
      }),
    ).resolves.toEqual({
      [CHAIN_HEX]: {
        atomic: { status: "supported" },
        staticPaymasterConfiguration: { supported: true, status: "experimental" },
      },
    });

    await expect(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, "static-sponsored", approved)],
      }),
    ).resolves.toEqual({ id: "static-sponsored" });

    const expectedPaymaster = {
      address: PAYMASTER,
      data: "0x01020304",
      verificationGasLimit: "50",
      postOpGasLimit: "60",
    };
    expect(quoteRequests).toHaveLength(1);
    expect(quoteRequests[0]?.paymaster).toEqual(expectedPaymaster);
    expect(base.signatures).toHaveLength(1);
    expect(base.sends).toHaveLength(1);
    expect(base.sends[0]?.userOperation.paymaster).toEqual(expectedPaymaster);
    const exactHash = base.sends[0]?.userOperationHash;
    const port = grantProviderPort(grant);
    const retained = await port.walletCallBundles.get({
      providerScopeId: port.providerScopeId as `0x${string}`,
      account,
      id: "static-sponsored",
    });
    expect(retained?.value.operation?.identity.userOperationHash).toBe(exactHash);
    await connection.close();

    const second = createUrlRealm({
      chain,
      stores: first.stores,
      clock: first.clock,
      relay: first.relay,
    });
    const reconnected = await second.oaath.connect();
    const resumed = await reconnected.resume();
    if (resumed === null) throw new Error("expected the static-paymaster Grant to resume");
    const resumedProvider = oaathProvider({ grant: resumed, chain: CHAIN_ID });
    await expect(
      resumedProvider.request({
        method: "wallet_getCallsStatus",
        params: ["static-sponsored"],
      }),
    ).resolves.toMatchObject({ id: "static-sponsored", status: 200 });
    expect(quoteRequests).toHaveLength(1);
    expect(base.signatures).toHaveLength(1);
    expect(base.sends).toHaveLength(1);
    expect(base.sends[0]?.userOperationHash).toBe(exactHash);
    await reconnected.close();
  });

  it("rejects a required policy mismatch before bundle or execution effects and leaves the ID reusable", async () => {
    const approved = configuration();
    const base = createChainFixture();
    const realm = createUrlRealm({ chain: staticChain({ base, approved }) });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });

    await providerError(
      provider.request({
        method: "wallet_sendCalls",
        params: [
          bundle(account, "policy-mismatch", configuration({ paymasterData: "0x05060708" })),
        ],
      }),
      5700,
    );
    const port = grantProviderPort(grant);
    await expect(
      port.walletCallBundles.get({
        providerScopeId: port.providerScopeId as `0x${string}`,
        account,
        id: "policy-mismatch",
      }),
    ).resolves.toBeUndefined();
    expect(base.quotes).toBe(0);
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);

    await expect(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, "policy-mismatch", approved)],
      }),
    ).resolves.toEqual({ id: "policy-mismatch" });
    expect(base.sends).toHaveLength(1);
    await connection.close();
  });

  it("ignores an optional policy mismatch and stays self-funded", async () => {
    const approved = configuration();
    const quoteRequests: OaathQuoteRequest[] = [];
    const base = createChainFixture();
    const realm = createUrlRealm({ chain: staticChain({ base, approved, quoteRequests }) });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });

    await expect(
      provider.request({
        method: "wallet_sendCalls",
        params: [
          bundle(
            account,
            "optional-mismatch",
            configuration({ paymasterData: "0x05060708", optional: true }),
          ),
        ],
      }),
    ).resolves.toEqual({ id: "optional-mismatch" });
    expect(quoteRequests).toHaveLength(1);
    expect(quoteRequests[0]?.paymaster).toBeNull();
    expect(base.sends).toHaveLength(1);
    expect(base.sends[0]?.userOperation.paymaster).toBeNull();
    await connection.close();
  });

  it("rejects contradictory dynamic and static sponsorship before bundle or execution effects", async () => {
    const approved = configuration();
    const base = createChainFixture();
    const realm = createUrlRealm({ chain: staticChain({ base, approved }) });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });
    const request = bundle(account, "conflicting-paymasters", approved);
    request.capabilities = {
      staticPaymasterConfiguration: approved,
      paymasterService: {
        url: `https://issuer.example/chains/${CHAIN_ID}/paymaster`,
        context: {},
      },
    };

    await providerError(
      provider.request({ method: "wallet_sendCalls", params: [request] }),
      -32602,
    );
    const port = grantProviderPort(grant);
    await expect(
      port.walletCallBundles.get({
        providerScopeId: port.providerScopeId as `0x${string}`,
        account,
        id: "conflicting-paymasters",
      }),
    ).resolves.toBeUndefined();
    expect(base.quotes).toBe(0);
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);
    await connection.close();
  });

  it("refuses the direct route before quote, signing, or submission", async () => {
    const approved = configuration();
    const base = createChainFixture({
      bundler: "absent",
      feePayer: { address: `0x${"77".repeat(20)}`, balance: "1000000000000000000" },
    });
    const realm = createUrlRealm({ chain: staticChain({ base, approved }) });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const account = await grant.account(CHAIN_ID);
    const provider = oaathProvider({ grant, chain: CHAIN_ID });

    await providerError(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, "no-direct-static", approved)],
      }),
      -32603,
    );
    expect(base.quotes).toBe(0);
    expect(base.signatures).toHaveLength(0);
    expect(base.sends).toHaveLength(0);
    await connection.close();
  });
});
