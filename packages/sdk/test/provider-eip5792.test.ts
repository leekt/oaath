/**
 * Final EIP-5792 orchestration through the genuine Grant provider port.
 *
 * @author taek <leekt216@gmail.com>
 */
import { describe, expect, it } from "vitest";
import type { OaathChainCapability } from "../src/advanced.js";
import {
  OAATH_PROVIDER_ERROR_MESSAGES,
  type OaathProviderErrorCode,
} from "../src/provider/errors.js";
import { type OaathProviderInput, oaathProvider } from "../src/viem.js";
import {
  CALL_DATA,
  CHAIN_ID,
  type ChainFixture,
  type ChainFixtureOptions,
  createChainFixture,
  createRealm,
  permissionInput,
  TARGET,
} from "./support/browser.js";

const CHAIN_HEX = `0x${CHAIN_ID.toString(16)}`;
const FOREIGN_ACCOUNT = `0x${"99".repeat(20)}`;

function bundle(
  account: `0x${string}`,
  overrides: Readonly<Record<string, unknown>> = {},
): Record<string, unknown> {
  return {
    version: "2.0.0",
    from: account,
    chainId: CHAIN_HEX,
    atomicRequired: true,
    calls: [{ to: TARGET, data: CALL_DATA }],
    ...overrides,
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

function countingChain(options: ChainFixtureOptions = {}): Readonly<{
  chain: ChainFixture;
  reads: () => number;
  requestTypes: () => readonly string[];
}> {
  const base = createChainFixture(options);
  let reads = 0;
  const requestTypes: string[] = [];
  const read: OaathChainCapability["observation"]["read"] = async (request) => {
    reads += 1;
    requestTypes.push(request.type);
    return base.capability.observation.read(request);
  };
  const chain = replaceChain(base, {
    observation: Object.freeze({
      read,
      close: () => base.capability.observation.close(),
    }),
  });
  return Object.freeze({
    chain,
    reads: () => reads,
    requestTypes: () => Object.freeze([...requestTypes]),
  });
}

async function activeProvider(
  chain: ChainFixture = createChainFixture(),
  showCallsStatus?: NonNullable<OaathProviderInput["showCallsStatus"]>,
) {
  const realm = createRealm({ chain });
  const connection = await realm.oaath.connect();
  const grant = await connection.requestPermission(permissionInput());
  const provider = oaathProvider({
    grant,
    chain: CHAIN_ID,
    ...(showCallsStatus === undefined ? {} : { showCallsStatus }),
  });
  const account = await grant.account(CHAIN_ID);
  return { realm, connection, grant, provider, account };
}

async function providerError(
  promise: Promise<unknown>,
  code: OaathProviderErrorCode,
): Promise<Error & { readonly code: number }> {
  const error = await promise.then(
    () => null,
    (reason: unknown) => reason,
  );
  expect(error).toBeInstanceOf(Error);
  expect(error).toMatchObject({
    name: "OaathProviderRpcError",
    code,
    message: OAATH_PROVIDER_ERROR_MESSAGES[code],
  });
  if (
    !(error instanceof Error) ||
    typeof (error as { readonly code?: unknown }).code !== "number"
  ) {
    throw new Error("expected a numeric provider error");
  }
  return error as Error & { readonly code: number };
}

describe("wallet_sendCalls orchestration", () => {
  it("preserves an exact app ID and safely defaults omitted values", async () => {
    const { realm, connection, provider, account } = await activeProvider();
    const id = " app-owned:\u0000/日本語/Keep-Exact ";

    const result = (await provider.request({
      method: "wallet_sendCalls",
      params: [
        bundle(account, {
          id,
          calls: [
            { to: TARGET, data: CALL_DATA },
            { to: TARGET, data: CALL_DATA, value: "0x0" },
          ],
        }),
      ],
    })) as { readonly id: string };

    expect(result).toEqual({ id });
    expect(result.id).toBe(id);
    expect(realm.chain.quotes).toBe(1);
    expect(realm.chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("generates an unpredictable-shape ID when the app omits one", async () => {
    const { realm, connection, provider, account } = await activeProvider();

    const result = (await provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account)],
    })) as { readonly id: string };

    expect(result.id).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(result.id).not.toBe(`0x${"00".repeat(32)}`);
    expect(realm.chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("reserves synchronously so concurrent duplicate IDs start exactly once", async () => {
    const { realm, connection, provider, account } = await activeProvider();
    const request = {
      method: "wallet_sendCalls",
      params: [bundle(account, { id: "concurrent-id" })],
    };

    const first = provider.request(request);
    const duplicate = provider.request(request);
    await providerError(duplicate, 5720);
    await expect(first).resolves.toEqual({ id: "concurrent-id" });

    expect(realm.chain.quotes).toBe(1);
    expect(realm.chain.signatures).toHaveLength(1);
    expect(realm.chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("ignores explicit optional capabilities and rejects required ones before effects", async () => {
    const { realm, connection, provider, account } = await activeProvider();

    for (const capabilities of [{ requiredTop: {} }, undefined]) {
      const calls =
        capabilities === undefined
          ? [{ to: TARGET, capabilities: { requiredCall: { optional: false } } }]
          : [{ to: TARGET }];
      await providerError(
        provider.request({
          method: "wallet_sendCalls",
          params: [
            bundle(account, {
              id: "required-capability",
              calls,
              ...(capabilities === undefined ? {} : { capabilities }),
            }),
          ],
        }),
        5700,
      );
    }
    expect(realm.chain.quotes).toBe(0);
    expect(realm.chain.signatures).toHaveLength(0);
    expect(realm.chain.sends).toHaveLength(0);

    await expect(
      provider.request({
        method: "wallet_sendCalls",
        params: [
          bundle(account, {
            id: "required-capability",
            calls: [
              {
                to: TARGET,
                data: CALL_DATA,
                capabilities: { callHint: { optional: true, hint: "ignored" } },
              },
            ],
            capabilities: { topHint: { optional: true, hint: "ignored" } },
          }),
        ],
      }),
    ).resolves.toEqual({ id: "required-capability" });
    expect(realm.chain.quotes).toBe(1);
    expect(realm.chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("returns 5710 for another chain and 4100 for another sender, then releases the ID", async () => {
    const { realm, connection, provider, account } = await activeProvider();
    const id = "retry-after-conclusive-refusal";

    await providerError(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, { id, chainId: "0x1" })],
      }),
      5710,
    );
    await providerError(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, { id, from: FOREIGN_ACCOUNT })],
      }),
      4100,
    );
    expect(realm.chain.quotes).toBe(0);
    expect(realm.chain.sends).toHaveLength(0);

    await expect(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, { id })],
      }),
    ).resolves.toEqual({ id });
    expect(realm.chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("sanitizes unexpected structured execution failures as internal errors", async () => {
    const base = createChainFixture();
    const chain = replaceChain(base, {
      async quote() {
        throw new Error("secret quote and storage details");
      },
    });
    const { connection, provider, account } = await activeProvider(chain);

    const error = await providerError(
      provider.request({
        method: "wallet_sendCalls",
        params: [bundle(account, { id: "internal-failure" })],
      }),
      -32603,
    );
    expect(error.message).toBe("Internal error");
    expect(error.message).not.toContain("secret");
    expect(base.sends).toHaveLength(0);
    await connection.close();
  });
});

describe("wallet_getCallsStatus state", () => {
  it("returns after submission with zero reads, stays 100, then durably reprojects terminal 200", async () => {
    let withheld = true;
    const observed = countingChain({ withholdReceipt: () => withheld });
    const { connection, provider, account } = await activeProvider(observed.chain);

    const sent = (await provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, { id: "withheld-finality" })],
    })) as { readonly id: string };
    expect(sent.id).toBe("withheld-finality");
    expect(observed.reads()).toBe(0);
    expect(observed.chain.sends).toHaveLength(1);

    const pending = (await provider.request({
      method: "wallet_getCallsStatus",
      params: [sent.id],
    })) as { readonly status: number };
    expect(pending.status).toBe(100);
    expect(observed.reads()).toBeGreaterThan(0);
    expect(observed.requestTypes()).not.toContain("transaction_receipt");
    expect(observed.chain.sends).toHaveLength(1);

    withheld = false;
    const terminal = (await provider.request({
      method: "wallet_getCallsStatus",
      params: [sent.id],
    })) as { readonly status: number };
    expect(terminal.status).toBe(200);
    expect(observed.requestTypes()).toContain("transaction_receipt");
    const readsAtTerminal = observed.reads();
    const cached = await provider.request({
      method: "wallet_getCallsStatus",
      params: [sent.id],
    });
    expect(cached).toEqual(terminal);
    expect(observed.reads()).toBeGreaterThan(readsAtTerminal);
    expect(observed.chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("returns 100 without observation while the known ID is still accepted", async () => {
    const observed = countingChain();
    let enterQuote!: () => void;
    let releaseQuote!: () => void;
    const quoteEntered = new Promise<void>((resolve) => {
      enterQuote = resolve;
    });
    const quoteReleased = new Promise<void>((resolve) => {
      releaseQuote = resolve;
    });
    const chain = replaceChain(observed.chain, {
      async quote(request) {
        enterQuote();
        await quoteReleased;
        return observed.chain.capability.quote(request);
      },
    });
    const { connection, provider, account } = await activeProvider(chain);

    const sending = provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, { id: "accepted-id" })],
    });
    await quoteEntered;
    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["accepted-id"] }),
    ).resolves.toMatchObject({ id: "accepted-id", status: 100 });
    expect(observed.reads()).toBe(0);
    expect(chain.sends).toHaveLength(0);

    releaseQuote();
    await expect(sending).resolves.toEqual({ id: "accepted-id" });
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("returns 100 without observation after binding and before submission", async () => {
    const observed = countingChain();
    let enterSubmission!: () => void;
    let releaseSubmission!: () => void;
    const submissionEntered = new Promise<void>((resolve) => {
      enterSubmission = resolve;
    });
    const submissionReleased = new Promise<void>((resolve) => {
      releaseSubmission = resolve;
    });
    const open: OaathChainCapability["submission"]["open"] = async (request) => {
      enterSubmission();
      await submissionReleased;
      return observed.chain.capability.submission.open(request);
    };
    const chain = replaceChain(observed.chain, {
      submission: Object.freeze({ open }),
    });
    const { connection, provider, account } = await activeProvider(chain);

    const sending = provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, { id: "bound-id" })],
    });
    await submissionEntered;
    await expect(
      provider.request({ method: "wallet_getCallsStatus", params: ["bound-id"] }),
    ).resolves.toMatchObject({ id: "bound-id", status: 100 });
    expect(observed.reads()).toBe(0);
    expect(chain.sends).toHaveLength(0);

    releaseSubmission();
    await expect(sending).resolves.toEqual({ id: "bound-id" });
    expect(chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("hides headless status existence and rejects malformed status params", async () => {
    const { connection, provider } = await activeProvider();

    await providerError(
      provider.request({ method: "wallet_getCallsStatus", params: ["unknown"] }),
      5730,
    );
    await providerError(
      provider.request({ method: "wallet_showCallsStatus", params: ["unknown"] }),
      4200,
    );
    for (const params of [undefined, [], ["a", "b"], new Array(1)]) {
      await providerError(provider.request({ method: "wallet_getCallsStatus", params }), -32602);
    }
    await providerError(
      provider.request({ method: "wallet_getCallsStatus", params: ["x".repeat(4_097)] }),
      -32602,
    );
    const extended = ["unknown"];
    Object.defineProperty(extended, "extra", { value: true, enumerable: true });
    await providerError(
      provider.request({ method: "wallet_getCallsStatus", params: extended }),
      -32602,
    );
    await connection.close();
  });
});

describe("wallet_showCallsStatus presentation", () => {
  it("returns 4200 for a known headless ID without observing", async () => {
    const observed = countingChain({ withholdReceipt: () => true });
    const { connection, provider, account } = await activeProvider(observed.chain);
    await provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, { id: "headless-id" })],
    });
    expect(observed.reads()).toBe(0);

    await providerError(
      provider.request({ method: "wallet_showCallsStatus", params: ["headless-id"] }),
      4200,
    );
    expect(observed.reads()).toBe(0);
    expect(observed.chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("observes through the shared status path and invokes the presenter once", async () => {
    const observed = countingChain({ withholdReceipt: () => true });
    let calls = 0;
    let presented: unknown;
    let presenterThis: unknown = "not-called";
    const presenter: NonNullable<OaathProviderInput["showCallsStatus"]> = async function (
      this: void,
      status,
    ) {
      calls += 1;
      presenterThis = this;
      presented = status;
    };
    const { connection, provider, account } = await activeProvider(observed.chain, presenter);
    await provider.request({
      method: "wallet_sendCalls",
      params: [bundle(account, { id: "presented-id" })],
    });
    const quotes = observed.chain.quotes;
    const signatures = observed.chain.signatures.length;

    await expect(
      provider.request({ method: "wallet_showCallsStatus", params: ["presented-id"] }),
    ).resolves.toBeUndefined();
    expect(calls).toBe(1);
    expect(presenterThis).toBeUndefined();
    expect(presented).toEqual({
      version: "2.0.0",
      id: "presented-id",
      chainId: CHAIN_HEX,
      atomic: true,
      status: 100,
    });
    expect(Object.isFrozen(presented)).toBe(true);
    expect(observed.reads()).toBeGreaterThan(0);
    expect(observed.chain.quotes).toBe(quotes);
    expect(observed.chain.signatures).toHaveLength(signatures);
    expect(observed.chain.sends).toHaveLength(1);
    await connection.close();
  });
});

describe("wallet_getCapabilities authorization and parsing", () => {
  it("advertises atomic only for the configured requested chain", async () => {
    const { connection, provider, account } = await activeProvider();
    const uppercaseAccount = `0x${account.slice(2).toUpperCase()}`;

    await expect(
      provider.request({ method: "wallet_getCapabilities", params: [uppercaseAccount] }),
    ).resolves.toEqual({
      [CHAIN_HEX]: { atomic: { status: "supported" } },
    });
    const mixed = (await provider.request({
      method: "wallet_getCapabilities",
      params: [account, ["0x1", CHAIN_HEX]],
    })) as Record<string, unknown>;
    expect(mixed).toEqual({ [CHAIN_HEX]: { atomic: { status: "supported" } } });
    expect(mixed).not.toHaveProperty("0x0");
    await expect(
      provider.request({ method: "wallet_getCapabilities", params: [account, ["0x1"]] }),
    ).resolves.toEqual({});
    await connection.close();
  });

  it("returns 4100 for another address and rejects noncanonical or hostile params", async () => {
    const { connection, provider, account } = await activeProvider();

    await providerError(
      provider.request({ method: "wallet_getCapabilities", params: [FOREIGN_ACCOUNT] }),
      4100,
    );
    for (const params of [
      undefined,
      [],
      [account, ["0x0"]],
      [account, ["0x01"]],
      [account, ["0xA"]],
      [account, new Array(1)],
    ]) {
      await providerError(provider.request({ method: "wallet_getCapabilities", params }), -32602);
    }
    const extended = [account];
    Object.defineProperty(extended, "extra", { value: true, enumerable: true });
    await providerError(
      provider.request({ method: "wallet_getCapabilities", params: extended }),
      -32602,
    );
    await connection.close();
  });
});
