import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { concatHex, encodeFunctionData, toHex } from "viem";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mintCall } from "../src/plan.js";
import worker, { type Env } from "../worker/index.js";
import { ENTRY_POINT_V09, isMintCall, MINT_AMOUNT } from "../worker/rpc.js";

const ORIGIN = "https://dca.taek.tech";
const SERVICE = "https://automation.test";
const APP_TOKEN = "dca-app-credential-secret";
const ACCOUNT = `0x${"ab".repeat(20)}`;
const TUSD = "0xa394869aabedb1a989614aa9c3dd41907c596e71";
const allow = { limit: async () => ({ success: true }) };

function environment(overrides: { [K in keyof Env]?: Env[K] | undefined } = {}): Env {
  return {
    ASSETS: {
      fetch: async (request) =>
        new Response(new URL(request.url).pathname, { headers: { "content-type": "text/html" } }),
    },
    DCA_ORIGIN: ORIGIN,
    OAATH_ISSUER: "https://oaath.taek.tech",
    OAATH_CLIENT_ID: "client-1",
    EXPLORER_TX_URL: "https://sepolia.arbiscan.io/tx/",
    CHAIN_RPC_URL: "https://chain.test/rpc",
    AUTOMATION_URL: SERVICE,
    AUTOMATION_APP_TOKEN: APP_TOKEN,
    TUSD_TOKEN: TUSD,
    // The VPC binding; tests route it through the stubbed global fetch.
    BUNDLER: { fetch: (request: Request) => fetch(request) },
    RPC_LIMIT: allow,
    SEND_LIMIT: allow,
    ...overrides,
  } as Env;
}

function post(path: string, body: unknown, env = environment(), headers: HeadersInit = {}) {
  return worker.fetch(
    new Request(`${ORIGIN}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: ORIGIN, ...headers },
      body: typeof body === "string" ? body : JSON.stringify(body),
    }),
    env,
  );
}

const rpc = (method: string, params: unknown[] = [], id = 1) => ({
  jsonrpc: "2.0",
  id,
  method,
  params,
});

function upstream(answer: (request: Request) => Response | Promise<Response>) {
  const requests: Request[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo, init?: RequestInit) => {
      const request = new Request(input, init);
      requests.push(request.clone());
      return answer(request);
    }),
  );
  return requests;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("dca worker pages", () => {
  it("serves the page and the callback with a CSP naming only the issuer and the service", async () => {
    for (const [path, asset] of [
      ["/", "/index.html"],
      ["/callback?code=a&state=b", "/callback.html"],
    ] as const) {
      const response = await worker.fetch(new Request(`${ORIGIN}${path}`), environment());
      expect(await response.text()).toBe(asset);
      const policy = response.headers.get("content-security-policy") ?? "";
      expect(policy).toContain(`connect-src 'self' https://oaath.taek.tech ${SERVICE};`);
      expect(policy).toContain("script-src 'self';");
      expect(policy).toContain("frame-ancestors 'none'");
    }
    const asset = await worker.fetch(new Request(`${ORIGIN}/assets/index-abc.js`), environment());
    expect(asset.headers.get("cache-control")).toContain("immutable");
  });

  it("refuses unknown paths, writes to pages, and other hosts", async () => {
    const env = environment();
    expect((await worker.fetch(new Request(`${ORIGIN}/index.html`), env)).status).toBe(404);
    expect((await worker.fetch(new Request(`${ORIGIN}/assets/x.json`), env)).status).toBe(404);
    expect((await worker.fetch(new Request(`${ORIGIN}/`, { method: "POST" }), env)).status).toBe(
      404,
    );
    expect((await worker.fetch(new Request("https://evil.test/"), env)).status).toBe(421);
  });

  it("serves the client and the service from vars, never the app credential", async () => {
    const config = await worker.fetch(new Request(`${ORIGIN}/config.json`), environment());
    const text = await config.text();
    expect(JSON.parse(text)).toEqual({
      issuer: "https://oaath.taek.tech",
      clientId: "client-1",
      chainId: 421614,
      explorerTxUrl: "https://sepolia.arbiscan.io/tx/",
      automation: { url: SERVICE, prefix: "dca.arbsep." },
      mint: { token: TUSD, amount: "1000000000" },
    });
    expect(text).not.toContain(APP_TOKEN);
  });

  it("stays off without the app credential", async () => {
    const env = environment({ AUTOMATION_APP_TOKEN: undefined });
    const config = await worker.fetch(new Request(`${ORIGIN}/config.json`), env);
    expect((await config.json()).automation).toBeNull();
    expect((await post("/automation/session", { idToken: "x" }, env)).status).toBe(503);
    const page = await worker.fetch(new Request(`${ORIGIN}/`), env);
    expect(page.headers.get("content-security-policy")).not.toContain(SERVICE);
  });
});

describe("dca chain proxy", () => {
  it("forwards a read once to its one upstream", async () => {
    const requests = upstream(() => Response.json({ jsonrpc: "2.0", id: 1, result: "0x01" }));
    const call = rpc("eth_call", [{ to: ACCOUNT, data: "0x70a08231" }, "latest"]);
    const response = await post("/rpc/chain", call);
    expect(await response.json()).toEqual({ jsonrpc: "2.0", id: 1, result: "0x01" });
    expect(requests.map((request) => request.url)).toEqual(["https://chain.test/rpc"]);
    expect([...requests[0]!.headers.keys()]).toEqual(["content-type"]);
    expect(await requests[0]!.json()).toEqual(call);
  });

  it("refuses writes and other methods, cross-site callers, and oversize requests", async () => {
    const requests = upstream(() => Response.json({}));
    for (const method of ["eth_sendRawTransaction", "eth_sendUserOperation", "eth_getLogs"]) {
      const refused = await post("/rpc/chain", [rpc("eth_chainId"), rpc(method, [], 2)]);
      expect((await refused.json()).error.code).toBe(-32005);
    }
    expect(
      (
        await post("/rpc/chain", rpc("eth_chainId"), environment(), {
          "sec-fetch-site": "cross-site",
        })
      ).status,
    ).toBe(403);
    expect(
      (await post("/rpc/chain", rpc("eth_chainId"), environment(), { origin: "https://evil.test" }))
        .status,
    ).toBe(403);
    expect((await post("/rpc/chain", Array(9).fill(rpc("eth_chainId")))).status).toBe(413);
    expect((await post("/rpc/chain", "x".repeat(65 * 1024))).status).toBe(413);
    expect(requests).toHaveLength(0);
  });

  it("spends the per-IP budget before forwarding, and refuses without it", async () => {
    const requests = upstream(() => Response.json({ jsonrpc: "2.0", id: 1, result: "0x1" }));
    const spent: string[] = [];
    let remaining = 1;
    const budget = {
      limit: async ({ key }: { key: string }) => {
        spent.push(key);
        remaining -= 1;
        return { success: remaining >= 0 };
      },
    };
    const env = environment({ RPC_LIMIT: budget });
    const headers = { "cf-connecting-ip": "203.0.113.9" };
    expect((await post("/rpc/chain", rpc("eth_chainId"), env, headers)).status).toBe(200);
    expect((await post("/rpc/chain", rpc("eth_chainId"), env, headers)).status).toBe(429);
    expect(spent).toEqual(["203.0.113.9", "203.0.113.9"]);
    expect(
      (await post("/rpc/chain", rpc("eth_chainId"), environment({ RPC_LIMIT: undefined }))).status,
    ).toBe(429);
    expect(requests).toHaveLength(1);
  });

  it("answers an unreachable or unusable provider without retrying", async () => {
    const requests = upstream(() => {
      throw new TypeError("network");
    });
    expect((await post("/rpc/chain", rpc("eth_chainId"))).status).toBe(504);
    expect(requests).toHaveLength(1);
    upstream(() => new Response("<html>", { status: 200 }));
    expect((await post("/rpc/chain", rpc("eth_chainId"))).status).toBe(502);
  });
});

describe("dca automation session", () => {
  async function issuer() {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256" };
    const token = (audience = "client-1") =>
      new SignJWT({ signer: { id: "signer-1" } })
        .setProtectedHeader({ alg: "ES256", kid: "k1" })
        .setIssuer("https://oaath.taek.tech")
        .setAudience(audience)
        .setSubject(ACCOUNT)
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);
    return { jwk, token };
  }

  it("turns a verified login into a session through the service binding, with the app credential", async () => {
    const { jwk, token } = await issuer();
    const jwks = upstream(() => Response.json({ keys: [jwk] }));
    const bound: Request[] = [];
    const env = environment({
      AUTOMATION_SERVICE: {
        fetch: async (request: Request) => {
          bound.push(request.clone());
          return Response.json({
            token: "session",
            expiresAt: 99,
            account: ACCOUNT,
            keyScope: "user",
          });
        },
      },
    });
    const response = await post("/automation/session", { idToken: await token() }, env);
    expect(await response.json()).toEqual({ token: "session", expiresAt: 99, account: ACCOUNT });
    expect(bound.map((request) => request.url)).toEqual([`${SERVICE}/v1/sessions`]);
    expect(bound[0]!.headers.get("authorization")).toBe(`Bearer ${APP_TOKEN}`);
    expect(await bound[0]!.json()).toEqual({ userId: "signer-1", account: ACCOUNT });
    // Only the issuer's keys are fetched publicly; the service is reached through the binding.
    expect(jwks.every((request) => request.url === "https://oaath.taek.tech/oauth/jwks")).toBe(
      true,
    );
  });

  it("refuses another client's login, a forged token, and cross-site callers", async () => {
    const { jwk, token } = await issuer();
    const forged = await issuer();
    const requests = upstream(async () => Response.json({ keys: [jwk] }));
    for (const idToken of [await token("another-client"), await forged.token(), "not-a-jwt"]) {
      expect((await post("/automation/session", { idToken })).status).toBe(401);
    }
    expect(requests.some((request) => request.url.startsWith(SERVICE))).toBe(false);
    const cross = await post("/automation/session", { idToken: await token() }, environment(), {
      "sec-fetch-site": "cross-site",
    });
    expect(cross.status).toBe(403);
  });
});

/** Kernel v4 `execute(mode, executionData)` for one call. */
function execute(
  target: string,
  value: bigint,
  data: `0x${string}`,
  mode = toHex(0, { size: 32 }),
) {
  return encodeFunctionData({
    abi: [
      {
        type: "function",
        name: "execute",
        inputs: [
          { name: "mode", type: "bytes32" },
          { name: "executionCalldata", type: "bytes" },
        ],
        outputs: [],
        stateMutability: "payable",
      },
    ],
    args: [mode, concatHex([target as `0x${string}`, toHex(value, { size: 32 }), data])],
  });
}

const MINT = encodeFunctionData({
  abi: [
    {
      type: "function",
      name: "mint",
      inputs: [
        { name: "to", type: "address" },
        { name: "value", type: "uint256" },
      ],
      outputs: [],
      stateMutability: "nonpayable",
    },
  ],
  functionName: "mint",
  args: [ACCOUNT as `0x${string}`, MINT_AMOUNT],
});
const MINT_CALL = execute(TUSD, 0n, MINT);
const SENDER = `0x${"11".repeat(20)}`;

function relayed(callData: string, method = "eth_sendUserOperation", entryPoint = ENTRY_POINT_V09) {
  return rpc(method, [{ sender: SENDER, callData }, entryPoint]);
}

describe("dca mint relay", () => {
  it("answers 503 and hides the mint without the bundler binding or the token", async () => {
    const requests = upstream(() => Response.json({}));
    for (const env of [
      environment({ BUNDLER: undefined }),
      environment({ TUSD_TOKEN: undefined }),
    ]) {
      expect((await post("/rpc/bundler", relayed(MINT_CALL), env)).status).toBe(503);
      const config = await worker.fetch(new Request(`${ORIGIN}/config.json`), env);
      expect((await config.json()).mint).toBeNull();
    }
    expect(requests).toHaveLength(0);
  });

  it("estimates and sends only one zero-value mint of exactly 1,000 tUSD through EntryPoint 0.9", async () => {
    const requests = upstream(() => Response.json({}));
    const mint = (to: string, amount: bigint) =>
      `0x40c10f19${to.slice(2).padStart(64, "0")}${amount.toString(16).padStart(64, "0")}` as const;
    for (const method of ["eth_sendUserOperation", "eth_estimateUserOperationGas"]) {
      const refusals = [
        // The wrong amount.
        relayed(execute(TUSD, 0n, mint(ACCOUNT, MINT_AMOUNT + 1n)), method),
        relayed(execute(TUSD, 0n, mint(ACCOUNT, 1n)), method),
        // Another target, a value, another selector, trailing data.
        relayed(execute(`0x${"cd".repeat(20)}`, 0n, MINT), method),
        relayed(execute(TUSD, 1n, MINT), method),
        relayed(execute(TUSD, 0n, `0xa9059cbb${MINT.slice(10)}`), method),
        relayed(execute(TUSD, 0n, `${MINT}00`), method),
        // A recipient word with high bits set is not an address.
        relayed(execute(TUSD, 0n, `0x40c10f19${"ff".repeat(32)}${MINT.slice(74)}`), method),
        // A batch mode is refused even when its one call is the mint.
        relayed(execute(TUSD, 0n, MINT, `0x01${"00".repeat(31)}`), method),
        relayed("0x", method),
        relayed(MINT_CALL, method, `0x${"00".repeat(20)}`),
        // A state override would simulate against another state.
        rpc(method, [{ sender: SENDER, callData: MINT_CALL }, ENTRY_POINT_V09, {}]),
        rpc(method, [null, ENTRY_POINT_V09]),
      ];
      for (const body of refusals) {
        const answer = await (await post("/rpc/bundler", body)).json();
        expect(answer.error.code).toBe(-32005);
      }
      // One refused call refuses the whole batch.
      const mixed = await post("/rpc/bundler", [relayed(MINT_CALL, method), relayed("0x", method)]);
      expect((await mixed.json()).error.code).toBe(-32005);
    }
    expect(requests).toHaveLength(0);
  });

  it("accepts the page's mint for any recipient, plain or executeUserOp-wrapped", () => {
    const page = mintCall(TUSD, `0x${"77".repeat(20)}`, MINT_AMOUNT.toString());
    expect(isMintCall(execute(page.to, 0n, page.data), TUSD)).toBe(true);
    expect(isMintCall(MINT_CALL, TUSD)).toBe(true);
    expect(isMintCall(`0x8dd7712f${MINT_CALL.slice(2)}`, TUSD)).toBe(true);
    expect(isMintCall(MINT_CALL, `0x${"cd".repeat(20)}`)).toBe(false);
  });

  it("forwards the mint and receipt reads through the binding once, and spends the send budget", async () => {
    // Nothing reaches the public network: only the binding is called.
    const publicFetches = upstream(() => Response.json({}));
    const requests: Request[] = [];
    const sends: string[] = [];
    let remaining = 1;
    const env = environment({
      BUNDLER: {
        fetch: async (request: Request) => {
          requests.push(request.clone());
          const { id } = (await request.json()) as { id: number };
          return Response.json({ jsonrpc: "2.0", id, result: "0x01" });
        },
      },
      SEND_LIMIT: {
        limit: async ({ key }: { key: string }) => {
          sends.push(key);
          remaining -= 1;
          return { success: remaining >= 0 };
        },
      },
    });
    const headers = { "cf-connecting-ip": "203.0.113.9" };
    for (const body of [
      relayed(MINT_CALL, "eth_estimateUserOperationGas"),
      relayed(MINT_CALL),
      rpc("eth_getUserOperationReceipt", [`0x${"11".repeat(32)}`]),
    ]) {
      const response = await post("/rpc/bundler", body, env, headers);
      expect(await response.json()).toEqual({ jsonrpc: "2.0", id: 1, result: "0x01" });
    }
    expect((await post("/rpc/bundler", relayed(MINT_CALL), env, headers)).status).toBe(429);
    expect(sends).toEqual(["203.0.113.9", "203.0.113.9"]);
    expect(requests).toHaveLength(3);
    expect([...requests[0]!.headers.keys()]).toEqual(["content-type"]);
    expect(publicFetches).toHaveLength(0);
  });

  it("sends only the BUNDLER_API_KEY secret to the bundler, never a client's key", async () => {
    const requests: Request[] = [];
    const chain = upstream((request) => {
      requests.push(request.clone());
      return Response.json({ jsonrpc: "2.0", id: 1, result: "0x01" });
    });
    const env = environment({
      BUNDLER_API_KEY: "server-key",
      BUNDLER: {
        fetch: async (request: Request) => {
          requests.push(request.clone());
          return Response.json({ jsonrpc: "2.0", id: 1, result: "0x01" });
        },
      },
    });
    const client = { "x-api-key": "client-key" };
    await post("/rpc/bundler", { ...relayed(MINT_CALL), apiKey: "client-key" }, env, client);
    await post("/rpc/chain", { ...rpc("eth_chainId"), apiKey: "client-key" }, env, client);
    expect(requests).toHaveLength(2);
    expect(requests[0]!.headers.get("x-api-key")).toBe("server-key");
    expect(requests[1]!.headers.get("x-api-key")).toBeNull();
    for (const request of requests) expect(await request.text()).not.toContain("apiKey");
    expect(chain).toHaveLength(1);

    // Without the secret the bundler still gets the request, with no key at all.
    requests.length = 0;
    await post(
      "/rpc/bundler",
      relayed(MINT_CALL),
      environment({ BUNDLER: env.BUNDLER, BUNDLER_API_KEY: undefined }),
      client,
    );
    expect(requests).toHaveLength(1);
    expect(requests[0]!.headers.get("x-api-key")).toBeNull();
  });
});
