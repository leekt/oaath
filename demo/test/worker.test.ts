import { concatHex, encodeAbiParameters, encodeFunctionData, toHex } from "viem";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker, { type Env } from "../worker/index.js";
import { DEMO_SELECTOR, DEMO_TARGET, ENTRY_POINT_V09, isDemoCall } from "../worker/rpc.js";

const ORIGIN = "https://oaath-demo.taek.tech";
const KEY = "pim_SECRET_test_key_123";
const allow = { limit: async () => ({ success: true }) };

function environment(overrides: { [K in keyof Env]?: Env[K] | undefined } = {}): Env {
  return {
    ASSETS: {
      fetch: async (request) =>
        new Response(new URL(request.url).pathname, { headers: { "content-type": "text/html" } }),
    },
    DEMO_ORIGIN: ORIGIN,
    OAATH_ISSUER: "https://oaath.taek.tech",
    OAATH_CLIENT_ID: "client-1",
    EXPLORER_TX_URL: "https://sepolia.arbiscan.io/tx/",
    CHAIN_RPC_URL: "https://chain.test/rpc",
    BUNDLER_URL: "https://bundler.test/rpc",
    PAYMASTER_URL: "https://paymaster.test/v2/421614/rpc",
    PIMLICO_API_KEY: KEY,
    RPC_LIMIT: allow,
    SEND_LIMIT: allow,
    SPONSOR_LIMIT: allow,
    SPONSOR_GLOBAL_LIMIT: allow,
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

const DEMO_CALL = execute(DEMO_TARGET, 0n, DEMO_SELECTOR);

function sponsor(callData: string, method = "pm_getPaymasterData", chainId = "0x66eee") {
  return rpc(method, [{ sender: `0x${"11".repeat(20)}`, callData }, ENTRY_POINT_V09, chainId, {}]);
}

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

describe("demo worker pages", () => {
  it("serves the SPA and the callback with a strict CSP naming the issuer", async () => {
    for (const [path, asset] of [
      ["/", "/"],
      ["/?invite=0xabc", "/"],
      ["/callback?code=a&state=b", "/callback.html"],
    ] as const) {
      const response = await worker.fetch(new Request(`${ORIGIN}${path}`), environment());
      expect(await response.text()).toBe(asset);
      const policy = response.headers.get("content-security-policy") ?? "";
      expect(policy).toContain("connect-src 'self' https://oaath.taek.tech;");
      expect(policy).toContain("script-src 'self';");
      expect(policy).toContain("frame-ancestors 'none'");
    }
    const asset = await worker.fetch(new Request(`${ORIGIN}/assets/index-abc.js`), environment());
    expect(asset.headers.get("cache-control")).toContain("immutable");
  });

  it("refuses unknown paths, writes to pages, and other hosts", async () => {
    const env = environment();
    expect((await worker.fetch(new Request(`${ORIGIN}/callback.html`), env)).status).toBe(404);
    expect((await worker.fetch(new Request(`${ORIGIN}/assets/../x`), env)).status).toBe(404);
    expect((await worker.fetch(new Request(`${ORIGIN}/`, { method: "POST" }), env)).status).toBe(
      404,
    );
    expect((await worker.fetch(new Request("https://evil.test/"), env)).status).toBe(421);
  });

  it("serves the client id and sponsorship flag from vars, never the key", async () => {
    const config = await worker.fetch(new Request(`${ORIGIN}/config.json`), environment());
    const text = await config.text();
    expect(JSON.parse(text)).toMatchObject({
      issuer: "https://oaath.taek.tech",
      clientId: "client-1",
      chainId: 421614,
      target: DEMO_TARGET,
      selector: DEMO_SELECTOR,
      sponsored: true,
    });
    expect(text).not.toContain(KEY);
    const unsponsored = await worker.fetch(
      new Request(`${ORIGIN}/config.json`),
      environment({ PIMLICO_API_KEY: undefined }),
    );
    expect((await unsponsored.json()).sponsored).toBe(false);
  });
});

describe("demo worker proxies", () => {
  it("forwards an allow-listed call once to its one upstream", async () => {
    const requests = upstream(() => Response.json({ jsonrpc: "2.0", id: 1, result: "0x66eee" }));
    const response = await post("/rpc/chain", rpc("eth_chainId"));
    expect(await response.json()).toEqual({ jsonrpc: "2.0", id: 1, result: "0x66eee" });
    expect(requests.map((request) => request.url)).toEqual(["https://chain.test/rpc"]);
    expect([...requests[0]!.headers.keys()]).toEqual(["content-type"]);
  });

  it("refuses cross-site requests and requests without the demo origin", async () => {
    const requests = upstream(() => Response.json({}));
    expect(
      (await post("/rpc/chain", rpc("eth_chainId"), environment(), { origin: "https://evil.test" }))
        .status,
    ).toBe(403);
    expect(
      (
        await post("/rpc/chain", rpc("eth_chainId"), environment(), {
          "sec-fetch-site": "cross-site",
        })
      ).status,
    ).toBe(403);
    expect(requests).toHaveLength(0);
  });

  it("refuses methods outside each role's allow-list, oversize batches and bodies", async () => {
    const requests = upstream(() => Response.json({}));
    for (const [path, method] of [
      ["/rpc/chain", "eth_sendRawTransaction"],
      ["/rpc/chain", "eth_sendUserOperation"],
      ["/rpc/bundler", "eth_call"],
      ["/rpc/bundler", "debug_bundler_clearState"],
      ["/paymaster/421614", "eth_chainId"],
    ] as const) {
      const response = await post(path, rpc(method));
      expect((await response.json()).error.message).toBe("method not allowed by the demo");
    }
    // One refused call refuses the whole batch.
    const mixed = await post("/rpc/chain", [rpc("eth_chainId", [], 1), rpc("eth_sign", [], 2)]);
    expect((await mixed.json()).error.message).toBe("method not allowed by the demo");
    const many = Array.from({ length: 9 }, (_, id) => rpc("eth_chainId", [], id));
    expect((await post("/rpc/chain", many)).status).toBe(413);
    expect((await post("/rpc/chain", "x".repeat(70 * 1024))).status).toBe(413);
    expect((await post("/rpc/chain", "{")).status).toBe(400);
    expect(requests).toHaveLength(0);
  });

  it("spends the per-IP budgets before forwarding, and refuses without a binding", async () => {
    const requests = upstream(() => Response.json({ jsonrpc: "2.0", id: 1, result: "0x1" }));
    const keys: string[] = [];
    const spent = (success: boolean) => ({
      limit: async ({ key }: { key: string }) => {
        keys.push(key);
        return { success };
      },
    });
    const headers = { "cf-connecting-ip": "203.0.113.9" };
    expect(
      (
        await post(
          "/rpc/chain",
          rpc("eth_chainId"),
          environment({ RPC_LIMIT: spent(false) }),
          headers,
        )
      ).status,
    ).toBe(429);
    expect(keys).toEqual(["203.0.113.9"]);
    expect(
      (await post("/rpc/chain", rpc("eth_chainId"), environment({ RPC_LIMIT: undefined }))).status,
    ).toBe(429);
    const send = rpc("eth_sendUserOperation", [{}, ENTRY_POINT_V09]);
    expect(
      (await post("/rpc/bundler", send, environment({ SEND_LIMIT: spent(false) }))).status,
    ).toBe(429);
    keys.length = 0;
    expect(
      (
        await post(
          "/paymaster/421614",
          sponsor(DEMO_CALL),
          environment({ SPONSOR_GLOBAL_LIMIT: spent(false) }),
          headers,
        )
      ).status,
    ).toBe(429);
    // The global sponsorship budget is one key for everyone.
    expect(keys).toEqual(["global"]);
    expect(requests).toHaveLength(0);
  });

  it("never repeats a send without an answer: a bare 504, one upstream attempt", async () => {
    const requests = upstream(() => {
      throw new Error("connection reset");
    });
    const response = await post(
      "/rpc/bundler",
      rpc("eth_sendUserOperation", [{ sender: "0x1" }, ENTRY_POINT_V09]),
    );
    expect(response.status).toBe(504);
    expect(await response.text()).toBe("");
    expect(requests).toHaveLength(1);
  });

  it("refuses an unusable provider answer instead of passing it on", async () => {
    upstream(() => new Response("<html>oops</html>", { status: 200 }));
    expect((await post("/rpc/chain", rpc("eth_chainId"))).status).toBe(502);
    upstream(() => Response.json({ error: "x" }, { status: 500 }));
    expect((await post("/rpc/chain", rpc("eth_chainId"))).status).toBe(502);
  });
});

describe("demo paymaster", () => {
  it("answers 503 when no key is configured", async () => {
    const requests = upstream(() => Response.json({}));
    const response = await post(
      "/paymaster/421614",
      sponsor(DEMO_CALL),
      environment({ PIMLICO_API_KEY: undefined }),
    );
    expect(response.status).toBe(503);
    expect(requests).toHaveLength(0);
  });

  it("sponsors only the demo's own call on 421614 through EntryPoint 0.9", async () => {
    const requests = upstream(() => Response.json({}));
    const refusals = [
      sponsor(execute(DEMO_TARGET, 1n, DEMO_SELECTOR)),
      sponsor(execute(`0x${"ab".repeat(20)}`, 0n, DEMO_SELECTOR)),
      sponsor(execute(DEMO_TARGET, 0n, "0xa9059cbb")),
      sponsor(execute(DEMO_TARGET, 0n, `${DEMO_SELECTOR}00`)),
      // A batch mode is refused even when its one call is the demo call.
      sponsor(execute(DEMO_TARGET, 0n, DEMO_SELECTOR, `0x01${"00".repeat(31)}`)),
      sponsor("0x"),
      sponsor(DEMO_CALL, "pm_getPaymasterData", "0x1"),
      rpc("pm_getPaymasterData", [{ callData: DEMO_CALL }, `0x${"00".repeat(20)}`, "0x66eee", {}]),
    ];
    for (const body of refusals) {
      const answer = await (await post("/paymaster/421614", body)).json();
      expect(answer.error.code).toBe(-32005);
    }
    expect((await post("/paymaster/421614", [sponsor(DEMO_CALL), sponsor(DEMO_CALL)])).status).toBe(
      400,
    );
    expect(requests).toHaveLength(0);
  });

  it("recognises the SDK's call shapes: plain, executeUserOp-wrapped, and validity-ranged", () => {
    expect(isDemoCall(DEMO_CALL)).toBe(true);
    expect(isDemoCall(`0x8dd7712f${DEMO_CALL.slice(2)}`)).toBe(true);
    const ranged =
      `0x0000000000001ba8f415${"00".repeat(6)}${"ff".repeat(6)}${"00".repeat(10)}` as const;
    expect(isDemoCall(execute(DEMO_TARGET, 0n, DEMO_SELECTOR, ranged))).toBe(true);
    expect(
      isDemoCall(
        execute(
          DEMO_TARGET,
          0n,
          encodeAbiParameters([{ type: "bytes4" }], [DEMO_SELECTOR]) as `0x${string}`,
        ),
      ),
    ).toBe(false);
  });

  it("forwards with the key and the configured policy, and never leaks the key", async () => {
    const logged: unknown[] = [];
    for (const level of ["log", "info", "warn", "error", "debug"] as const)
      vi.spyOn(console, level).mockImplementation((...args) => void logged.push(...args));
    const requests = upstream(async (request) =>
      // A provider echoing its own URL must not hand the key to the page.
      Response.json({
        jsonrpc: "2.0",
        id: 1,
        error: { code: -32000, message: `rejected at ${request.url}` },
      }),
    );
    const env = environment({ PIMLICO_SPONSORSHIP_POLICY_ID: "sp_demo" });
    const response = await post("/paymaster/421614", sponsor(DEMO_CALL), env);
    const text = await response.text();
    expect(text).not.toContain(KEY);
    expect(text).toContain("[redacted]");
    expect(requests).toHaveLength(1);
    const url = new URL(requests[0]!.url);
    expect(`${url.origin}${url.pathname}`).toBe("https://paymaster.test/v2/421614/rpc");
    expect(url.searchParams.get("apikey")).toBe(KEY);
    const forwarded = (await requests[0]!.json()) as { params: unknown[] };
    expect(forwarded.params[3]).toEqual({ sponsorshipPolicyId: "sp_demo" });

    upstream(() => {
      throw new Error(`fetch failed for https://paymaster.test/?apikey=${KEY}`);
    });
    const lost = await post(
      "/paymaster/421614",
      sponsor(DEMO_CALL, "pm_getPaymasterStubData"),
      env,
    );
    expect(lost.status).toBe(504);
    expect(await lost.text()).toBe("");
    expect(JSON.stringify(logged)).not.toContain(KEY);
  });
});
