import { createPlanTerms, derivePlanPolicy, parseAutomation } from "@oaath/automation";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { concatHex, encodeAbiParameters, encodeFunctionData, toHex } from "viem";
import { afterEach, describe, expect, it, vi } from "vitest";
import pingDefinition from "../automation/demo-ping.automation.json" with { type: "json" };
import worker, { DEMO_AUTOMATION, type Env } from "../worker/index.js";
import { DEMO_SELECTOR, DEMO_TARGET, ENTRY_POINT_V09, isDemoCall } from "../worker/rpc.js";

const ORIGIN = "https://oaath-demo.taek.tech";
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

function relayed(callData: string, method = "eth_sendUserOperation", entryPoint = ENTRY_POINT_V09) {
  return rpc(method, [{ sender: `0x${"11".repeat(20)}`, callData }, entryPoint]);
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
      ["/", "/index.html"],
      ["/?invite=0xabc", "/index.html"],
      ["/callback?code=a&state=b", "/callback.html"],
    ] as const) {
      const response = await worker.fetch(new Request(`${ORIGIN}${path}`), environment());
      expect(await response.text()).toBe(asset);
      const policy = response.headers.get("content-security-policy") ?? "";
      expect(policy).toContain("connect-src 'self' https://oaath.taek.tech;");
      expect(policy).toContain("script-src 'self';");
      expect(policy).toContain("frame-ancestors 'none'");
    }
    for (const name of ["index-abc.js", "style-abc.css", "geist-latin-abc.woff2"]) {
      const asset = await worker.fetch(new Request(`${ORIGIN}/assets/${name}`), environment());
      expect(asset.status).toBe(200);
      expect(asset.headers.get("cache-control")).toContain("immutable");
    }
  });

  it("refuses unknown paths, writes to pages, and other hosts", async () => {
    const env = environment();
    expect((await worker.fetch(new Request(`${ORIGIN}/callback.html`), env)).status).toBe(404);
    expect((await worker.fetch(new Request(`${ORIGIN}/assets/../x`), env)).status).toBe(404);
    expect((await worker.fetch(new Request(`${ORIGIN}/assets/private.json`), env)).status).toBe(
      404,
    );
    expect((await worker.fetch(new Request(`${ORIGIN}/`, { method: "POST" }), env)).status).toBe(
      404,
    );
    expect((await worker.fetch(new Request("https://evil.test/"), env)).status).toBe(421);
  });

  it("serves the client id and the relay-paid flag from vars and bindings", async () => {
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
    const unsponsored = await worker.fetch(
      new Request(`${ORIGIN}/config.json`),
      environment({ BUNDLER: undefined }),
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
      ["/rpc/bundler", "pm_getPaymasterData"],
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
    keys.length = 0;
    expect(
      (
        await post(
          "/rpc/bundler",
          relayed(DEMO_CALL),
          environment({ SEND_LIMIT: spent(false) }),
          headers,
        )
      ).status,
    ).toBe(429);
    expect(keys).toEqual(["203.0.113.9"]);
    expect(requests).toHaveLength(0);
  });

  it("never repeats a send without an answer: a bare 504, one upstream attempt", async () => {
    const requests = upstream(() => {
      throw new Error("connection reset");
    });
    const response = await post("/rpc/bundler", relayed(DEMO_CALL));
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

describe("demo relay", () => {
  it("answers 503 without the bundler binding", async () => {
    const requests = upstream(() => Response.json({}));
    const response = await post(
      "/rpc/bundler",
      relayed(DEMO_CALL),
      environment({ BUNDLER: undefined }),
    );
    expect(response.status).toBe(503);
    expect(requests).toHaveLength(0);
  });

  it("sends and estimates only the demo's own call through EntryPoint 0.9", async () => {
    const requests = upstream(() => Response.json({}));
    for (const method of ["eth_sendUserOperation", "eth_estimateUserOperationGas"]) {
      const refusals = [
        relayed(execute(DEMO_TARGET, 1n, DEMO_SELECTOR), method),
        relayed(execute(`0x${"ab".repeat(20)}`, 0n, DEMO_SELECTOR), method),
        relayed(execute(DEMO_TARGET, 0n, "0xa9059cbb"), method),
        relayed(execute(DEMO_TARGET, 0n, `${DEMO_SELECTOR}00`), method),
        // A batch mode is refused even when its one call is the demo call.
        relayed(execute(DEMO_TARGET, 0n, DEMO_SELECTOR, `0x01${"00".repeat(31)}`), method),
        relayed("0x", method),
        relayed(DEMO_CALL, method, `0x${"00".repeat(20)}`),
        // A state override would simulate against another state.
        rpc(method, [{ callData: DEMO_CALL }, ENTRY_POINT_V09, {}]),
        rpc(method, [null, ENTRY_POINT_V09]),
      ];
      for (const body of refusals) {
        const answer = await (await post("/rpc/bundler", body)).json();
        expect(answer.error.code).toBe(-32005);
      }
      // One refused call refuses the whole batch.
      const mixed = await post("/rpc/bundler", [relayed(DEMO_CALL, method), relayed("0x", method)]);
      expect((await mixed.json()).error.code).toBe(-32005);
    }
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

  it("forwards the demo call and receipt reads through the binding only", async () => {
    // Nothing reaches the public network: only the binding is called.
    const publicFetches = upstream(() => Response.json({}));
    const requests: Request[] = [];
    const env = environment({
      BUNDLER: {
        fetch: async (request: Request) => {
          requests.push(request.clone());
          const { id } = (await request.json()) as { id: number };
          return Response.json({ jsonrpc: "2.0", id, result: "0x01" });
        },
      },
    });
    for (const body of [
      relayed(DEMO_CALL, "eth_estimateUserOperationGas"),
      relayed(DEMO_CALL),
      rpc("eth_getUserOperationReceipt", [`0x${"11".repeat(32)}`]),
    ]) {
      const response = await post("/rpc/bundler", body, env);
      expect(await response.json()).toEqual({ jsonrpc: "2.0", id: 1, result: "0x01" });
    }
    expect(requests).toHaveLength(3);
    expect([...requests[0]!.headers.keys()]).toEqual(["content-type"]);
    expect(((await requests[1]!.json()) as { params: unknown[] }).params).toEqual(
      relayed(DEMO_CALL).params,
    );
    expect(publicFetches).toHaveLength(0);
  });
});

describe("demo automation session", () => {
  const SERVICE = "https://automation.test";
  const APP_TOKEN = "automation-app-credential-secret";
  const ACCOUNT = `0x${"ab".repeat(20)}`;

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

  const configured = () =>
    environment({ AUTOMATION_URL: SERVICE, AUTOMATION_APP_TOKEN: APP_TOKEN });

  it("schedules a definition that calls only the demo target", () => {
    const definition = parseAutomation(pingDefinition);
    expect(definition.id).toBe(DEMO_AUTOMATION);
    expect(Object.values(definition.contracts).map((contract) => contract.address)).toEqual([
      DEMO_TARGET,
    ]);
    const terms = createPlanTerms(definition, {
      planId: `0x${"cd".repeat(32)}`,
      account: ACCOUNT as `0x${string}`,
      now: 1_800_000_000,
      occurrences: 3,
    });
    const policy = derivePlanPolicy(definition, terms, 1_800_000_000);
    expect(policy.calls).toHaveLength(1);
    expect(policy.calls[0]).toMatchObject({ target: DEMO_TARGET, valueLimit: "0" });
    expect(policy.perChainOperationLimit.count).toBe(3);
  });

  it("stays off without a service credential", async () => {
    const config = await worker.fetch(new Request(`${ORIGIN}/config.json`), environment());
    expect((await config.json()).automation).toBeNull();
    expect((await post("/automation/session", { idToken: "x" })).status).toBe(503);
    const page = await worker.fetch(new Request(`${ORIGIN}/`), environment());
    expect(page.headers.get("content-security-policy")).not.toContain(SERVICE);
  });

  it("names the service in the config and the CSP, never the credential", async () => {
    const config = await worker.fetch(new Request(`${ORIGIN}/config.json`), configured());
    const text = await config.text();
    expect(JSON.parse(text).automation).toEqual({ url: SERVICE, id: "demo.ping.v1" });
    expect(text).not.toContain(APP_TOKEN);
    const page = await worker.fetch(new Request(`${ORIGIN}/`), configured());
    expect(page.headers.get("content-security-policy")).toContain(
      `connect-src 'self' https://oaath.taek.tech ${SERVICE};`,
    );
  });

  it("turns a verified login into a session for exactly that signer and account", async () => {
    const { jwk, token } = await issuer();
    const requests = upstream(async (request) => {
      if (request.url === "https://oaath.taek.tech/oauth/jwks")
        return Response.json({ keys: [jwk] });
      return Response.json({ token: "session", expiresAt: 99, account: ACCOUNT, keyScope: "user" });
    });
    const response = await post("/automation/session", { idToken: await token() }, configured());
    expect(await response.json()).toEqual({ token: "session", expiresAt: 99, account: ACCOUNT });
    const created = requests.find((request) => request.url === `${SERVICE}/v1/sessions`);
    expect(created?.headers.get("authorization")).toBe(`Bearer ${APP_TOKEN}`);
    expect(await created?.json()).toEqual({ userId: "signer-1", account: ACCOUNT });
  });

  it("refuses another client's login, a forged token, and cross-site callers", async () => {
    const { jwk, token } = await issuer();
    const forged = await issuer();
    const requests = upstream(async () => Response.json({ keys: [jwk] }));
    for (const idToken of [await token("another-client"), await forged.token(), "not-a-jwt"]) {
      const response = await post("/automation/session", { idToken }, configured());
      expect(response.status).toBe(401);
    }
    expect(requests.some((request) => request.url.startsWith(SERVICE))).toBe(false);
    const cross = await post("/automation/session", { idToken: await token() }, configured(), {
      "sec-fetch-site": "cross-site",
    });
    expect(cross.status).toBe(403);
  });
});
