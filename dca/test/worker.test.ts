import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker, { type Env } from "../worker/index.js";

const ORIGIN = "https://dca.taek.tech";
const SERVICE = "https://automation.test";
const APP_TOKEN = "dca-app-credential-secret";
const ACCOUNT = `0x${"ab".repeat(20)}`;
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
    RPC_LIMIT: allow,
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
    expect((await post("/rpc/chain", "x".repeat(17 * 1024))).status).toBe(413);
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
