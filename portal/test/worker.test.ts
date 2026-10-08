import { afterEach, describe, expect, it, vi } from "vitest";
import worker, { type Env, MAX_BODY_BYTES, ORIGIN } from "../worker/index.js";

interface Recorded {
  readonly requests: Request[];
  readonly env: Env;
}

function environment(): Recorded {
  const requests: Request[] = [];
  return {
    requests,
    env: {
      ASSETS: {
        fetch: async (request) =>
          new Response(new URL(request.url).pathname === "/" ? "<!doctype html>" : "asset", {
            headers: { "content-type": "text/html" },
          }),
      },
      RELAY: {
        fetch: async (request) => {
          requests.push(request);
          return Response.json({ ok: true });
        },
      },
      WRITE_LIMIT: { limit: async () => ({ success: true }) },
    },
  };
}

function call(path: string, init: RequestInit = {}, recorded = environment()) {
  return worker.fetch(new Request(`${ORIGIN}${path}`, init), recorded.env);
}

describe("portal worker", () => {
  it("serves the SPA document for its pages, and hashed assets", async () => {
    for (const path of [
      "/",
      "/authorize?client_id=a&request_uri=b",
      "/link/Ab_c-1",
      "/requests/Ab_c-1",
      "/accounts",
      "/developers",
    ]) {
      const response = await call(path);
      expect(response.status).toBe(200);
      expect(await response.text()).toBe("<!doctype html>");
      expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    }
    const asset = await call("/assets/index-abc123.js");
    expect(await asset.text()).toBe("asset");
    expect(asset.headers.get("cache-control")).toContain("immutable");
  });

  it("refuses unknown paths, writes to pages, and other hosts", async () => {
    expect((await call("/admin")).status).toBe(404);
    expect((await call("/assets/../secret")).status).toBe(404);
    expect((await call("/link/")).status).toBe(404);
    expect((await call("/link/a/b")).status).toBe(404);
    expect((await call("/requests/a/b")).status).toBe(404);
    expect((await call("/", { method: "POST" })).status).toBe(404);
    const recorded = environment();
    const other = await worker.fetch(new Request("https://evil.example/portal/x"), recorded.env);
    expect(other.status).toBe(421);
    expect(recorded.requests).toHaveLength(0);
  });

  it("refuses cross-site portal API calls before reaching the relay", async () => {
    const recorded = environment();
    for (const site of ["cross-site", "same-site", "none"]) {
      const response = await call(
        "/portal/transactions/abc",
        { headers: { "sec-fetch-site": site } },
        recorded,
      );
      expect(response.status).toBe(403);
    }
    const write = await call(
      "/portal/signers",
      { method: "POST", headers: { origin: "https://dapp.example" }, body: "{}" },
      recorded,
    );
    expect(write.status).toBe(403);
    expect(recorded.requests).toHaveLength(0);
  });

  it("forwards same-origin portal calls with only allow-listed headers", async () => {
    const recorded = environment();
    const response = await call(
      "/portal/signers",
      {
        method: "POST",
        headers: {
          origin: ORIGIN,
          "sec-fetch-site": "same-origin",
          "content-type": "application/json",
          "x-forwarded-for": "203.0.113.9",
          forwarded: "for=203.0.113.9",
          "cf-connecting-ip": "203.0.113.9",
          "x-oaath-client-ip": "198.51.100.1",
          cookie: "session=1",
        },
        body: '{"profile":{}}',
      },
      recorded,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    const [forwarded] = recorded.requests;
    expect(forwarded?.url).toBe("http://oaath.taek.tech/portal/signers");
    expect(await forwarded?.text()).toBe('{"profile":{}}');
    for (const name of ["x-forwarded-for", "forwarded", "cf-connecting-ip"])
      expect(forwarded?.headers.get(name)).toBeNull();
    expect(forwarded?.headers.get("content-type")).toBe("application/json");
    expect(forwarded?.headers.get("cookie")).toBe("session=1");
    // The relay's client address is Cloudflare's, never the client's own claim.
    expect(forwarded?.headers.get("x-oaath-client-ip")).toBe("203.0.113.9");
  });

  it("drops a client-supplied client address when Cloudflare names none", async () => {
    const recorded = environment();
    await call(
      "/oauth/par",
      { method: "POST", headers: { "x-oaath-client-ip": "198.51.100.1" }, body: "client_id=a" },
      recorded,
    );
    const [forwarded] = recorded.requests;
    expect(forwarded?.headers.get("x-oaath-client-ip")).toBeNull();
  });

  it("carries the session cookie on /portal/* only, in both directions", async () => {
    const SET_COOKIE =
      "oaath_portal_session=t; Max-Age=1800; Path=/portal; HttpOnly; Secure; SameSite=Strict";
    const requests: Request[] = [];
    const env: Env = {
      ...environment().env,
      RELAY: {
        fetch: async (request) => {
          requests.push(request);
          return Response.json({}, { headers: { "set-cookie": SET_COOKIE } });
        },
      },
    };
    const portal = await worker.fetch(
      new Request(`${ORIGIN}/portal/sessions`, {
        method: "DELETE",
        headers: { origin: ORIGIN, "sec-fetch-site": "same-origin", cookie: "a=1" },
      }),
      env,
    );
    expect(portal.status).toBe(200);
    expect(portal.headers.get("set-cookie")).toBe(SET_COOKIE);
    expect(requests[0]?.method).toBe("DELETE");
    expect(requests[0]?.headers.get("cookie")).toBe("a=1");
    // A template edit is a same-origin PUT; PATCH is not a portal method.
    for (const [method, status] of [
      ["PUT", 200],
      ["PATCH", 405],
    ] as const) {
      const response = await worker.fetch(
        new Request(`${ORIGIN}/portal/accounts/a/policies/t`, {
          method,
          headers: {
            origin: ORIGIN,
            "sec-fetch-site": "same-origin",
            "content-type": "application/json",
          },
          body: "{}",
        }),
        env,
      );
      expect(response.status).toBe(status);
    }
    expect(requests[1]?.method).toBe("PUT");
    expect(requests).toHaveLength(2);

    const oauth = await worker.fetch(
      new Request(`${ORIGIN}/oauth/token`, {
        method: "POST",
        headers: { cookie: "a=1" },
        body: "grant_type=authorization_code",
      }),
      env,
    );
    expect(oauth.status).toBe(200);
    expect(oauth.headers.get("set-cookie")).toBeNull();
    expect(requests[1]?.headers.get("cookie")).toBeNull();
  });

  it("answers OAuth CORS preflight and forwards cross-site OAuth calls", async () => {
    const recorded = environment();
    const preflight = await call(
      "/oauth/par",
      {
        method: "OPTIONS",
        headers: {
          origin: "https://dapp.example",
          "access-control-request-method": "POST",
          "sec-fetch-site": "cross-site",
        },
      },
      recorded,
    );
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("access-control-allow-origin")).toBe("*");
    expect(preflight.headers.get("access-control-allow-methods")).toContain("POST");
    expect(preflight.headers.get("access-control-allow-credentials")).toBeNull();
    const par = await call(
      "/oauth/par",
      {
        method: "POST",
        headers: { origin: "https://dapp.example", "sec-fetch-site": "cross-site" },
        body: "client_id=a",
      },
      recorded,
    );
    expect(par.status).toBe(200);
    expect(par.headers.get("access-control-allow-origin")).toBe("*");
    const discovery = await call("/.well-known/openid-configuration", {}, recorded);
    expect(discovery.status).toBe(200);
    expect(recorded.requests.map((request) => new URL(request.url).pathname)).toEqual([
      "/oauth/par",
      "/.well-known/openid-configuration",
    ]);
  });

  it("refuses an oversized body, declared or streamed", async () => {
    const recorded = environment();
    const big = "x".repeat(MAX_BODY_BYTES + 1);
    const declared = await call(
      "/oauth/par",
      { method: "POST", headers: { "content-length": String(big.length) }, body: big },
      recorded,
    );
    expect(declared.status).toBe(413);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(big));
        controller.close();
      },
    });
    const streamed = await call(
      "/portal/accounts",
      {
        method: "POST",
        headers: { origin: ORIGIN },
        body: stream,
        duplex: "half",
      } as RequestInit,
      recorded,
    );
    expect(streamed.status).toBe(413);
    expect(recorded.requests).toHaveLength(0);
  });

  it("does not follow relay redirects", async () => {
    const recorded = environment();
    const env: Env = {
      ...recorded.env,
      RELAY: {
        fetch: async () => new Response(null, { status: 302, headers: { location: "/x" } }),
      },
    };
    const response = await worker.fetch(new Request(`${ORIGIN}/oauth/jwks`), env);
    expect(response.status).toBe(502);
  });
});

describe("portal worker write budget", () => {
  const post = (path: string, env: Env, ip = "198.51.100.1") =>
    worker.fetch(
      new Request(`${ORIGIN}${path}`, {
        method: "POST",
        headers: {
          origin: ORIGIN,
          "sec-fetch-site": "same-origin",
          "content-type": "application/json",
          "cf-connecting-ip": ip,
        },
        body: "{}",
      }),
      env,
    );

  it("spends one per-IP unit per unauthenticated write and refuses an exhausted or missing budget", async () => {
    const recorded = environment();
    const keys: string[] = [];
    const remaining = new Map([["198.51.100.1", 4]]);
    const env: Env = {
      ...recorded.env,
      WRITE_LIMIT: {
        limit: async ({ key }) => {
          keys.push(key);
          const left = remaining.get(key) ?? 1;
          remaining.set(key, left - 1);
          return { success: left > 0 };
        },
      },
    };
    for (const path of [
      "/oauth/clients",
      "/oauth/par",
      "/portal/signers",
      "/portal/sessions/challenge",
    ])
      expect((await post(path, env)).status).toBe(200);
    const limited = await post("/oauth/par", env);
    expect(limited.status).toBe(429);
    expect(limited.headers.get("access-control-allow-origin")).toBe("*");
    expect((await post("/portal/signers", env)).status).toBe(429);
    // Another address has its own budget.
    expect((await post("/portal/signers", env, "203.0.113.9")).status).toBe(200);
    // Session sign-in, token exchange and reads spend nothing.
    expect((await post("/portal/sessions", env)).status).toBe(200);
    expect((await post("/oauth/token", env)).status).toBe(200);
    expect((await worker.fetch(new Request(`${ORIGIN}/oauth/jwks`), env)).status).toBe(200);
    expect(keys).toEqual([
      "198.51.100.1",
      "198.51.100.1",
      "198.51.100.1",
      "198.51.100.1",
      "198.51.100.1",
      "198.51.100.1",
      "203.0.113.9",
    ]);
    // Refused writes never reach the relay.
    expect(recorded.requests).toHaveLength(8);

    const { WRITE_LIMIT: _limit, ...unbudgeted } = recorded.env;
    expect((await post("/oauth/clients", unbudgeted)).status).toBe(503);
    expect((await post("/portal/sessions/challenge", unbudgeted)).status).toBe(503);
  });
});

describe("portal worker chain reads", () => {
  function rpcEnvironment(budget = 100) {
    const upstream: { headers: Headers; body: unknown[] }[] = [];
    let remaining = budget;
    const env: Env = {
      ...environment().env,
      RPC_LIMIT: { limit: async () => ({ success: remaining-- > 0 }) },
      RPC_UPSTREAM_421614: "http://provider.invalid/secret-key",
    };
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      expect(url).toBe("http://provider.invalid/secret-key");
      const body = JSON.parse(String(init.body)) as { id: unknown }[];
      upstream.push({ headers: new Headers(init.headers), body });
      return Response.json(
        body.map((call) => ({ jsonrpc: "2.0", id: call.id, result: "0x1" })),
        { headers: { "set-cookie": "provider=1" } },
      );
    });
    return { env, upstream };
  }

  function rpc(env: Env, body: unknown, headers: Record<string, string> = {}) {
    return worker.fetch(
      new Request(`${ORIGIN}/rpc/421614`, {
        method: "POST",
        headers: {
          origin: ORIGIN,
          "sec-fetch-site": "same-origin",
          "content-type": "application/json",
          cookie: "oaath_portal_session=secret",
          ...headers,
        },
        body: JSON.stringify(body),
      }),
      env,
    );
  }

  const call = (method: string, params: unknown[] = [], id: number | string = 1) => ({
    jsonrpc: "2.0",
    id,
    method,
    params,
  });
  const account = `0x${"ab".repeat(20)}`;

  afterEach(() => vi.unstubAllGlobals());

  it("forwards allow-listed reads with no cookie or client header, and returns no cookie", async () => {
    const { env, upstream } = rpcEnvironment();
    const response = await rpc(env, call("eth_getCode", [account, "latest"]));
    expect(await response.json()).toEqual({ jsonrpc: "2.0", id: 1, result: "0x1" });
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(upstream).toHaveLength(1);
    expect([...(upstream[0]?.headers.keys() ?? [])]).toEqual(["content-type"]);
    const batch = await rpc(env, [
      call("eth_chainId", [], "a"),
      call("eth_call", [{ to: account, data: "0x12345678" }, "0x10"], "b"),
    ]);
    expect(await batch.json()).toEqual([
      { jsonrpc: "2.0", id: "a", result: "0x1" },
      { jsonrpc: "2.0", id: "b", result: "0x1" },
    ]);
  });

  it("refuses writes, unknown methods and unbounded reads without reaching the provider", async () => {
    const { env, upstream } = rpcEnvironment();
    const refused = [
      call("eth_sendRawTransaction", ["0x00"]),
      call("eth_call", [{ to: account, data: "0x", value: "0x1" }, "latest"]),
      call("eth_call", [{ to: account, data: "0x" }, "latest", {}]),
      call("eth_getBlockByNumber", ["latest", true]),
      call("eth_getLogs", [{ fromBlock: "0x0", toBlock: "0x10" }]),
      call("eth_getLogs", [{ address: account, fromBlock: "earliest", toBlock: "latest" }]),
    ];
    for (const entry of refused) {
      const body = (await (await rpc(env, entry)).json()) as { error: { code: number } };
      expect(body.error.code, entry.method).toBeLessThan(0);
    }
    const wide = (await (
      await rpc(
        env,
        call("eth_getLogs", [{ address: account, fromBlock: "0x0", toBlock: "0x989680" }]),
      )
    ).json()) as { error: { code: number; message: string } };
    // A range error readers split on, rather than a provider call.
    expect(wide.error).toEqual({
      code: -32005,
      message: "log block range exceeds the 10000000 limit",
    });
    expect(upstream).toHaveLength(0);
  });

  it("caps the batch, the body and the per-IP budget, and refuses other origins", async () => {
    const { env, upstream } = rpcEnvironment(3);
    const nine = Array.from({ length: 9 }, (_, index) => call("eth_chainId", [], index));
    expect((await rpc(env, nine)).status).toBe(413);
    expect((await rpc(env, call("eth_chainId", ["x".repeat(20_000)]))).status).toBe(413);
    expect((await rpc(env, call("eth_chainId"), { origin: "https://dapp.example" })).status).toBe(
      403,
    );
    expect((await rpc(env, call("eth_chainId"), { "sec-fetch-site": "cross-site" })).status).toBe(
      403,
    );
    expect(upstream).toHaveLength(0);
    // Three units of budget: a batch of two, then one, then exhausted.
    expect((await rpc(env, [call("eth_chainId", [], 1), call("eth_chainId", [], 2)])).status).toBe(
      200,
    );
    expect((await rpc(env, call("eth_chainId"))).status).toBe(200);
    expect((await rpc(env, call("eth_chainId"))).status).toBe(429);
    expect(upstream).toHaveLength(2);
    const { RPC_LIMIT: _limit, ...unbudgeted } = env;
    expect((await rpc(unbudgeted, call("eth_chainId"))).status).toBe(503);
  });

  it("answers a lost or malformed provider reply with an HTTP error, never a JSON-RPC result", async () => {
    const { env } = rpcEnvironment();
    vi.stubGlobal("fetch", async () => {
      throw new Error("timeout");
    });
    expect((await rpc(env, call("eth_chainId"))).status).toBe(504);
    vi.stubGlobal("fetch", async () => Response.json({ jsonrpc: "2.0", id: 9, result: "0x1" }));
    expect((await rpc(env, call("eth_chainId"))).status).toBe(502);
  });
});
