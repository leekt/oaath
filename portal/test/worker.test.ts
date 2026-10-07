import { describe, expect, it } from "vitest";
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
    },
  };
}

function call(path: string, init: RequestInit = {}, recorded = environment()) {
  return worker.fetch(new Request(`${ORIGIN}${path}`, init), recorded.env);
}

describe("portal worker", () => {
  it("serves the SPA document for / and /authorize, and hashed assets", async () => {
    for (const path of ["/", "/authorize?client_id=a&request_uri=b"]) {
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
