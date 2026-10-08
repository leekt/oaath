/**
 * The `oaath-automation.taek.tech` edge for OAAth's hosted automation service.
 *
 * Forwards every request once, unchanged, to the service on the VM through
 * the Workers VPC service `oaath-automation` (127.0.0.1:4321). The service owns
 * authentication, CORS and its own RPC budgets; this Worker only adds a per-IP
 * request budget. Self-hosters expose the service however they like.
 *
 * @author taek <leekt216@gmail.com>
 */

interface Env {
  readonly SERVICE: { fetch(request: Request): Promise<Response> };
  readonly LIMIT: { limit(options: { key: string }): Promise<{ success: boolean }> };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const client = request.headers.get("cf-connecting-ip") ?? "unknown";
    if (!(await env.LIMIT.limit({ key: client })).success)
      return Response.json({ error: { code: "rate_limited" } }, { status: 429 });
    const url = new URL(request.url);
    const reading = request.method === "GET" || request.method === "HEAD";
    // The binding pins the destination; this URL only sets the Host the service sees.
    return env.SERVICE.fetch(
      new Request(`http://oaath-automation.taek.tech${url.pathname}${url.search}`, {
        method: request.method,
        headers: request.headers,
        body: reading ? null : await request.arrayBuffer(),
        redirect: "manual",
        signal: AbortSignal.timeout(30_000),
      }),
    );
  },
};
