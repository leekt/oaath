export interface RpcReader {
  request(method: string, params?: readonly unknown[]): Promise<unknown>;
}

/** One explicit endpoint, no fallback or retries, bounded time and request count. */
export class Rpc implements RpcReader {
  #requests = 0;
  readonly #deadline: number;
  readonly #maxRequests: number;
  readonly #fetch: typeof fetch;

  constructor(
    readonly url: string,
    options: { maxRequests?: number; durationMs?: number; fetch?: typeof fetch } = {},
  ) {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("rpc_url_invalid");
    this.#maxRequests = options.maxRequests ?? 32;
    this.#deadline = Date.now() + (options.durationMs ?? 60_000);
    this.#fetch = options.fetch ?? fetch;
  }

  async request(method: string, params: readonly unknown[] = []): Promise<unknown> {
    if (this.#requests >= this.#maxRequests) throw new Error("rpc_budget_exhausted");
    const remaining = this.#deadline - Date.now();
    if (remaining <= 0) throw new Error("rpc_deadline_exhausted");
    const id = ++this.#requests;
    let payload: unknown;
    try {
      const response = await this.#fetch(this.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
        signal: AbortSignal.timeout(Math.min(5_000, remaining)),
        redirect: "error",
      });
      if (!response.ok) throw new Error();
      payload = await response.json();
    } catch {
      throw new Error("rpc_unavailable");
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload))
      throw new Error("rpc_invalid_response");
    const record = payload as Record<string, unknown>;
    if (record.jsonrpc !== "2.0" || record.id !== id || !("result" in record) || "error" in record)
      throw new Error("rpc_invalid_response");
    return record.result;
  }
}
