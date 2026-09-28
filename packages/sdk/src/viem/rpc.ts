import { captureDenseArray, captureRecord } from "@oaath/protocol";

export type OaathRpcErrorCode =
  | "oaath_rpc_config_invalid"
  | "oaath_rpc_unavailable"
  | "oaath_rpc_rejected"
  | "oaath_rpc_wrong_chain"
  | "oaath_rpc_evidence_invalid"
  | "oaath_rpc_budget_exhausted"
  | "oaath_rpc_concurrency_exceeded";

/** Contains no URL, provider prose, request body, signature, or raw error. */
export class OaathRpcError extends Error {
  constructor(
    readonly code: OaathRpcErrorCode,
    readonly rpcCode: number | null = null,
  ) {
    super(code);
    this.name = "OaathRpcError";
  }
}

const transient = new WeakSet<OaathRpcError>();
function unavailable(): OaathRpcError {
  const error = new OaathRpcError("oaath_rpc_unavailable");
  transient.add(error);
  return error;
}
export function invalid(): never {
  throw new OaathRpcError("oaath_rpc_config_invalid");
}
export function evidence(): never {
  throw new OaathRpcError("oaath_rpc_evidence_invalid");
}
export function record(
  value: unknown,
  keys?: readonly string[],
): Readonly<Record<string, unknown>> {
  const result = captureRecord(value, "RPC configuration", new WeakSet(), invalid);
  if (keys && Object.keys(result).some((key) => !keys.includes(key))) invalid();
  return result;
}
export function integer(value: unknown, fallback: number, maximum: number, minimum = 1): number {
  if (value === undefined) return fallback;
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  )
    invalid();
  return value;
}
export function url(value: unknown): string {
  if (typeof value !== "string") return invalid();
  try {
    const parsed = new URL(value);
    if (
      !["http:", "https:"].includes(parsed.protocol) ||
      parsed.hash ||
      parsed.username ||
      parsed.password
    )
      invalid();
    return parsed.href;
  } catch {
    return invalid();
  }
}
export function urls(value: unknown): readonly string[] {
  const entries = captureDenseArray(value, "public RPC URLs", new WeakSet(), invalid);
  if (entries.length === 0 || entries.length > 16) invalid();
  return Object.freeze(entries.map(url));
}
export function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return evidence();
  return value as Record<string, unknown>;
}
export function quantity(value: unknown): bigint {
  if (typeof value !== "string" || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/iu.test(value)) return evidence();
  return BigInt(value);
}

export interface ViemChainPortOptions {
  readonly retry?: Readonly<{ attempts: number; delayMs?: number }>;
  readonly timeoutMs?: number;
  /** Hard instance-lifetime budget across every chain, including chain checks and retries. */
  readonly maxRequests?: number;
  /** Excess concurrent requests fail immediately; there is no unbounded queue. */
  readonly maxConcurrency?: number;
  readonly fetch?: (request: Request) => Promise<Response>;
}

export type RpcRequest = (
  method: string,
  params?: readonly unknown[],
  retry?: boolean,
) => Promise<unknown>;

/** One budget and concurrency owner shared by all pools in one configuration. */
export function rpcOwner(input: ViemChainPortOptions) {
  const options = record(input, ["retry", "timeoutMs", "maxRequests", "maxConcurrency", "fetch"]);
  const retry = options.retry === undefined ? {} : record(options.retry, ["attempts", "delayMs"]);
  const attempts = integer(retry.attempts, 3, 5);
  const delayMs = integer(retry.delayMs, 100, 5_000, 0);
  const timeoutMs = integer(options.timeoutMs, 10_000, 60_000);
  const maxRequests = integer(options.maxRequests, 1_000, 1_000_000);
  const maxConcurrency = integer(options.maxConcurrency, 4, 32);
  if (options.fetch !== undefined && typeof options.fetch !== "function") invalid();
  const fetcher = (options.fetch ?? globalThis.fetch) as (request: Request) => Promise<Response>;
  if (typeof fetcher !== "function") invalid();
  let used = 0;
  let active = 0;

  async function once(endpoint: string, method: string, params: readonly unknown[]) {
    if (used >= maxRequests) throw new OaathRpcError("oaath_rpc_budget_exhausted");
    if (active >= maxConcurrency) throw new OaathRpcError("oaath_rpc_concurrency_exceeded");
    const id = ++used;
    active += 1;
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        (async () => {
          const response = await fetcher(
            new Request(endpoint, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
              signal: abort.signal,
              redirect: "error",
              credentials: "omit",
            }),
          );
          if (response.status === 429 || response.status >= 500) {
            await response.body?.cancel();
            throw unavailable();
          }
          if (!response.ok) {
            await response.body?.cancel();
            throw new OaathRpcError("oaath_rpc_rejected");
          }
          const reader = response.body?.getReader();
          if (!reader) throw unavailable();
          const decoder = new TextDecoder();
          let size = 0;
          let text = "";
          for (;;) {
            const chunk = await reader.read();
            if (chunk.done) break;
            size += chunk.value.length;
            if (size > 2 * 1024 * 1024) {
              await reader.cancel();
              throw unavailable();
            }
            text += decoder.decode(chunk.value, { stream: true });
          }
          text += decoder.decode();
          let result: Record<string, unknown>;
          try {
            result = object(JSON.parse(text));
          } catch {
            throw unavailable();
          }
          if (
            result.jsonrpc !== "2.0" ||
            result.id !== id ||
            Object.hasOwn(result, "result") === Object.hasOwn(result, "error")
          )
            throw unavailable();
          if (Object.hasOwn(result, "error")) {
            const error = object(result.error);
            if (typeof error.code !== "number" || !Number.isSafeInteger(error.code))
              throw unavailable();
            const failure = new OaathRpcError("oaath_rpc_rejected", error.code);
            if ([-32005, -32016, 429].includes(error.code)) transient.add(failure);
            throw failure;
          }
          return result.result;
        })(),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            abort.abort();
            reject(unavailable());
          }, timeoutMs);
        }),
      ]);
    } catch (error) {
      if (error instanceof OaathRpcError) throw error;
      throw unavailable();
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      active -= 1;
    }
  }

  return Object.freeze({
    pool(
      endpoints: readonly string[],
      chainId: number,
      methods: readonly string[],
      verifyChain = true,
    ): RpcRequest {
      const checked = new Set<string>();
      let preferred = 0;
      return async (method, params = [], retry = true) => {
        if (!methods.includes(method)) return invalid();
        const start = preferred;
        for (let attempt = 0; ; attempt += 1) {
          const index = (start + attempt) % endpoints.length;
          const endpoint = endpoints[index];
          if (!endpoint) return invalid();
          try {
            if (verifyChain && method !== "eth_chainId" && !checked.has(endpoint)) {
              if (quantity(await once(endpoint, "eth_chainId", [])) !== BigInt(chainId))
                throw new OaathRpcError("oaath_rpc_wrong_chain");
              checked.add(endpoint);
            }
            const result = await once(endpoint, method, params);
            if (verifyChain && method === "eth_chainId" && quantity(result) !== BigInt(chainId))
              throw new OaathRpcError("oaath_rpc_wrong_chain");
            if (verifyChain && method === "eth_chainId") checked.add(endpoint);
            preferred = index;
            return result;
          } catch (error) {
            if (
              !retry ||
              attempt + 1 >= attempts ||
              !(error instanceof OaathRpcError) ||
              (!transient.has(error) && error.code !== "oaath_rpc_wrong_chain")
            )
              throw error;
            checked.delete(endpoint);
            if (delayMs > 0) await new Promise((resolve) => setTimeout(resolve, delayMs));
          }
        }
      };
    },
  });
}
