/**
 * `POST /rpc/421614`: the portal's read-only Arbitrum Sepolia JSON-RPC proxy,
 * for reading an existing account before it is imported.
 *
 * It is a shared provider spent on behalf of anyone who can load the portal, so
 * every request is bounded:
 * - same-origin portal pages only;
 * - one allow-listed read method per call, at most `RPC_MAX_BATCH` calls per request;
 * - `eth_getLogs` needs one address and numbered blocks spanning at most
 *   `RPC_MAX_LOG_BLOCKS`; a wider range gets a JSON-RPC range error, which
 *   readers split, without reaching the provider;
 * - each call spends one unit of the per-IP `RPC_LIMIT` rate budget, and an
 *   exhausted or missing budget refuses the whole request;
 * - one upstream attempt, capped in time and response size, with no fallback.
 *
 * Only `content-type` reaches the provider: never a cookie or a client header.
 * The upstream URL can carry a credential, so it is never logged or returned.
 *
 * @author taek <leekt216@gmail.com>
 */

export interface RateLimit {
  limit(input: { key: string }): Promise<{ success: boolean }>;
}

export interface RpcEnv {
  /** Workers rate-limiting binding: the per-IP request budget. */
  readonly RPC_LIMIT?: RateLimit;
  /** Arbitrum Sepolia JSON-RPC URL; may carry a credential. Defaults to the public endpoint. */
  readonly RPC_UPSTREAM_421614?: string;
}

export const RPC_CHAIN_ID = 421_614;
export const RPC_DEFAULT_UPSTREAM = "https://sepolia-rollup.arbitrum.io/rpc";
export const RPC_MAX_BATCH = 8;
export const RPC_MAX_BODY_BYTES = 16 * 1024;
export const RPC_MAX_RESPONSE_BYTES = 1024 * 1024;
export const RPC_MAX_LOG_BLOCKS = 10_000_000n;
export const RPC_TIMEOUT_MS = 10_000;

const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]{0,15})$/u;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const HEX = /^0x(?:[0-9a-fA-F]{2})*$/u;
const BLOCK_TAGS = new Set(["latest", "safe", "finalized", "earliest"]);

type Call = { jsonrpc: "2.0"; id: string | number | null; method: string; params: unknown[] };
type Refusal = { readonly code: number; readonly message: string };

function blockOf(value: unknown): boolean {
  return typeof value === "string" && (QUANTITY.test(value) || BLOCK_TAGS.has(value));
}

function plainObject(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).every((key) => keys.includes(key))
  );
}

/** Null when the call may reach the provider; otherwise the JSON-RPC error it gets instead. */
function refusal(method: string, params: unknown[]): Refusal | null {
  const invalid = { code: -32602, message: "Invalid params" };
  switch (method) {
    case "eth_chainId":
    case "eth_blockNumber":
      return params.length === 0 ? null : invalid;
    case "eth_getCode":
      return params.length === 2 && ADDRESS.test(String(params[0])) && blockOf(params[1])
        ? null
        : invalid;
    case "eth_getStorageAt":
      return params.length === 3 &&
        ADDRESS.test(String(params[0])) &&
        HEX.test(String(params[1])) &&
        blockOf(params[2])
        ? null
        : invalid;
    case "eth_call": {
      const [call, block] = params;
      // No state overrides, value, or gas: a plain read at one block.
      return params.length === 2 &&
        plainObject(call, ["to", "data", "from"]) &&
        ADDRESS.test(String(call.to)) &&
        HEX.test(String(call.data)) &&
        (call.from === undefined || ADDRESS.test(String(call.from))) &&
        blockOf(block)
        ? null
        : invalid;
    }
    case "eth_getBlockByNumber":
      return params.length === 2 && blockOf(params[0]) && params[1] === false ? null : invalid;
    case "eth_getLogs": {
      const [filter] = params;
      if (
        params.length !== 1 ||
        !plainObject(filter, ["address", "topics", "fromBlock", "toBlock"]) ||
        !ADDRESS.test(String(filter.address)) ||
        typeof filter.fromBlock !== "string" ||
        typeof filter.toBlock !== "string" ||
        !QUANTITY.test(filter.fromBlock) ||
        !QUANTITY.test(filter.toBlock) ||
        (filter.topics !== undefined && !Array.isArray(filter.topics))
      )
        return invalid;
      const span = BigInt(filter.toBlock) - BigInt(filter.fromBlock) + 1n;
      if (span < 1n) return invalid;
      return span > RPC_MAX_LOG_BLOCKS
        ? { code: -32005, message: `log block range exceeds the ${RPC_MAX_LOG_BLOCKS} limit` }
        : null;
    }
    default:
      return { code: -32601, message: "Method not allowed" };
  }
}

function captureCall(value: unknown): Call | null {
  if (!plainObject(value, ["jsonrpc", "id", "method", "params"])) return null;
  const { jsonrpc, id, method, params = [] } = value;
  if (
    jsonrpc !== "2.0" ||
    typeof method !== "string" ||
    !Array.isArray(params) ||
    !(id === null || typeof id === "string" || (typeof id === "number" && Number.isFinite(id)))
  )
    return null;
  return { jsonrpc, id, method, params };
}

function reply(status: number, body: unknown): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

async function boundedText(response: Response): Promise<string | null> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const chunk = await reader.read();
    if (chunk.done) break;
    size += chunk.value.byteLength;
    if (size > RPC_MAX_RESPONSE_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(chunk.value);
  }
  return new TextDecoder().decode(
    chunks.reduce((all, chunk) => {
      const next = new Uint8Array(all.byteLength + chunk.byteLength);
      next.set(all);
      next.set(chunk, all.byteLength);
      return next;
    }, new Uint8Array()),
  );
}

/** Serves one same-origin proxy request; the caller has checked the path and origin. */
export async function proxyRpc(request: Request, env: RpcEnv): Promise<Response> {
  if (request.method !== "POST") return reply(405, { error: "Unsupported method" });
  if (Number(request.headers.get("content-length") ?? "0") > RPC_MAX_BODY_BYTES)
    return reply(413, { error: "Request too large" });
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > RPC_MAX_BODY_BYTES)
    return reply(413, { error: "Request too large" });
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return reply(400, { error: "Invalid JSON-RPC request" });
  }
  const batch = Array.isArray(parsed);
  const entries = batch ? (parsed as unknown[]) : [parsed];
  if (entries.length < 1 || entries.length > RPC_MAX_BATCH)
    return reply(413, { error: `At most ${RPC_MAX_BATCH} calls per request` });
  const calls = entries.map(captureCall);
  if (
    calls.some((call) => call === null) ||
    new Set(calls.map((call) => JSON.stringify(call?.id))).size !== calls.length
  )
    return reply(400, { error: "Invalid JSON-RPC request" });

  // Every call spends budget, refused or not, before anything reaches the provider.
  const limiter = env.RPC_LIMIT;
  if (!limiter) return reply(503, { error: "Chain reads are not configured" });
  const key = request.headers.get("cf-connecting-ip") ?? "unknown";
  for (const _ of calls) {
    if (!(await limiter.limit({ key })).success)
      return reply(429, { error: "Too many chain reads. Try again in a minute." });
  }

  const answers = new Map<number, unknown>();
  const forwarded: Call[] = [];
  const positions: number[] = [];
  (calls as Call[]).forEach((call, index) => {
    const refused = refusal(call.method, call.params);
    if (refused) answers.set(index, { jsonrpc: "2.0", id: call.id, error: refused });
    else {
      forwarded.push(call);
      positions.push(index);
    }
  });

  if (forwarded.length > 0) {
    let upstream: Response;
    try {
      upstream = await fetch(env.RPC_UPSTREAM_421614 ?? RPC_DEFAULT_UPSTREAM, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(forwarded),
        redirect: "error",
        signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
      });
    } catch {
      return reply(504, { error: "The chain provider did not answer" });
    }
    const body = upstream.ok ? await boundedText(upstream) : null;
    let results: unknown;
    try {
      results = body === null ? null : JSON.parse(body);
    } catch {
      results = null;
    }
    // A batch answer is matched by id; anything else is not an answer.
    if (!Array.isArray(results) || results.length !== forwarded.length)
      return reply(502, { error: "The chain provider's answer was unusable" });
    const byId = new Map(
      (results as { id?: unknown }[]).map((result) => [JSON.stringify(result?.id), result]),
    );
    for (const [offset, call] of forwarded.entries()) {
      const result = byId.get(JSON.stringify(call.id));
      if (result === undefined)
        return reply(502, { error: "The chain provider's answer was unusable" });
      answers.set(positions[offset] as number, result);
    }
  }
  const ordered = calls.map((_, index) => answers.get(index));
  return reply(200, batch ? ordered : ordered[0]);
}
