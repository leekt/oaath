/**
 * The app's read-only chain proxy: the page reads token balances through it.
 * It spends a shared chain RPC on behalf of anyone who loads the page, so
 * every request is bounded:
 *
 * - an allow-listed read-only method set; at most `MAX_BATCH` calls per request;
 * - body and response size caps;
 * - each call spends one unit of the per-IP `RPC_LIMIT` budget; a missing
 *   binding refuses;
 * - one upstream attempt, capped in time, with no fallback and no retry.
 *
 * The app never sends a transaction or a UserOperation: the automation service
 * submits every plan operation through its own bundler.
 *
 * Only `content-type` reaches the provider. The upstream URL is never logged or
 * returned; answers pass through unchanged only when they are JSON-RPC.
 *
 * @author taek <leekt216@gmail.com>
 */

export interface RateLimit {
  limit(input: { key: string }): Promise<{ success: boolean }>;
}

export interface ProxyEnv {
  /** Per-IP budget: every proxied call. */
  readonly RPC_LIMIT?: RateLimit;
  /** Arbitrum Sepolia JSON-RPC endpoint. */
  readonly CHAIN_RPC_URL: string;
}

export const DCA_CHAIN_ID = 421_614;
export const MAX_BATCH = 8;
export const MAX_BODY_BYTES = 16 * 1024;
export const MAX_RESPONSE_BYTES = 256 * 1024;
export const TIMEOUT_MS = 15_000;

/** Read-only methods the page uses. */
export const METHODS: ReadonlySet<string> = new Set(["eth_chainId", "eth_blockNumber", "eth_call"]);

type Call = { jsonrpc: "2.0"; id: string | number | null; method: string; params: unknown[] };

function captureCall(value: unknown): Call | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const { jsonrpc, id, method, params = [] } = value as Record<string, unknown>;
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
    if (size > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(chunk.value);
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}

/** Serves one same-origin chain request; the caller has checked the path and origin. */
export async function proxy(request: Request, env: ProxyEnv): Promise<Response> {
  if (request.method !== "POST") return reply(405, { error: "Unsupported method" });
  if (Number(request.headers.get("content-length") ?? "0") > MAX_BODY_BYTES)
    return reply(413, { error: "Request too large" });
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > MAX_BODY_BYTES)
    return reply(413, { error: "Request too large" });
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return reply(400, { error: "Invalid JSON-RPC request" });
  }
  const batch = Array.isArray(parsed);
  const entries = batch ? (parsed as unknown[]) : [parsed];
  if (entries.length < 1 || entries.length > MAX_BATCH)
    return reply(413, { error: `At most ${MAX_BATCH} calls per request` });
  const calls = entries.map(captureCall);
  if (calls.some((call) => call === null)) return reply(400, { error: "Invalid JSON-RPC request" });
  const captured = calls as Call[];
  // A refused call refuses the whole request: a batch is forwarded whole or not at all.
  for (const call of captured) {
    if (!METHODS.has(call.method))
      return reply(200, {
        jsonrpc: "2.0",
        id: call.id,
        error: { code: -32005, message: "method not allowed by the app" },
      });
  }

  // Every call spends budget before anything reaches the provider.
  const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
  for (const _ of captured) {
    if (!env.RPC_LIMIT || !(await env.RPC_LIMIT.limit({ key: ip }).then((r) => r.success)))
      return reply(429, { error: "Too many requests. Try again in a minute." });
  }

  let upstream: Response;
  try {
    upstream = await fetch(
      new Request(env.CHAIN_RPC_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(batch ? captured : captured[0]),
        // Workers accepts only "follow" or "manual"; a 3xx is not ok and is refused below.
        redirect: "manual",
        signal: AbortSignal.timeout(TIMEOUT_MS),
      }),
    );
  } catch {
    return reply(504, { error: "The provider did not answer" });
  }
  const body = upstream.ok ? await boundedText(upstream) : null;
  let answer: unknown = null;
  try {
    answer = body === null ? null : JSON.parse(body);
  } catch {}
  const answers = Array.isArray(answer) ? answer : [answer];
  if (
    answer === null ||
    Array.isArray(answer) !== batch ||
    answers.some((entry) => typeof entry !== "object" || entry === null)
  )
    return reply(502, { error: "The provider's answer was unusable" });
  return reply(200, answer);
}
