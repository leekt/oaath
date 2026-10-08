/**
 * The demo's chain and bundler proxies. They spend a shared chain RPC and our
 * own gas-paying relay on behalf of anyone who loads the demo, so every
 * request is bounded:
 *
 * - an allow-listed method set per role; at most `MAX_BATCH` calls per request;
 * - body and response size caps;
 * - each call spends one unit of a per-IP rate budget (`RPC_LIMIT`); a send
 *   (`eth_sendUserOperation`) also spends `SEND_LIMIT`. A missing binding refuses;
 * - one upstream attempt, capped in time, with no fallback and no retry. A
 *   send without an answer gets a bare 504: the SDK keeps it uncertain and only
 *   observes it, and this proxy never repeats it;
 * - the relay pays every operation's gas, so it simulates and sends only the
 *   demo's own call (`DEMO_TARGET`, zero value, `DEMO_SELECTOR`) through
 *   EntryPoint 0.9, decoded from the operation's Kernel callData.
 *
 * The bundler is bundle_rs (zerodevapp/bundle_rs) in its default fast mode:
 * operations carry zero fees and its executor pays chain gas, because the
 * hosted paymasters (Pimlico, ZeroDev, Alchemy) do not support EntryPoint 0.9,
 * which Kernel v4 accounts use. It listens only on the VM's loopback, so the
 * Worker reaches it through the `BUNDLER` Workers VPC service binding.
 *
 * Only `content-type` reaches a provider, plus the bundler's own `x-api-key`
 * from the `BUNDLER_API_KEY` secret: a client's headers and any body field
 * outside JSON-RPC (such as `apiKey`) are dropped. Upstream URLs are never logged or
 * returned; provider answers pass through unchanged only when they are JSON-RPC.
 *
 * @author taek <leekt216@gmail.com>
 */

export interface RateLimit {
  limit(input: { key: string }): Promise<{ success: boolean }>;
}

export interface ProxyEnv {
  /** Per-IP budget: every proxied call. */
  readonly RPC_LIMIT?: RateLimit;
  /** Per-IP budget: `eth_sendUserOperation`. */
  readonly SEND_LIMIT?: RateLimit;
  /** Arbitrum Sepolia JSON-RPC endpoint. */
  readonly CHAIN_RPC_URL: string;
  /** Workers VPC service: bundle_rs on the VM's loopback. Unset: the bundler route answers 503. */
  readonly BUNDLER?: { fetch(request: Request): Promise<Response> };
  /** Secret: bundle_rs client key, sent only to the bundler. Unset: forwarded without one. */
  readonly BUNDLER_API_KEY?: string;
}

/** True when the relay that pays every operation's gas is bound. */
export function relayConfigured(env: ProxyEnv): boolean {
  return Boolean(env.BUNDLER);
}

export type Role = "chain" | "bundler";

export const DEMO_CHAIN_ID = 421_614;
export const DEMO_TARGET = "0x000000000000000000000000000000000000dead";
export const DEMO_SELECTOR = "0x12345678";
export const ENTRY_POINT_V09 = "0x433709009b8330fda32311df1c2afa402ed8d009";
export const MAX_BATCH = 8;
export const MAX_BODY_BYTES = 64 * 1024;
export const MAX_RESPONSE_BYTES = 1024 * 1024;
export const TIMEOUT_MS = 15_000;

/** Exactly the methods OAAth's Cetane chain ports send, plus the demo's own reads. */
export const METHODS: Readonly<Record<Role, ReadonlySet<string>>> = {
  chain: new Set([
    "eth_chainId",
    "eth_blockNumber",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_call",
    "eth_gasPrice",
    "eth_maxPriorityFeePerGas",
    "eth_feeHistory",
    "eth_getBlockByNumber",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_getBalance",
  ]),
  bundler: new Set([
    "eth_chainId",
    "eth_supportedEntryPoints",
    "eth_estimateUserOperationGas",
    "eth_sendUserOperation",
    "eth_getUserOperationReceipt",
  ]),
};

/** Methods the relay pays for or simulates: only the demo's own call. */
const RELAY_PAID = new Set(["eth_sendUserOperation", "eth_estimateUserOperationGas"]);

type Call = { jsonrpc: "2.0"; id: string | number | null; method: string; params: unknown[] };

const EXECUTE = "e9ae5c53";
const EXECUTE_USER_OP = "8dd7712f";

/**
 * True when Kernel callData is exactly one zero-value `DEMO_SELECTOR` call to
 * `DEMO_TARGET`: `[executeUserOp ‖] execute(mode, target ‖ value ‖ data)` with
 * a single-call mode.
 */
export function isDemoCall(callData: unknown): boolean {
  if (typeof callData !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/u.test(callData)) return false;
  let hex = callData.slice(2).toLowerCase();
  if (hex.startsWith(EXECUTE_USER_OP)) hex = hex.slice(8);
  if (!hex.startsWith(EXECUTE)) return false;
  const word = (index: number) => hex.slice(8 + index * 64, 8 + (index + 1) * 64);
  // Call type 0x00 (single); exec type 0x00 (revert on failure).
  if (!word(0).startsWith("0000")) return false;
  if (BigInt(`0x${word(1) || "0"}`) !== 64n) return false;
  const length = Number(BigInt(`0x${word(2) || "0"}`));
  const execution = hex.slice(8 + 3 * 64, 8 + 3 * 64 + length * 2);
  const expected = `${DEMO_TARGET.slice(2)}${"0".repeat(64)}${DEMO_SELECTOR.slice(2)}`;
  return execution === expected && length * 2 === expected.length;
}

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

function refused(call: Call, message: string): Response {
  return reply(200, { jsonrpc: "2.0", id: call.id, error: { code: -32005, message } });
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

async function spend(limiter: RateLimit | undefined, key: string): Promise<boolean> {
  return limiter ? (await limiter.limit({ key })).success : false;
}

/** The relay-paid call's refusal, or null: only the demo's own call through EntryPoint 0.9. */
function relayRefusal(call: Call): string | null {
  const [operation, entryPoint] = call.params;
  // A third (state override) parameter would simulate against another state.
  if (call.params.length !== 2) return "invalid bundler params";
  if (String(entryPoint).toLowerCase() !== ENTRY_POINT_V09) return "unsupported EntryPoint";
  if (!isDemoCall((operation as { callData?: unknown } | null)?.callData))
    return "the demo relays only its own call";
  return null;
}

/** Serves one same-origin proxy request; the caller has checked the path and origin. */
export async function proxy(role: Role, request: Request, env: ProxyEnv): Promise<Response> {
  if (request.method !== "POST") return reply(405, { error: "Unsupported method" });
  if (role === "bundler" && !relayConfigured(env))
    return reply(503, { error: "The bundler is not configured" });
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
    if (!METHODS[role].has(call.method)) return refused(call, "method not allowed by the demo");
    if (RELAY_PAID.has(call.method)) {
      const refusal = relayRefusal(call);
      if (refusal) return refused(call, refusal);
    }
  }

  // Every call spends budget before anything reaches a provider.
  const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
  const tooMany = () => reply(429, { error: "Too many requests. Try again in a minute." });
  for (const call of captured) {
    if (!(await spend(env.RPC_LIMIT, ip))) return tooMany();
    if (call.method === "eth_sendUserOperation" && !(await spend(env.SEND_LIMIT, ip)))
      return tooMany();
  }

  const forwarded = new Request(
    // The VPC binding pins the bundler's destination; this URL only sets its path.
    role === "chain" ? env.CHAIN_RPC_URL : "http://bundler.internal/",
    {
      method: "POST",
      headers:
        role === "bundler" && env.BUNDLER_API_KEY
          ? { "content-type": "application/json", "x-api-key": env.BUNDLER_API_KEY }
          : { "content-type": "application/json" },
      body: JSON.stringify(batch ? captured : captured[0]),
      // Workers accepts only "follow" or "manual"; a 3xx is not ok and is refused below.
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    },
  );
  let upstream: Response;
  try {
    upstream = await (role === "bundler"
      ? (env.BUNDLER as NonNullable<ProxyEnv["BUNDLER"]>).fetch(forwarded)
      : fetch(forwarded));
  } catch {
    // No answer is not a refusal: a send may still land. A bare 504 keeps it
    // uncertain in the SDK, which observes and never resends.
    return new Response(null, { status: 504, headers: { "Cache-Control": "no-store" } });
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
