/**
 * Serves the Grant demo on loopback and is its only path to a chain.
 *
 * The page never sees an RPC or bundler URL: it calls `/rpc/chain` and
 * `/rpc/bundler` on this origin, and this server forwards each JSON-RPC call
 * to exactly one configured endpoint. That makes every live-network rule
 * enforceable in one place:
 *
 * - one endpoint per role, no fallback, an allow-listed method set;
 * - a hard request budget for the whole run (batch entries count singly),
 *   a concurrency cap and a per-request timeout; nothing here retries;
 * - a wall-clock cap after which nothing more is forwarded;
 * - once the budget or the time cap is spent, forwarding stops for good, so a
 *   timed-out or refused send is never repeated by this process;
 * - logs name the role, method and count only, never URLs, params or bodies.
 *
 * Shared by `run.mjs` and the portal's end-to-end rehearsal.
 *
 * @author taek <leekt216@gmail.com>
 */
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const LOGIN = fileURLToPath(new URL("../oauth-login/", import.meta.url));

/** Exactly the methods OAAth's Cetane chain ports send, plus the demo's balance read. */
const METHODS = {
  chain: new Set([
    "eth_chainId",
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
const MAX_BODY_BYTES = 64 * 1024;

/** `https://host/path?key` → `https://host`: what may be printed about an endpoint. */
export function redact(url) {
  return new URL(url).origin;
}

export async function startGrantDemo({
  issuer,
  clientId = null,
  chainId,
  rpcUrl,
  bundlerUrl,
  /** Transaction page prefix, for example `https://sepolia.arbiscan.io/tx/`, or null. */
  explorerTxUrl = null,
  maxRequests,
  maxConcurrency = 4,
  requestTimeoutMs = 15_000,
  timeCapMs,
  /** How often the page observes a sent operation. */
  pollIntervalMs = 30_000,
  /** The harmless covered call: a zero-value call with this selector to this target. */
  target,
  selector,
  port = 0,
  host = "localhost",
  log = (line) => console.log(line),
}) {
  const endpoints = { chain: rpcUrl, bundler: bundlerUrl };
  const deadline = Date.now() + timeCapMs;
  let used = 0;
  let active = 0;
  let stopped = null;
  const stop = (reason) => {
    if (stopped) return;
    stopped = reason;
    log(
      `[demo] ${reason}: nothing more is forwarded. Restart to observe again; nothing is resent.`,
    );
  };

  const bundles = await build({
    entryPoints: [`${HERE}app.js`, `${LOGIN}callback.js`],
    bundle: true,
    format: "esm",
    platform: "browser",
    // Inside this repository the SDK resolves to its sources; an adopter
    // installs the built package and needs no condition.
    conditions: ["oaath-source"],
    outdir: "/",
    // The two entries live in different directories; serve both at the root.
    entryNames: "[name]",
    write: false,
    logLevel: "silent",
  });
  const config = {
    issuer,
    clientId,
    chainId,
    explorerTxUrl,
    maxRequests,
    target,
    selector,
    pollIntervalMs,
    maxPolls: Math.max(1, Math.floor(timeCapMs / pollIntervalMs)),
  };
  const files = new Map([
    ["/", { type: "text/html", body: await readFile(`${HERE}index.html`) }],
    ["/callback", { type: "text/html", body: await readFile(`${LOGIN}callback.html`) }],
    ["/config.json", { type: "application/json", body: JSON.stringify(config) }],
    ...bundles.outputFiles.map((file) => [
      file.path,
      { type: "text/javascript", body: file.contents },
    ]),
  ]);

  function refuse(response, id, message) {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify({ jsonrpc: "2.0", id: id ?? null, error: { code: -32005, message } }),
    );
  }

  async function forward(role, request, response) {
    const chunks = [];
    let size = 0;
    for await (const chunk of request) {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) return refuse(response, null, "request too large");
      chunks.push(chunk);
    }
    let body;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      return refuse(response, null, "invalid JSON-RPC request");
    }
    const calls = Array.isArray(body) ? body : [body];
    const id = Array.isArray(body) ? null : body?.id;
    if (calls.length === 0 || calls.some((call) => !METHODS[role].has(call?.method)))
      return refuse(response, id, "method not allowed by the demo");
    if (!stopped && Date.now() > deadline) stop("time cap reached");
    if (!stopped && used + calls.length > maxRequests) stop("request budget exhausted");
    if (stopped) return refuse(response, id, `demo stopped: ${stopped}`);
    if (active >= maxConcurrency) return refuse(response, id, "demo concurrency limit");
    used += calls.length;
    active += 1;
    log(`[rpc] ${role} ${calls.map((call) => call.method).join(",")} (${used}/${maxRequests})`);
    try {
      const upstream = await fetch(endpoints[role], {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(requestTimeoutMs),
        redirect: "error",
      });
      const text = await upstream.text();
      response.writeHead(upstream.ok ? 200 : 502, { "content-type": "application/json" });
      response.end(text);
    } catch {
      // No answer is not a refusal: a send may still land. A transport failure,
      // never a JSON-RPC error, keeps it uncertain in the SDK, which observes
      // and never resends; this proxy never repeats it either.
      log(`[rpc] ${role} request did not complete; it is not retried`);
      response.writeHead(504).end();
    } finally {
      active -= 1;
    }
  }

  const server = createServer((request, response) => {
    const path = new URL(request.url ?? "/", "http://localhost").pathname;
    if (request.method === "POST" && path === "/rpc/chain")
      return void forward("chain", request, response);
    if (request.method === "POST" && path === "/rpc/bundler")
      return void forward("bundler", request, response);
    const file = files.get(path);
    if (request.method !== "GET" || !file) return response.writeHead(404).end();
    response.writeHead(200, { "content-type": file.type, "cache-control": "no-store" });
    response.end(file.body);
  });
  await new Promise((resolve) =>
    server.listen(port, host === "localhost" ? "127.0.0.1" : host, resolve),
  );
  const timer = setTimeout(() => stop("time cap reached"), timeCapMs);
  timer.unref();
  const address = server.address();
  return {
    url: `http://${host}:${address.port}`,
    usage: () => ({ used, maxRequests, stopped }),
    close: () => {
      clearTimeout(timer);
      return new Promise((resolve) => server.close(resolve));
    },
  };
}
