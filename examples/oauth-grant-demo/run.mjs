/**
 * The live Arbitrum Sepolia Grant demo, opt-in only:
 *
 *   OAATH_LIVE=1 bun run --filter @oaath/examples example:oauth-grant-demo
 *
 * Without OAATH_LIVE=1 it refuses to start: no live network is contacted by
 * default, by tests, or by CI. All chain traffic goes through this process
 * (see server.mjs) under one hard budget and one time cap.
 *
 *   OAATH_ISSUER             default https://oaath.taek.tech
 *   OAATH_RPC_URL            default https://sepolia-rollup.arbitrum.io/rpc
 *   OAATH_BUNDLER_URL        default https://public.pimlico.io/v2/421614/rpc
 *   OAATH_MAX_REQUESTS       default 800 chain + bundler requests for the run
 *   OAATH_TIME_CAP_MINUTES   default 45 (Arbitrum finality can take tens of minutes)
 *   OAATH_PORT               default 5175
 *   OAATH_CLIENT_ID          optional; otherwise the page registers a client once
 *
 * @author taek <leekt216@gmail.com>
 */
import { redact, startGrantDemo } from "./server.mjs";

if (process.env.OAATH_LIVE !== "1") {
  console.error(
    "This demo sends a real UserOperation on Arbitrum Sepolia. Run it with OAATH_LIVE=1 to opt in.",
  );
  process.exit(1);
}
const positive = (name, fallback) => {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value < 1)
    throw new Error(`${name} must be a positive integer`);
  return value;
};
const rpcUrl = process.env.OAATH_RPC_URL ?? "https://sepolia-rollup.arbitrum.io/rpc";
const bundlerUrl = process.env.OAATH_BUNDLER_URL ?? "https://public.pimlico.io/v2/421614/rpc";
const maxRequests = positive("OAATH_MAX_REQUESTS", 800);
const minutes = positive("OAATH_TIME_CAP_MINUTES", 45);
const demo = await startGrantDemo({
  issuer: process.env.OAATH_ISSUER ?? "https://oaath.taek.tech",
  clientId: process.env.OAATH_CLIENT_ID ?? null,
  chainId: 421_614,
  rpcUrl,
  bundlerUrl,
  explorerTxUrl: "https://sepolia.arbiscan.io/tx/",
  maxRequests,
  timeCapMs: minutes * 60_000,
  // A zero-value call to the conventional burn address: no code, no state, no funds.
  target: "0x000000000000000000000000000000000000dead",
  selector: "0x12345678",
  port: positive("OAATH_PORT", 5175),
});
console.log(`OAAth Grant demo: open ${demo.url}`);
console.log(`  chain 421614 via ${redact(rpcUrl)}, bundler ${redact(bundlerUrl)} (no fallback)`);
console.log(`  budget ${maxRequests} requests, time cap ${minutes} min; Ctrl-C to stop`);
