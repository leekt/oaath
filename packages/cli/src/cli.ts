#!/usr/bin/env node
import { parseArgs } from "node:util";
import { doctor } from "./doctor.js";
import { Rpc } from "./rpc.js";

const PUBLIC_RPCS: Readonly<Record<number, string>> = {
  143: "https://rpc.monad.xyz",
  480: "https://worldchain-mainnet.g.alchemy.com/public",
  4326: "https://mainnet.megaeth.com/rpc",
  4217: "https://rpc.mainnet.tempo.xyz",
  4663: "https://rpc.mainnet.chain.robinhood.com",
  5042: "https://rpc.mainnet.arc.io",
};

const HELP = `Usage: oaath doctor --chain <id> [--rpc <url>] [--json]

Checks the Kernel v4 / EntryPoint 0.7 ECDSA session module set.
Owner validators remain application-selected; optional P-256/WebAuthn rows
report their deployment separately. No wallet or transaction is used.
Defaults exist for chains 143, 480, 4326, 4217, 4663 and 5042.
RPC bounds: 32 requests, four in flight, 5 seconds per request, 60 seconds total,
no retries or fallback. --rpc explicitly selects one endpoint.
Exit: 0 runtime ready, 1 not ready or unreadable, 2 invalid command.
`;

async function main(): Promise<void> {
  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        chain: { type: "string" },
        rpc: { type: "string" },
        json: { type: "boolean" },
        help: { type: "boolean", short: "h" },
      },
    });
  } catch {
    console.error(HELP);
    process.exitCode = 2;
    return;
  }
  const { positionals, values } = parsed;
  if (values.help || positionals.length === 0) {
    console.log(HELP);
    return;
  }
  const chainId =
    typeof values.chain === "string" && /^[1-9][0-9]*$/u.test(values.chain)
      ? Number(values.chain)
      : NaN;
  if (positionals.length !== 1 || positionals[0] !== "doctor" || !Number.isSafeInteger(chainId)) {
    console.error(HELP);
    process.exitCode = 2;
    return;
  }
  const url = typeof values.rpc === "string" ? values.rpc : PUBLIC_RPCS[chainId];
  if (!url) {
    console.error("No default RPC for this chain; supply --rpc <url>.");
    process.exitCode = 2;
    return;
  }
  let rpc: Rpc;
  try {
    rpc = new Rpc(url);
  } catch {
    console.error("Invalid RPC URL; use http or https.");
    process.exitCode = 2;
    return;
  }
  const report = await doctor(chainId, rpc);
  if (values.json) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(
      `Chain ${chainId}: ${report.ready ? "runtime ready" : "not ready"} — ${report.checkedAt}`,
    );
    console.log(
      `Block: ${report.blockNumber ?? "unreadable"}; factory binding: ${report.factoryBinding}`,
    );
    if (report.error) console.log(`Error: ${report.error}`);
    for (const row of report.components)
      console.log(
        `${row.id.padEnd(22)} ${row.address}  ${row.status}${row.required ? "" : " (optional)"}`,
      );
    console.log(
      "present = code at the canonical CREATE2 address; verified = pinned runtime hash matches.",
    );
    console.log(
      "Readiness covers the ECDSA session set; verify your chosen owner validator separately.",
    );
  }
  process.exitCode = report.ready ? 0 : 1;
}

main().catch(() => {
  console.error("Runtime check failed; no readiness claim was made.");
  process.exitCode = 1;
});
