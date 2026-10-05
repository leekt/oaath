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
       oaath deploy-runtime --chain <id> --rpc <url> [--dry-run] [--journal <path>] [--json]

Checks the Kernel v4 / EntryPoint 0.9 ECDSA session module set.
Owner validators remain application-selected. Passkey (WebAuthn) session
readiness, the WebAuthn signer and P-256 verifier with pinned hashes, is reported
separately and never gates the exit code. No wallet or transaction is used.
Defaults exist for chains 143, 480, 4326, 4217, 4663 and 5042.
RPC bounds: 32 requests, four in flight, 5 seconds per request, 60 seconds total,
no retries or fallback. --rpc explicitly selects one endpoint.
deploy-runtime requires an explicit --rpc and OAATH_DEPLOYER_PRIVATE_KEY for new
transactions. --dry-run checks prerequisites and lists missing contracts without
loading a key. Deployment bounds: 256 requests, 180 seconds total, gas <= 10M
per transaction. Receipt observation never resends an attempted transaction.
Exit: 0 runtime ready or successful dry run, 1 incomplete or unreadable, 2 invalid command.
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
        "dry-run": { type: "boolean" },
        journal: { type: "string" },
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
  const deploying = positionals[0] === "deploy-runtime";
  if (
    positionals.length !== 1 ||
    (!deploying && positionals[0] !== "doctor") ||
    !Number.isSafeInteger(chainId) ||
    (!deploying && (values["dry-run"] !== undefined || values.journal !== undefined))
  ) {
    console.error(HELP);
    process.exitCode = 2;
    return;
  }
  const url =
    typeof values.rpc === "string" ? values.rpc : deploying ? undefined : PUBLIC_RPCS[chainId];
  if (!url) {
    console.error("Supply --rpc <url>; deployment always requires an explicit endpoint.");
    process.exitCode = 2;
    return;
  }
  let rpc: Rpc;
  try {
    rpc = new Rpc(url, deploying ? { maxRequests: 256, durationMs: 180_000 } : {});
  } catch {
    console.error("Invalid RPC URL; use http or https.");
    process.exitCode = 2;
    return;
  }
  if (deploying) {
    const [
      { deployRuntime, DeploymentError },
      { DeploymentJournal },
      { privateKeyToAccount },
      { homedir },
      { join, resolve },
    ] = await Promise.all([
      import("./deploy.js"),
      import("./journal.js"),
      import("viem/accounts"),
      import("node:os"),
      import("node:path"),
    ]);
    const path =
      typeof values.journal === "string"
        ? resolve(values.journal)
        : join(homedir(), ".local", "state", "oaath", "runtime.sqlite");
    const journal = new DeploymentJournal(values["dry-run"] ? ":memory:" : path);
    try {
      const result = await deployRuntime({
        chainId,
        rpc,
        journal,
        dryRun: values["dry-run"] === true,
        account: () => {
          const key = process.env.OAATH_DEPLOYER_PRIVATE_KEY;
          if (!key) throw new DeploymentError("deployment_key_required");
          if (!/^0x[0-9a-fA-F]{64}$/u.test(key))
            throw new DeploymentError("deployment_key_invalid");
          try {
            return privateKeyToAccount(key as `0x${string}`);
          } catch {
            throw new DeploymentError("deployment_key_invalid");
          }
        },
      });
      if (values.json) console.log(JSON.stringify(result, null, 2));
      else {
        console.log(`Chain ${chainId}: ${result.status}`);
        if (result.missing.length) console.log(`Missing: ${result.missing.join(", ")}`);
        for (const row of result.readiness.components.filter((row) => row.required))
          console.log(`${row.id.padEnd(22)} ${row.address}  ${row.status}`);
        if (result.transactionHash)
          console.log(
            `Observe transaction ${result.transactionHash}; rerun with the same journal. No resend will occur.`,
          );
        if (!values["dry-run"]) console.log(`Journal: ${path}`);
      }
      process.exitCode =
        result.status === "ready" || (values["dry-run"] && result.status === "planned") ? 0 : 1;
    } catch (error) {
      console.error(error instanceof DeploymentError ? error.code : "deployment_unavailable");
      console.error(
        "Retain the journal. Rerunning observes any saved attempt before allowing another deployment.",
      );
      process.exitCode = 1;
    } finally {
      journal.close();
    }
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
        `${row.id.padEnd(22)} ${row.address}  ${row.status}${row.required ? "" : row.passkeySession ? " (passkey sessions)" : " (optional)"}`,
      );
    console.log(`Passkey sessions: ${report.passkeySessionsReady ? "ready" : "not ready"}`);
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
