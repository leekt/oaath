/** Runnable local delegation service with a phone as its owner device. */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";
import { startPhoneService } from "./service.mjs";

const envFile = new URL("../.env", import.meta.url);
if (existsSync(envFile)) {
  for (const [name, value] of Object.entries(parseEnv(readFileSync(envFile, "utf8")))) {
    if (process.env[name] === undefined) process.env[name] = value;
  }
}
if (process.env.OAATH_ZERODEV_LIVE === "1") {
  console.error(
    "The phone example now uses the shared SDK on local Anvil. Live sponsorship needs an SDK chain adapter.",
  );
  process.exitCode = 1;
} else if (process.env.OAATH_PHONE_SIMULATE === "1") {
  const result = spawnSync(
    process.execPath,
    [
      "--import",
      fileURLToPath(new URL("../support/workspace-typescript.mjs", import.meta.url)),
      "--test",
      fileURLToPath(new URL("./workflow.test.mjs", import.meta.url)),
    ],
    { stdio: "inherit", env: process.env },
  );
  process.exitCode = result.status ?? 1;
} else {
  let service;
  try {
    service = await startPhoneService({
      host: process.env.OAATH_HOST ?? "0.0.0.0",
      port: Number(process.env.OAATH_PORT ?? 8787),
    });
    console.log(`Phone delegation demo: ${service.url}`);
    console.log("Local Anvil, P-256 owner. Choose Pair phone, connect, then request permission.");
    const waitMs = Number(process.env.OAATH_PHONE_WAIT_MS ?? 300_000);
    await new Promise((resolve) => {
      const timer = setTimeout(done, waitMs);
      function done() {
        clearTimeout(timer);
        process.off("SIGINT", done);
        process.off("SIGTERM", done);
        resolve();
      }
      process.once("SIGINT", done);
      process.once("SIGTERM", done);
    });
  } catch {
    console.error("Phone demo unavailable; check local Anvil and the configured listening port.");
    process.exitCode = 1;
  } finally {
    await service?.close();
  }
}
