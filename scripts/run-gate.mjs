import { spawnSync } from "node:child_process";
import { scrubLiveProviderEnvironment } from "./live-provider-environment.mjs";

const environment = scrubLiveProviderEnvironment(process.env);
const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";

for (const script of ["lint", "typecheck", "test", "pack:check"]) {
  const result = spawnSync(pnpm, [script], {
    cwd: new URL("..", import.meta.url),
    env: environment,
    stdio: "inherit",
  });

  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
