// Owns: default gates remove paid-provider credentials before any test worker starts.
// Wired as a vitest globalSetup; test workers inherit the scrubbed process env.
import { scrubLiveProviderEnvironment } from "../packages/sdk/scripts/live-provider-environment.mjs";

export default function scrubLiveRpcEnv() {
  const scrubbed = scrubLiveProviderEnvironment(process.env);
  for (const name of Object.keys(process.env)) {
    if (!(name in scrubbed)) {
      delete process.env[name];
    }
  }
}
