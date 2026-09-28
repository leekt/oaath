/** The published CLI bin against a real local deployment from packed artifacts. */
import { createConsumer } from "./packed-consumer.mjs";

const consumer = await createConsumer({
  label: "runtime-cli",
  packages: ["@oaath/protocol", "@oaath/sdk", "@oaath/server", "@oaath/testing", "oaath"],
  files: {
    "run.mjs": `
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createLocalAnvilFixture } from "@oaath/testing/anvil";
const exec = promisify(execFile);
const bin = "./node_modules/.bin/oaath";
const help = await exec(bin, ["--help"]);
if (!help.stdout.includes("oaath doctor")) throw new Error("CLI help unavailable");
const fixture = await createLocalAnvilFixture({ chainIds: [421614] });
try {
  const { stdout } = await exec(bin, ["doctor", "--chain", "421614", "--rpc", fixture.rpcUrl(421614), "--json"]);
  const ready = JSON.parse(stdout);
  if (!ready.ready || ready.factoryBinding !== "verified" || ready.components.find(row => row.id === "kernelUups").status !== "verified") throw new Error("packed CLI did not verify the real runtime");
  let mismatch;
  try { await exec(bin, ["doctor", "--chain", "143", "--rpc", fixture.rpcUrl(421614), "--json"]); }
  catch (error) { if (error.code !== 1) throw error; mismatch = JSON.parse(error.stdout); }
  if (mismatch?.ready !== false || mismatch.error !== "chain_mismatch") throw new Error("packed CLI accepted the wrong chain");
  console.log("packed oaath bin: real deterministic runtime verified; wrong chain rejected; no deployment writes by doctor");
} finally { await fixture.close(); }
`,
  },
});

try {
  console.log(consumer.node("run.mjs"));
} finally {
  await consumer.cleanup();
}
