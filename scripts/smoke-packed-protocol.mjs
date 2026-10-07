import { readFileSync } from "node:fs";
import { createConsumer } from "./packed-consumer.mjs";

const fixture = readFileSync(
  new URL("../packages/protocol/test/fixtures/eip712-hash-vectors.json", import.meta.url),
  "utf8",
);
const consumer = await createConsumer({
  label: "cetane-protocol",
  packages: ["@oaath/protocol"],
  files: {
    "vectors.json": fixture,
    "consumer.ts": `import { hashCanonicalEip712TypedData, deriveCodeChallenge, entryPointAbi } from "@oaath/protocol";
const digest: \`0x\${string}\` = hashCanonicalEip712TypedData({});
const challenge: string = deriveCodeChallenge("a".repeat(43));
void [digest, challenge, entryPointAbi];`,
    "consumer.mjs": `import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { hashCanonicalEip712TypedData, deriveCodeChallenge } from "@oaath/protocol";
assert.throws(() => import.meta.resolve("viem"), { code: "ERR_MODULE_NOT_FOUND" });
const fixture = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
for (const vector of fixture.vectors) {
  assert.equal(hashCanonicalEip712TypedData(vector.typedData), vector.expectedDigest);
  for (const mutation of vector.mutations) {
    const input = structuredClone(vector.typedData);
    const path = mutation.pointer.slice(1).split("/").map(p => p.replaceAll("~1", "/").replaceAll("~0", "~"));
    let target = input;
    for (const key of path.slice(0, -1)) target = target[key];
    target[path.at(-1)] = mutation.value;
    assert.equal(hashCanonicalEip712TypedData(input), mutation.expectedDigest);
  }
}
assert.equal(deriveCodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
assert.throws(() => hashCanonicalEip712TypedData({}));
assert.throws(() => deriveCodeChallenge("short"));
console.log("Packed protocol vectors and PKCE pass without viem installed.");`,
  },
});
try {
  consumer.typecheck();
  console.log(consumer.node("consumer.mjs").trim());
} finally {
  await consumer.cleanup();
}
