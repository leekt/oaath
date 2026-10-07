/**
 * Owns: the signed Kernel replayable-install approvals that pin the relay's
 * root-signature verifier to the SDK, for each root a portal account can have.
 *
 * Each root kind (ECDSA, raw P-256, WebAuthn) approves one fixed dapp-session
 * permission request through `prepareKernelPermissionApproval` on a local
 * loopback Anvil chain (the account binding reads the factory and validator
 * code; nothing is sent and no public RPC is contacted). Tampered variants
 * break exactly one binding. `expect` comes from the SDK's own checks: the
 * capability hash, the recomputed approval digest, the bound account and
 * packages through the digest, and the root key profile's local signature
 * verification. Keys, times and nonces are fixed, so the output is
 * deterministic.
 *
 * Run: bun run fixtures:protocol
 *
 * @author taek <leekt216@gmail.com>
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const sdk = `${root}packages/sdk/`;
const { createHarness, deployKernelStack, startAnvil } = await import(
  `${sdk}test/support/anvil.ts`
);
const { PORTAL_ORIGIN, PORTAL_RP_ID, portalPermissionRequest, portalRoot } = await import(
  `${sdk}test/support/portal-roots.ts`
);
const { prepareKernelPermissionApproval } = await import(`${sdk}src/kernel.ts`);
const { kernelGrantCapabilityHash } = await import(`${sdk}src/kernel/permission/approval.ts`);
const { parseKernelAllChainApproval } = await import(`${sdk}src/kernel/permission/materialize.ts`);
// Third-party modules resolve from the SDK, whose tests own these helpers.
const fromSdk = createRequire(`${sdk}package.json`);
const { decodeAbiParameters, encodeAbiParameters } = await import(fromSdk.resolve("viem"));
const { p256 } = await import(fromSdk.resolve("@noble/curves/nist.js"));
const { sha256 } = await import(fromSdk.resolve("@noble/hashes/sha256"));

const OUTPUT = `${root}relay/fixtures/kernel-approval`;
const CHAIN_ID = 8_453;
const REQUESTED_AT = 1_800_000_000;
const DECIDED_AT = REQUESTED_AT + 10;
const TARGET = `0x${"7a".repeat(20)}`;
const OTHER_DIGEST = `0x${"5c".repeat(32)}`;
const ASSERTION = [
  { name: "authenticatorData", type: "bytes" },
  { name: "clientDataJSON", type: "string" },
  { name: "responseTypeLocation", type: "uint256" },
  { name: "r", type: "uint256" },
  { name: "s", type: "uint256" },
  { name: "usePrecompiled", type: "bool" },
];

const clone = (value) => JSON.parse(JSON.stringify(value));

/**
 * The checks the relay must reproduce, in order; the first failure names the
 * case. The approval digest equal to the signing request's commits to the
 * account (the registry address) and the requested permission's packages.
 */
async function verify(kind, decision, signingRequest) {
  const approval = decision.installApproval;
  try {
    parseKernelAllChainApproval(approval);
  } catch {
    return "approval_digest";
  }
  if (approval.digest !== signingRequest.expectedDigest) return "approval_digest";
  if (decision.capabilityHash !== kernelGrantCapabilityHash(approval)) return "capability_hash";
  return (await portalRoot(kind).key.verify(approval.digest, approval.enableSignature))
    ? null
    : "signature";
}

/** Replaces the signature and recomputes the capability hash, so only the signature differs. */
function withSignature(decision, enableSignature) {
  const installApproval = { ...decision.installApproval, enableSignature };
  return {
    ...decision,
    installApproval,
    capabilityHash: kernelGrantCapabilityHash(installApproval),
  };
}

function flipByte(hex, index) {
  const offset = 2 + index * 2;
  const byte = (Number.parseInt(hex.slice(offset, offset + 2), 16) ^ 0x01).toString(16);
  return `${hex.slice(0, offset)}${byte.padStart(2, "0")}${hex.slice(offset + 2)}`;
}

/** A WebAuthn assertion re-signed by the root over altered authenticator or client data. */
async function webauthnVariant(digest, change) {
  const [authenticatorData, clientDataJSON] = decodeAbiParameters(
    ASSERTION,
    await portalRoot("webauthn").key.sign(digest),
  );
  const client = { ...JSON.parse(clientDataJSON), ...change.client };
  const json = JSON.stringify(client);
  const data = change.authenticatorData?.(authenticatorData) ?? authenticatorData;
  const secret = sha256(new TextEncoder().encode("oaath-portal-root:webauthn:root"));
  const message = sha256(
    new Uint8Array([
      ...Buffer.from(data.slice(2), "hex"),
      ...sha256(new TextEncoder().encode(json)),
    ]),
  );
  const signature = p256.sign(message, secret, { lowS: true, prehash: false });
  return encodeAbiParameters(ASSERTION, [
    data,
    json,
    BigInt(json.indexOf('"type":')),
    signature.r,
    signature.s,
    false,
  ]);
}

const cases = [];
const chain = await startAnvil(CHAIN_ID, "osaka");
try {
  const harness = await createHarness(chain);
  await deployKernelStack(harness);
  await harness.deployModule(harness.fixture.p256Validator);
  await harness.deployModule(harness.fixture.ecdsaSigner);
  await harness.deployModule(harness.fixture.callPolicy);
  await harness.deployModule(harness.fixture.validityPolicy);
  await harness.deployModule(harness.fixture.rateLimitPolicy);
  const read = async (path) => JSON.parse(await readFile(path, "utf8"));
  const v33 = await read(`${sdk}test/fixtures/kernel-v33-deployments.json`);
  await harness.deployCreate2(v33.ecdsaValidator.deploymentInput);
  const webauthn = await read(`${root}packages/contracts/artifacts/KernelWebAuthnValidator.json`);
  await harness.deployCreate2(webauthn.deploymentInput);

  for (const kind of ["ecdsa", "p256", "webauthn"]) {
    const rootKey = portalRoot(kind);
    const request = portalPermissionRequest({
      root: rootKey,
      target: TARGET,
      requestedAt: REQUESTED_AT,
    });
    const prepared = await prepareKernelPermissionApproval({
      request,
      chainId: CHAIN_ID,
      reads: harness.reads,
    });
    const signingRequest = clone(prepared.signingRequest);
    const decision = clone(await prepared.sign(rootKey.key, DECIDED_AT));
    const digest = decision.installApproval.digest;
    const variants = [["valid", decision]];
    const signature = decision.installApproval.enableSignature;
    // A byte of r: the ECDSA and P-256 signatures lead with it; the WebAuthn
    // assertion ABI-encodes it as its fourth word.
    variants.push([
      "signature byte flipped",
      withSignature(decision, flipByte(signature, kind === "webauthn" ? 100 : 10)),
    ]);
    variants.push([
      "signed by another key of the same kind",
      withSignature(decision, await portalRoot(kind, "other").key.sign(digest)),
    ]);
    variants.push([
      "signature over another digest",
      withSignature(decision, await rootKey.key.sign(OTHER_DIGEST)),
    ]);
    variants.push([
      "capability hash does not commit to the approval",
      { ...decision, capabilityHash: `0x${"ab".repeat(32)}` },
    ]);
    variants.push([
      "approval digest altered",
      {
        ...decision,
        installApproval: { ...decision.installApproval, digest: OTHER_DIGEST },
      },
    ]);
    if (kind === "webauthn") {
      for (const [name, change] of [
        ["assertion from another origin", { client: { origin: "https://evil.example" } }],
        ["assertion for another challenge", { client: { challenge: "AAAA" } }],
        ["assertion of type create", { client: { type: "webauthn.create" } }],
        [
          "assertion without user verification",
          { authenticatorData: (data) => `${data.slice(0, 66)}01${data.slice(68)}` },
        ],
        [
          "assertion for another relying party",
          { authenticatorData: (data) => `0x${"00".repeat(32)}${data.slice(66)}` },
        ],
      ])
        variants.push([name, withSignature(decision, await webauthnVariant(digest, change))]);
    }
    for (const [name, variant] of variants) {
      const failure = await verify(kind, variant, signingRequest);
      if (name === "valid" && failure !== null) throw new Error(`${kind} root approval is invalid`);
      if (name !== "valid" && failure === null) throw new Error(`${kind} ${name} still verifies`);
      cases.push({
        name: `${kind} root: ${name}`,
        rootKind: kind,
        request: clone(request),
        signingRequest,
        decision: variant,
        expect: failure === null ? { valid: true } : { valid: false, failure },
      });
    }
  }
} finally {
  chain.stop();
}

mkdirSync(OUTPUT, { recursive: true });
writeFileSync(
  `${OUTPUT}/portal-root-approvals.json`,
  `${JSON.stringify(
    {
      version: "oaath.portal-root-approval-fixtures/v1",
      webauthn: { rpId: PORTAL_RP_ID, origin: PORTAL_ORIGIN },
      cases,
    },
    null,
    2,
  )}\n`,
);
console.log(`kernel approvals: ${cases.length} cases`);
