/**
 * Owns: the signed owner operations that pin the relay's owner-operation
 * verifier to the SDK, for each root a portal account can have.
 *
 * Each root kind (ECDSA, raw P-256, WebAuthn) signs one fixed operation on its
 * factory-derived account through `prepareOwnerOperation`, offline, and one on
 * the same account named by an existing-account (imported) profile. Variants
 * alter exactly one fact. An altered operation that is re-encoded and
 * re-hashed keeps the original signature, as a submitter tampering after
 * signing would. `expect.failure` names the first failing stage of the SDK's
 * own `verifyOwnerOperation`: `request` (protocol shape, calls against
 * callData, root nonce, hash), `binding` (derived or existing sender, factory,
 * EntryPoint),
 * or `signature`. Keys and inputs are fixed, so the output is deterministic.
 *
 * Run: bun run fixtures:protocol
 *
 * @author taek <leekt216@gmail.com>
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const sdk = `${root}packages/sdk/`;
const { PORTAL_ORIGIN, PORTAL_RP_ID, portalRoot, portalSecret } = await import(
  `${sdk}test/support/portal-roots.ts`
);
const { ECDSA_VALIDATOR, prepareOwnerOperation, verifyOwnerOperation } = await import(
  `${sdk}src/kernel.ts`
);
const { ecdsaWalletKey } = await import(`${sdk}src/kernel/key/ecdsa.ts`);
const {
  OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
  OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
  ownerUserOperationForCetane,
} = await import(`${root}packages/protocol/src/index.ts`);
const fromSdk = { resolve: (specifier) => Bun.resolveSync(specifier, sdk) };
const { privateKeyToAccount } = await import(fromSdk.resolve("cetane/accounts"));
const { getSigningHash } = await import(fromSdk.resolve("cetane/execution/erc4337"));
const { bytesToHex, decodeAbiParameters, encodeAbiParameters } = await import(
  fromSdk.resolve("cetane/utils")
);
const { p256 } = await import(fromSdk.resolve("@noble/curves/nist.js"));
const { sha256 } = await import(fromSdk.resolve("@noble/hashes/sha256"));

const OUTPUT = `${root}relay/fixtures/kernel-approval`;
const CHAIN_ID = 8_453;
const RELYING_PARTY = Object.freeze({ rpId: PORTAL_RP_ID, origin: PORTAL_ORIGIN });
const TARGET = `0x${"7a".repeat(20)}`;
const ASSERTION = [
  { name: "authenticatorData", type: "bytes" },
  { name: "clientDataJSON", type: "string" },
  { name: "responseTypeLocation", type: "uint256" },
  { name: "r", type: "uint256" },
  { name: "s", type: "uint256" },
  { name: "usePrecompiled", type: "bool" },
];
const base = Object.freeze({
  chainId: CHAIN_ID,
  deployed: false,
  calls: [
    { target: TARGET, value: "500", data: "0x12345678" },
    { target: `0x${"7b".repeat(20)}`, value: "0", data: "0xa9059cbb" },
  ],
  nonce: { lane: "0", sequence: "0" },
  gas: {
    callGasLimit: "900000",
    verificationGasLimit: "3000000",
    preVerificationGas: "150000",
    maxFeePerGas: "2000000000",
    maxPriorityFeePerGas: "1000000000",
  },
});

const clone = (value) => JSON.parse(JSON.stringify(value));

function account(rootKey, accountIndex = "0") {
  return {
    version: OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
    kind: "kernel",
    accountIndex,
    kernelVersion: "0.4.0",
    factoryRoute: "kernel_factory",
    entryPoint: { version: "0.9" },
    ownerCredential: rootKey.credential,
  };
}

/** The same account as an existing (imported) Kernel 0.4.0 profile at `address`. */
function existingAccount(rootKey, address) {
  return {
    version: OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
    kind: "kernel",
    address,
    kernelVersion: "0.4.0",
    entryPoint: { version: "0.9" },
    ownerCredential: rootKey.credential,
  };
}

/** The first stage `verifyOwnerOperation` refuses, or null when it verifies. */
async function failure(signed) {
  try {
    await verifyOwnerOperation(signed, RELYING_PARTY);
    return null;
  } catch (error) {
    if (error.code === "signing_request_invalid") return "request";
    if (error.code === "kernel_runtime_binding_mismatch") return "binding";
    if (error.code === "kernel_runtime_signature_invalid") return "signature";
    throw error;
  }
}

/** The same operation input with one change, re-prepared, keeping `signed`'s signature. */
function altered(signed, rootKey, change) {
  const request = prepareOwnerOperation({
    ...base,
    account: account(rootKey),
    ...change,
  }).request;
  return { ...signed, request: clone(request) };
}

/** One field of the operation replaced and the hash recomputed; callData stays. */
function rehashed(signed, change) {
  const request = clone(signed.request);
  Object.assign(request, change.request ?? {});
  Object.assign(request.userOperation, change.userOperation ?? {});
  request.userOperationHash = getSigningHash(
    ownerUserOperationForCetane(request.userOperation),
    request.chainId,
    request.entryPoint,
    "0.9",
  );
  return { ...signed, request };
}

function flipByte(hex, index) {
  const offset = 2 + index * 2;
  const byte = (Number.parseInt(hex.slice(offset, offset + 2), 16) ^ 0x01).toString(16);
  return `${hex.slice(0, offset)}${byte.padStart(2, "0")}${hex.slice(offset + 2)}`;
}

/** The root's WebAuthn assertion re-signed over altered authenticator or client data. */
function webauthnVariant(signature, change) {
  const [authenticatorData, clientDataJSON] = decodeAbiParameters(ASSERTION, signature);
  const json = JSON.stringify({ ...JSON.parse(clientDataJSON), ...change.client });
  const data = change.authenticatorData?.(authenticatorData) ?? authenticatorData;
  const message = sha256(
    new Uint8Array([
      ...Buffer.from(data.slice(2), "hex"),
      ...sha256(new TextEncoder().encode(json)),
    ]),
  );
  const signed = p256.sign(message, portalSecret("webauthn"), { lowS: true, prehash: false });
  return encodeAbiParameters(ASSERTION, [
    data,
    json,
    BigInt(json.indexOf('"type":')),
    signed.r,
    signed.s,
    false,
  ]);
}

const cases = [];
async function record(kind, name, signed, valid) {
  const stage = await failure(signed);
  if (valid !== (stage === null))
    throw new Error(`${kind} ${name}: expected ${valid ? "valid" : "a refusal"}, got ${stage}`);
  cases.push({
    name: `${kind} root: ${name}`,
    rootKind: kind,
    signed,
    expect: stage === null ? { valid: true } : { valid: false, failure: stage },
  });
}

for (const kind of ["ecdsa", "p256", "webauthn"]) {
  const rootKey = portalRoot(kind);
  const prepared = prepareOwnerOperation({ ...base, account: account(rootKey) });
  const signed = clone(await prepared.sign(rootKey.key));
  await record(kind, "valid, deploys the account", signed, true);
  await record(
    kind,
    "valid, account already deployed",
    clone(
      await prepareOwnerOperation({ ...base, account: account(rootKey), deployed: true }).sign(
        rootKey.key,
      ),
    ),
    true,
  );

  const calls = clone(base.calls);
  calls[0].target = `0x${"7c".repeat(20)}`;
  await record(kind, "call target altered", altered(signed, rootKey, { calls }), false);
  const values = clone(base.calls);
  values[0].value = "501";
  await record(kind, "call value altered", altered(signed, rootKey, { calls: values }), false);
  await record(
    kind,
    "gas altered",
    altered(signed, rootKey, { gas: { ...base.gas, callGasLimit: "900001" } }),
    false,
  );
  await record(
    kind,
    "nonce altered",
    altered(signed, rootKey, { nonce: { lane: "0", sequence: "1" } }),
    false,
  );
  await record(
    kind,
    "paymaster added",
    altered(signed, rootKey, {
      paymaster: {
        address: `0x${"99".repeat(20)}`,
        verificationGasLimit: "100000",
        postOpGasLimit: "50000",
        data: "0x",
      },
    }),
    false,
  );
  await record(
    kind,
    "another account of the same root",
    altered(signed, rootKey, { account: account(rootKey, "1") }),
    false,
  );
  await record(
    kind,
    "sender is not the derived account",
    rehashed(signed, { userOperation: { sender: `0x${"5e".repeat(20)}` } }),
    false,
  );
  await record(
    kind,
    "factory data deploys another account",
    rehashed(signed, {
      userOperation: {
        factory: {
          address: signed.request.userOperation.factory.address,
          data: altered(signed, rootKey, { account: account(rootKey, "1") }).request.userOperation
            .factory.data,
        },
      },
    }),
    false,
  );
  await record(
    kind,
    "another EntryPoint",
    rehashed(signed, { request: { entryPoint: `0x${"43".repeat(20)}` } }),
    false,
  );
  const unencoded = clone(signed);
  unencoded.request.calls[0].value = "501";
  await record(kind, "calls altered without their callData", unencoded, false);
  const stale = clone(signed);
  stale.request.userOperation.callGasLimit = "900001";
  await record(kind, "operation altered without its hash", stale, false);
  await record(
    kind,
    "nonce outside root validation",
    rehashed(signed, { userOperation: { nonce: String(2n << 240n) } }),
    false,
  );
  await record(
    kind,
    "paymaster data carries a detached signature marker",
    rehashed(signed, {
      userOperation: {
        paymaster: {
          address: `0x${"99".repeat(20)}`,
          verificationGasLimit: "100000",
          postOpGasLimit: "50000",
          data: "0xab000122e325a297439656",
        },
      },
    }),
    false,
  );
  await record(
    kind,
    "signed by another key of the same kind",
    {
      ...signed,
      signature: await portalRoot(kind, "other").key.sign(signed.request.userOperationHash),
    },
    false,
  );
  await record(
    kind,
    "signature byte flipped",
    { ...signed, signature: flipByte(signed.signature, kind === "webauthn" ? 100 : 10) },
    false,
  );

  // The same account, imported: it executes at its own address, deployed.
  const address = signed.request.userOperation.sender;
  const existing = existingAccount(rootKey, address);
  const imported = clone(
    await prepareOwnerOperation({ ...base, deployed: true, account: existing }).sign(rootKey.key),
  );
  await record(kind, "existing account: valid", imported, true);
  await record(
    kind,
    "existing account: sender is not its address",
    rehashed(imported, { userOperation: { sender: `0x${"5e".repeat(20)}` } }),
    false,
  );
  await record(
    kind,
    "existing account: carries a factory",
    rehashed(imported, { userOperation: { factory: signed.request.userOperation.factory } }),
    false,
  );
  await record(
    kind,
    "existing account: another EntryPoint",
    rehashed(imported, { request: { entryPoint: `0x${"43".repeat(20)}` } }),
    false,
  );
  await record(
    kind,
    "existing account: a Kernel 0.3.3 profile",
    rehashed(imported, {
      request: { account: { ...existing, kernelVersion: "0.3.3", entryPoint: { version: "0.7" } } },
    }),
    false,
  );
  await record(
    kind,
    "existing account: signed by another key of the same kind",
    {
      ...imported,
      signature: await portalRoot(kind, "other").key.sign(imported.request.userOperationHash),
    },
    false,
  );
  if (kind === "webauthn") {
    for (const [name, change] of [
      ["assertion from another origin", { client: { origin: "https://evil.example" } }],
      [
        "assertion for another relying party",
        { authenticatorData: (data) => `0x${"00".repeat(32)}${data.slice(66)}` },
      ],
    ])
      await record(
        kind,
        name,
        { ...signed, signature: webauthnVariant(signed.signature, change) },
        false,
      );
  }
}

// A connected wallet signs the EIP-191 message hash; the ECDSA validator accepts both.
const ecdsaRoot = portalRoot("ecdsa");
const wallet = privateKeyToAccount(bytesToHex(portalSecret("ecdsa")));
const walletKey = ecdsaWalletKey({
  wallet: {
    account: { address: ecdsaRoot.credential.address, type: "local" },
    signMessage: ({ message }) => wallet.signMessage({ message }),
  },
  validator: ECDSA_VALIDATOR,
});
await record(
  "ecdsa",
  "valid, EIP-191 wallet signature",
  clone(await prepareOwnerOperation({ ...base, account: account(ecdsaRoot) }).sign(walletKey)),
  true,
);

mkdirSync(OUTPUT, { recursive: true });
writeFileSync(
  `${OUTPUT}/portal-root-owner-operations.json`,
  `${JSON.stringify(
    {
      version: "oaath.portal-root-owner-operation-fixtures/v1",
      webauthn: RELYING_PARTY,
      ecdsaValidator: ECDSA_VALIDATOR,
      cases,
    },
    null,
    2,
  )}\n`,
);
console.log(`owner operations: ${cases.length} cases`);
