/**
 * Owns: the generated fixtures that pin the Rust `oaath-protocol` port to the
 * TypeScript `@oaath/protocol` wire owner and the relay rules built on it.
 *
 * Every case is evaluated here by the TypeScript sources themselves; the Rust
 * suite (`relay/crates/oaath-protocol/tests/fixtures.rs`) must reproduce each
 * accept/reject decision, error code, canonical output, and hash exactly.
 * Inputs that JSON.stringify cannot express (`-0`, `1.0`, `1e3`, duplicate
 * keys) are stored as raw JSON text in `inputText`; both sides evaluate the
 * value that text parses to. The output is deterministic: no clock, no
 * randomness, fixed keys.
 *
 * Kernel v4 account-address cases start two local loopback Anvil chains
 * (foundry's `anvil` must be installed) and read the deployed factory; no other
 * case touches a chain, and nothing contacts a public RPC.
 *
 * Run: bun run fixtures:protocol (the `oaath-source` condition resolves the
 * server's `@oaath/protocol` imports to the same sources, never a stale build)
 *
 * @author taek <leekt216@gmail.com>
 */
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const P = await import(`${root}packages/protocol/src/index.ts`);
// Not re-exported from the package root; every request hash binds it.
const { hashOwnerCredentialProfile } = await import(
  `${root}packages/protocol/src/identity-profile.ts`
);
const { classifyStoredAuthorizationScope, parseApprovedPermission } = await import(
  `${root}packages/protocol/src/internal/relay-reference.ts`
);
const { p256 } = await import(`${root}packages/protocol/node_modules/@noble/curves/nist.js`);
const { keccak_256 } = await import(`${root}packages/protocol/node_modules/@noble/hashes/sha3.js`);

const OUTPUT = `${root}relay/fixtures/protocol`;

// ---------------------------------------------------------------- recording

/** Raw JSON number text that JSON.stringify cannot produce. */
class Raw {
  constructor(text) {
    this.text = text;
  }
}
const raw = (text) => new Raw(text);

/** A whole input given as raw JSON text (duplicate keys, `__proto__`). */
class Text {
  constructor(text) {
    this.text = text;
  }
}
const jsonText = (text) => new Text(text);

function hasRaw(value) {
  if (value instanceof Raw) return true;
  if (Array.isArray(value)) return value.some(hasRaw);
  if (value && typeof value === "object") return Object.values(value).some(hasRaw);
  return false;
}

function stringify(value) {
  if (value instanceof Raw) return value.text;
  if (Array.isArray(value)) return `[${value.map(stringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value)
      .map(([key, entry]) => `${JSON.stringify(key)}:${stringify(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function clone(value) {
  if (value instanceof Raw) return value;
  if (Array.isArray(value)) return value.map(clone);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, clone(entry)]));
  }
  return value;
}

function at(value, path) {
  return path.reduce((entry, key) => entry[key], value);
}

function set(base, path, next) {
  if (path.length === 0) return next;
  const copy = clone(base);
  at(copy, path.slice(0, -1))[path.at(-1)] = next;
  return copy;
}

function drop(base, path) {
  const copy = clone(base);
  const parent = at(copy, path.slice(0, -1));
  if (Array.isArray(parent)) parent.splice(path.at(-1), 1);
  else delete parent[path.at(-1)];
  return copy;
}

function edit(base, change) {
  const copy = clone(base);
  change(copy);
  return copy;
}

const files = new Map();

function errorCode(fn, error) {
  if (typeof error?.code === "string") return error.code;
  if (fn === "parseApprovedPermission") {
    if (error instanceof SyntaxError) return "permission_artifact_json_invalid";
    if (error?.constructor === Error) return "permission_artifact_not_approved";
  }
  throw error;
}

const EVALUATE = {
  deriveCodeChallenge: (value) => P.deriveCodeChallenge(value),
  parseOwnerCredentialProfile: P.parseOwnerCredentialProfile,
  hashOwnerCredentialProfile,
  parseOperatorCredentialProfile: P.parseOperatorCredentialProfile,
  parseKernelAccountProfile: P.parseKernelAccountProfile,
  parseGrantPolicy: P.parseGrantPolicy,
  hashGrantPolicy: P.hashGrantPolicy,
  hashGrantPolicyCalls: P.hashGrantPolicyCalls,
  isGrantPolicyAttenuation: (value) => P.isGrantPolicyAttenuation(value.requested, value.approved),
  parseWorkspaceAccountContext: P.parseWorkspaceAccountContext,
  parsePermissionRequest: P.parsePermissionRequest,
  hashPermissionRequest: P.hashPermissionRequest,
  parsePermissionDecision: P.parsePermissionDecision,
  hashPermissionDecision: P.hashPermissionDecision,
  parseApprovedPermission: (value) =>
    parseApprovedPermission(
      value.plaintext,
      P.parsePermissionRequest(value.request),
      value.relayDecidedAt,
    ),
  parseOwnerSigningRequest: P.parseOwnerSigningRequest,
  hashOwnerSigningRequest: P.hashOwnerSigningRequest,
  parseKernelReplayableInstallOwnerSigningRequest:
    P.parseKernelReplayableInstallOwnerSigningRequest,
  classifyStoredAuthorizationScope: (value) =>
    classifyStoredAuthorizationScope(value.requestedScope, value.requestId),
  parseVerifyGrantRevisionInput: P.parseVerifyGrantRevisionInput,
  parseOaathGrantRef: P.parseOaathGrantRef,
  parseGrantVerificationResult: P.parseGrantVerificationResult,
};

/** Records one case; `input` may hold `Raw` numbers or be a whole `Text`. */
function record(fn, name, input) {
  const text = input instanceof Text ? input.text : stringify(input);
  const parsed = JSON.parse(text);
  let expect;
  try {
    expect = { ok: JSON.parse(JSON.stringify(EVALUATE[fn](parsed))) };
  } catch (error) {
    expect = { error: errorCode(fn, error) };
  }
  const cases = files.get(fn) ?? [];
  if (cases.some((entry) => entry.name === name)) throw new Error(`duplicate case ${fn}: ${name}`);
  const textual = input instanceof Text || hasRaw(input);
  cases.push(textual ? { name, fn, inputText: text, expect } : { name, fn, input: parsed, expect });
  files.set(fn, cases);
}

const WRONG_TYPES = [
  ["null", null],
  ["number", 1],
  ["string", "x"],
  ["array", []],
  ["object", {}],
  ["boolean", true],
];

/** Drops each key, adds an unknown key, and substitutes wrong types at `path`. */
function shapeCases(fn, label, base, path = [], { types = true } = {}) {
  const where = path.length === 0 ? "root" : path.join(".");
  const target = at(base, path);
  for (const key of Object.keys(target)) {
    record(fn, `${label}: drop ${where}.${key}`, drop(base, [...path, key]));
    if (!types) continue;
    for (const [kind, value] of WRONG_TYPES) {
      if (JSON.stringify(value) === JSON.stringify(target[key])) continue;
      record(fn, `${label}: ${where}.${key} as ${kind}`, set(base, [...path, key], value));
    }
  }
  record(fn, `${label}: unknown key at ${where}`, set(base, [...path, "unexpected"], true));
  for (const [kind, value] of WRONG_TYPES.slice(0, 4)) {
    record(fn, `${label}: ${where} as ${kind}`, set(base, path, value));
  }
}

// ------------------------------------------------------------------ helpers

const hex = (byte, count) => `0x${byte.repeat(count)}`;
const ZERO_ADDRESS = hex("00", 20);
const ZERO_HASH = hex("00", 32);
const MAX_UINT256 = ((1n << 256n) - 1n).toString();
const MAX_UINT48 = 2 ** 48 - 1;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

function checksum(address) {
  const lower = address.slice(2).toLowerCase();
  const digest = Buffer.from(keccak_256(new TextEncoder().encode(lower))).toString("hex");
  return `0x${[...lower].map((char, index) => (Number.parseInt(digest[index], 16) >= 8 ? char.toUpperCase() : char)).join("")}`;
}

const word = (value) => value.toString(16).padStart(64, "0");

function privateKey(label) {
  return new Uint8Array(createHash("sha256").update(label).digest());
}

function publicKeyOf(secret) {
  return `0x${Buffer.from(p256.getPublicKey(secret, false)).toString("hex")}`;
}

/** A valid P-256 point whose x coordinate re-encoded as x + p still fits 32 bytes. */
function outOfFieldPublicKey() {
  const { Fp } = p256.CURVE;
  for (let x = 1n; ; x += 1n) {
    const y2 = Fp.add(Fp.sub(Fp.mul(Fp.mul(x, x), x), Fp.mul(3n, x)), p256.CURVE.b);
    let y;
    try {
      y = Fp.sqrt(y2);
    } catch {
      continue;
    }
    if (Fp.mul(y, y) !== y2) continue;
    return { valid: `0x04${word(x)}${word(y)}`, shifted: `0x04${word(x + Fp.ORDER)}${word(y)}` };
  }
}

const OWNER_SECRET = privateKey("oaath-relay-protocol-fixture-owner");
const OTHER_SECRET = privateKey("oaath-relay-protocol-fixture-other");
const OWNER_PUBLIC_KEY = publicKeyOf(OWNER_SECRET);
const OTHER_PUBLIC_KEY = publicKeyOf(OTHER_SECRET);
const P256_GENERATOR =
  "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

const GOLDEN = JSON.parse(
  readFileSync(`${root}scripts/fixtures/owner-signing-golden.json`, "utf8"),
).projection;

// --------------------------------------------------------------------- PKCE

{
  const fn = "deriveCodeChallenge";
  const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  record(fn, "RFC 7636 appendix B verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
  record(fn, "43 characters", "a".repeat(43));
  record(fn, "128 characters", unreserved.repeat(2).slice(0, 128));
  record(fn, "every unreserved character", unreserved.slice(0, 66));
  record(fn, "42 characters", "a".repeat(42));
  record(fn, "129 characters", "a".repeat(129));
  record(fn, "empty", "");
  for (const [label, character] of [
    ["plus", "+"],
    ["slash", "/"],
    ["equals", "="],
    ["space", " "],
    ["percent", "%"],
    ["latin small e acute", "é"],
    ["emoji", "\u{1f600}"],
    ["trailing newline", "\n"],
    ["nul", "\u0000"],
  ]) {
    record(fn, `contains ${label}`, `${"a".repeat(43)}${character}`);
  }
}

// --------------------------------------------------------- identity profiles

const OWNER_ECDSA = {
  version: "oaath.owner-credential-profile/v1",
  kind: "ecdsa",
  address: hex("11", 20),
};
const OWNER_P256 = {
  version: "oaath.owner-credential-profile/v1",
  kind: "p256",
  publicKey: OWNER_PUBLIC_KEY,
};
const OWNER_WEBAUTHN = {
  version: "oaath.owner-credential-profile/v1",
  kind: "webauthn",
  publicKey: P256_GENERATOR,
  authenticatorIdHash: hex("22", 32),
};
const OPERATOR_ECDSA = {
  version: "oaath.operator-credential-profile/v1",
  kind: "ecdsa",
  address: hex("44", 20),
};
const OPERATOR_WEBAUTHN = {
  version: "oaath.operator-credential-profile/v1",
  kind: "webauthn",
  publicKey: OTHER_PUBLIC_KEY,
  authenticatorIdHash: hex("55", 32),
};
const MIXED_ADDRESS = "0x52908400098527886e0f7030069857d2e4169ee7";

function addressCases(fn, label, base, path) {
  const mixed = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
  record(fn, `${label}: mixed EIP-55`, set(base, path, checksum(mixed)));
  record(
    fn,
    `${label}: single-case uppercase`,
    set(base, path, `0x${mixed.slice(2).toUpperCase()}`),
  );
  record(
    fn,
    `${label}: incorrect mixed checksum`,
    set(base, path, checksum(mixed).replace("E", "e")),
  );
  record(fn, `${label}: EIP-55 checksummed`, set(base, path, checksum(MIXED_ADDRESS)));
  record(fn, `${label}: lowercase mixed-hex`, set(base, path, MIXED_ADDRESS));
  record(
    fn,
    `${label}: uppercase hex digits`,
    set(base, path, `0x${MIXED_ADDRESS.slice(2).toUpperCase()}`),
  );
  const wrong = checksum(MIXED_ADDRESS).replace("E", "e");
  record(fn, `${label}: invalid checksum`, set(base, path, wrong));
  record(fn, `${label}: zero`, set(base, path, ZERO_ADDRESS));
  record(fn, `${label}: 19 bytes`, set(base, path, hex("11", 19)));
  record(fn, `${label}: missing 0x`, set(base, path, "11".repeat(20)));
  record(fn, `${label}: 0X prefix`, set(base, path, `0X${"11".repeat(20)}`));
}

function publicKeyCases(fn, label, base, path) {
  const { valid, shifted } = outOfFieldPublicKey();
  record(fn, `${label}: small-x valid point`, set(base, path, valid));
  record(fn, `${label}: x coordinate not reduced`, set(base, path, shifted));
  record(
    fn,
    `${label}: uppercase`,
    set(base, path, `0x${OWNER_P256.publicKey.slice(2).toUpperCase()}`),
  );
  record(fn, `${label}: compressed`, set(base, path, `0x02${OWNER_P256.publicKey.slice(4, 68)}`));
  const offCurve = `${OWNER_P256.publicKey.slice(0, -2)}${OWNER_P256.publicKey.endsWith("00") ? "01" : "00"}`;
  record(fn, `${label}: off curve`, set(base, path, offCurve));
  record(fn, `${label}: zero point`, set(base, path, `0x04${"00".repeat(64)}`));
  record(
    fn,
    `${label}: 0x03 prefix uncompressed length`,
    set(base, path, `0x03${OWNER_P256.publicKey.slice(4)}`),
  );
}

for (const fn of ["parseOwnerCredentialProfile", "hashOwnerCredentialProfile"]) {
  record(fn, "ecdsa", OWNER_ECDSA);
  record(fn, "p256", OWNER_P256);
  record(fn, "webauthn", OWNER_WEBAUTHN);
  addressCases(fn, "ecdsa address", OWNER_ECDSA, ["address"]);
  publicKeyCases(fn, "p256 publicKey", OWNER_P256, ["publicKey"]);
  record(
    fn,
    "webauthn uppercase authenticatorIdHash",
    set(OWNER_WEBAUTHN, ["authenticatorIdHash"], hex("AB", 32)),
  );
  record(
    fn,
    "webauthn zero authenticatorIdHash",
    set(OWNER_WEBAUTHN, ["authenticatorIdHash"], ZERO_HASH),
  );
  record(fn, "unsupported kind", set(OWNER_ECDSA, ["kind"], "ed25519"));
  record(
    fn,
    "operator version",
    set(OWNER_ECDSA, ["version"], "oaath.operator-credential-profile/v1"),
  );
  record(fn, "ecdsa with publicKey", { ...OWNER_ECDSA, publicKey: OWNER_P256.publicKey });
  record(fn, "p256 with address", { ...OWNER_P256, address: OWNER_ECDSA.address });
  record(fn, "kind only", { version: OWNER_ECDSA.version, kind: "ecdsa" });
  record(
    fn,
    "duplicate kind: last wins to p256 with address",
    jsonText(
      `{"version":"${OWNER_ECDSA.version}","kind":"ecdsa","address":"${OWNER_ECDSA.address}","kind":"p256"}`,
    ),
  );
  record(
    fn,
    "duplicate kind: last wins to ecdsa",
    jsonText(
      `{"version":"${OWNER_ECDSA.version}","kind":"p256","address":"${OWNER_ECDSA.address}","kind":"ecdsa"}`,
    ),
  );
  record(
    fn,
    "__proto__ key",
    jsonText(
      `{"version":"${OWNER_ECDSA.version}","kind":"ecdsa","address":"${OWNER_ECDSA.address}","__proto__":{}}`,
    ),
  );
}
shapeCases("parseOwnerCredentialProfile", "ecdsa", OWNER_ECDSA);
shapeCases("parseOwnerCredentialProfile", "webauthn", OWNER_WEBAUTHN);
shapeCases("hashOwnerCredentialProfile", "p256", OWNER_P256, [], { types: false });

{
  const fn = "parseOperatorCredentialProfile";
  record(fn, "ecdsa", OPERATOR_ECDSA);
  record(fn, "webauthn", OPERATOR_WEBAUTHN);
  record(fn, "p256 is not an operator kind", { ...OWNER_P256, version: OPERATOR_ECDSA.version });
  record(fn, "owner version", set(OPERATOR_ECDSA, ["version"], OWNER_ECDSA.version));
  addressCases(fn, "ecdsa address", OPERATOR_ECDSA, ["address"]);
  publicKeyCases(fn, "webauthn publicKey", OPERATOR_WEBAUTHN, ["publicKey"]);
  shapeCases(fn, "ecdsa", OPERATOR_ECDSA);
  shapeCases(fn, "webauthn", OPERATOR_WEBAUTHN);
}

const DERIVED_ACCOUNT = {
  version: "oaath.kernel-account-profile/v1",
  kind: "kernel",
  accountIndex: "7",
  kernelVersion: "0.4.0",
  factoryRoute: "meta_factory",
  entryPoint: { version: "0.9" },
  ownerCredential: OWNER_ECDSA,
};
const EXISTING_ACCOUNT = {
  version: "oaath.kernel-existing-account-profile/v3",
  kind: "kernel",
  kernelVersion: "0.3.3",
  address: hex("66", 20),
  entryPoint: { version: "0.7" },
  ownerCredential: OWNER_ECDSA,
};
const EXISTING_WEBAUTHN_ACCOUNT = {
  ...EXISTING_ACCOUNT,
  kernelVersion: "0.4.0",
  entryPoint: { version: "0.9" },
  ownerCredential: OWNER_WEBAUTHN,
};

{
  const fn = "parseKernelAccountProfile";
  record(fn, "derived meta factory ecdsa", DERIVED_ACCOUNT);
  record(fn, "derived kernel factory p256", {
    ...DERIVED_ACCOUNT,
    factoryRoute: "kernel_factory",
    ownerCredential: OWNER_P256,
  });
  record(fn, "derived webauthn", { ...DERIVED_ACCOUNT, ownerCredential: OWNER_WEBAUTHN });
  record(fn, "derived unknown factory", { ...DERIVED_ACCOUNT, factoryRoute: "factory" });
  record(fn, "derived kernel 0.3.3", {
    ...DERIVED_ACCOUNT,
    kernelVersion: "0.3.3",
    entryPoint: { version: "0.7" },
  });
  record(fn, "derived entryPoint 0.7", { ...DERIVED_ACCOUNT, entryPoint: { version: "0.7" } });
  record(fn, "derived entryPoint extra key", {
    ...DERIVED_ACCOUNT,
    entryPoint: { version: "0.9", address: hex("11", 20) },
  });
  for (const [label, index] of [
    ["zero", "0"],
    ["max uint256", MAX_UINT256],
    ["max uint256 + 1", (2n ** 256n).toString()],
    ["leading zero", "07"],
    ["negative", "-1"],
    ["79 digits", "1".repeat(79)],
    ["hex", "0x7"],
    ["empty", ""],
    ["number", 7],
  ]) {
    record(fn, `accountIndex ${label}`, { ...DERIVED_ACCOUNT, accountIndex: index });
  }
  record(fn, "existing 0.3.3 ecdsa", EXISTING_ACCOUNT);
  record(fn, "existing 0.4.0 ecdsa", {
    ...EXISTING_ACCOUNT,
    kernelVersion: "0.4.0",
    entryPoint: { version: "0.9" },
  });
  record(fn, "existing 0.4.0 p256", {
    ...EXISTING_ACCOUNT,
    kernelVersion: "0.4.0",
    entryPoint: { version: "0.9" },
    ownerCredential: OWNER_P256,
  });
  record(fn, "existing 0.3.3 p256", { ...EXISTING_ACCOUNT, ownerCredential: OWNER_P256 });
  record(fn, "existing 0.4.0 webauthn", {
    ...EXISTING_ACCOUNT,
    kernelVersion: "0.4.0",
    entryPoint: { version: "0.9" },
    ownerCredential: OWNER_WEBAUTHN,
  });
  record(fn, "existing 0.3.3 webauthn", { ...EXISTING_ACCOUNT, ownerCredential: OWNER_WEBAUTHN });
  record(fn, "existing 0.4.0 webauthn checksummed address", {
    ...EXISTING_WEBAUTHN_ACCOUNT,
    address: checksum(MIXED_ADDRESS),
  });
  record(fn, "existing 0.4.0 webauthn invalid authenticatorIdHash", {
    ...EXISTING_WEBAUTHN_ACCOUNT,
    ownerCredential: { ...OWNER_WEBAUTHN, authenticatorIdHash: hex("AB", 32) },
  });
  record(fn, "existing 0.3.3 entryPoint 0.9", {
    ...EXISTING_ACCOUNT,
    entryPoint: { version: "0.9" },
  });
  record(fn, "existing kernel 0.3.1", { ...EXISTING_ACCOUNT, kernelVersion: "0.3.1" });
  record(fn, "existing with derived fields", {
    ...EXISTING_ACCOUNT,
    accountIndex: "0",
    factoryRoute: "meta_factory",
  });
  record(fn, "derived with address", { ...DERIVED_ACCOUNT, address: hex("66", 20) });
  record(fn, "derived version with existing fields", {
    ...EXISTING_ACCOUNT,
    version: DERIVED_ACCOUNT.version,
  });
  record(fn, "kind safe", { ...DERIVED_ACCOUNT, kind: "safe" });
  record(fn, "invalid owner credential", {
    ...DERIVED_ACCOUNT,
    ownerCredential: { ...OWNER_ECDSA, address: ZERO_ADDRESS },
  });
  addressCases(fn, "existing address", EXISTING_ACCOUNT, ["address"]);
  shapeCases(fn, "derived", DERIVED_ACCOUNT);
  shapeCases(fn, "existing", EXISTING_ACCOUNT);
  shapeCases(fn, "derived entryPoint", DERIVED_ACCOUNT, ["entryPoint"], { types: false });
}

// --------------------------------------------------------------- grant policy

const POLICY = {
  version: "oaath.grant-policy/v2",
  calls: [
    {
      target: hex("11", 20),
      selector: "0x12345678",
      valueLimit: "100",
      argumentEquals: [
        { index: 0, value: hex("33", 32) },
        { index: 2, value: hex("44", 32) },
      ],
    },
    { target: hex("22", 20), selector: "0xabcdef01", valueLimit: "0", argumentEquals: [] },
  ],
  validAfter: 100,
  validUntil: 190,
  perChainOperationLimit: { count: 10, intervalSeconds: null },
};

function policyNumberCases(fn, label, base, path, extra = []) {
  for (const [name, value] of [
    ["-0", raw("-0")],
    ["-0.0", raw("-0.0")],
    ["-0e0", raw("-0e0")],
    ["1.0", raw("1.0")],
    ["1e2", raw("1e2")],
    ["1E2", raw("1E2")],
    ["100.000000000000000001", raw("100.000000000000000001")],
    ["0.5", raw("0.5")],
    ["-1", -1],
    ["2^48 - 1", MAX_UINT48],
    ["2^48", MAX_UINT48 + 1],
    ["2^53 - 1", MAX_SAFE],
    ["2^53", raw("9007199254740992")],
    ["2^53 + 1 text", raw("9007199254740993")],
    ["1e400", raw("1e400")],
    ["string", "100"],
    ...extra,
  ]) {
    record(fn, `${label} ${name}`, set(base, path, value));
  }
}

for (const fn of ["parseGrantPolicy", "hashGrantPolicy"]) {
  record(fn, "two calls with argument equality", POLICY);
  record(fn, "indefinite validUntil", { ...POLICY, validUntil: null });
  record(fn, "windowed limit", {
    ...POLICY,
    perChainOperationLimit: { count: 3, intervalSeconds: 3600 },
  });
  record(fn, "max uint256 valueLimit", set(POLICY, ["calls", 1, "valueLimit"], MAX_UINT256));
  record(
    fn,
    "argument index at maximum",
    set(POLICY, ["calls", 0, "argumentEquals", 1, "index"], Math.floor(MAX_SAFE / 32)),
  );
  record(fn, "validAfter equals validUntil", { ...POLICY, validAfter: 190 });
  record(fn, "validAfter written 1.0e2", { ...POLICY, validAfter: raw("1.0e2") });
}
{
  const fn = "parseGrantPolicy";
  record(fn, "version v1", { ...POLICY, version: "oaath.grant-policy/v1" });
  record(fn, "empty calls", { ...POLICY, calls: [] });
  record(fn, "unsorted calls", { ...POLICY, calls: [POLICY.calls[1], POLICY.calls[0]] });
  record(fn, "duplicate calls", { ...POLICY, calls: [POLICY.calls[1], POLICY.calls[1]] });
  record(fn, "same target different selectors sorted", {
    ...POLICY,
    calls: [POLICY.calls[0], { ...POLICY.calls[0], selector: "0x12345679" }],
  });
  record(fn, "same target different selectors unsorted", {
    ...POLICY,
    calls: [{ ...POLICY.calls[0], selector: "0x12345679" }, POLICY.calls[0]],
  });
  record(fn, "inverted window", { ...POLICY, validAfter: 191 });
  record(
    fn,
    "argument indexes unsorted",
    set(POLICY, ["calls", 0, "argumentEquals"], [...POLICY.calls[0].argumentEquals].reverse()),
  );
  record(
    fn,
    "argument indexes duplicate",
    set(POLICY, ["calls", 0, "argumentEquals", 1, "index"], 0),
  );
  record(
    fn,
    "argument index above maximum",
    set(POLICY, ["calls", 0, "argumentEquals", 1, "index"], Math.floor(MAX_SAFE / 32) + 1),
  );
  record(
    fn,
    "argument index -0",
    set(POLICY, ["calls", 0, "argumentEquals", 0, "index"], raw("-0")),
  );
  record(
    fn,
    "argument index 0.0",
    set(POLICY, ["calls", 0, "argumentEquals", 0, "index"], raw("0.0")),
  );
  record(
    fn,
    "argument value uppercase",
    set(POLICY, ["calls", 0, "argumentEquals", 0, "value"], hex("AB", 32)),
  );
  record(
    fn,
    "argument value 31 bytes",
    set(POLICY, ["calls", 0, "argumentEquals", 0, "value"], hex("33", 31)),
  );
  record(fn, "target zero", set(POLICY, ["calls", 0, "target"], ZERO_ADDRESS));
  record(fn, "target checksummed", set(POLICY, ["calls", 0, "target"], checksum(MIXED_ADDRESS)));
  addressCases(fn, "single-call target", { ...POLICY, calls: [POLICY.calls[0]] }, [
    "calls",
    0,
    "target",
  ]);
  record(fn, "selector zero", set(POLICY, ["calls", 0, "selector"], "0x00000000"));
  record(fn, "selector uppercase", set(POLICY, ["calls", 0, "selector"], "0xABCDEF01"));
  record(fn, "selector 3 bytes", set(POLICY, ["calls", 0, "selector"], "0x123456"));
  for (const [label, value] of [
    ["leading zero", "0100"],
    ["max + 1", (2n ** 256n).toString()],
    ["negative", "-1"],
    ["number", 100],
    ["hex", "0x64"],
    ["79 digits", "1".repeat(79)],
  ]) {
    record(fn, `valueLimit ${label}`, set(POLICY, ["calls", 0, "valueLimit"], value));
  }
  policyNumberCases(fn, "validAfter", POLICY, ["validAfter"]);
  policyNumberCases(
    fn,
    "validUntil",
    { ...POLICY, validAfter: 0 },
    ["validUntil"],
    [
      ["0", 0],
      ["1", 1],
    ],
  );
  policyNumberCases(fn, "count", POLICY, ["perChainOperationLimit", "count"], [["0", 0]]);
  policyNumberCases(
    fn,
    "intervalSeconds",
    POLICY,
    ["perChainOperationLimit", "intervalSeconds"],
    [["0", 0]],
  );
  shapeCases(fn, "policy", POLICY);
  shapeCases(fn, "call", POLICY, ["calls", 0]);
  shapeCases(fn, "argument", POLICY, ["calls", 0, "argumentEquals", 0]);
  shapeCases(fn, "limit", POLICY, ["perChainOperationLimit"]);
}
{
  const fn = "hashGrantPolicy";
  record(fn, "empty calls", { ...POLICY, calls: [] });
  record(fn, "validUntil -0", { ...POLICY, validUntil: raw("-0") });
  shapeCases(fn, "policy", POLICY, [], { types: false });
}
{
  const fn = "hashGrantPolicyCalls";
  record(fn, "policy calls", POLICY.calls);
  record(fn, "single call", [POLICY.calls[1]]);
  record(
    fn,
    "argument index 1.0",
    set(POLICY.calls, [0, "argumentEquals", 0, "index"], raw("1.0")),
  );
  record(fn, "empty", []);
  record(fn, "unsorted", [POLICY.calls[1], POLICY.calls[0]]);
  record(fn, "object", POLICY);
  record(fn, "null", null);
  record(fn, "call with unknown key", set(POLICY.calls, [0, "unexpected"], true));
  record(fn, "call value limit invalid", set(POLICY.calls, [0, "valueLimit"], "01"));
}
{
  const fn = "isGrantPolicyAttenuation";
  const pair = (approved, requested = POLICY) => ({ requested, approved });
  record(fn, "identical", pair(POLICY));
  record(fn, "lower value limit", pair(set(POLICY, ["calls", 0, "valueLimit"], "99")));
  record(fn, "higher value limit", pair(set(POLICY, ["calls", 0, "valueLimit"], "101")));
  record(fn, "subset of calls", pair({ ...POLICY, calls: [POLICY.calls[0]] }));
  record(fn, "extra call", pair(POLICY, { ...POLICY, calls: [POLICY.calls[0]] }));
  record(
    fn,
    "different selector",
    pair({ ...POLICY, calls: [{ ...POLICY.calls[0], selector: "0x12345679" }] }),
  );
  record(
    fn,
    "added argument equality",
    pair(set(POLICY, ["calls", 1, "argumentEquals"], [{ index: 5, value: hex("66", 32) }])),
  );
  record(
    fn,
    "dropped argument equality",
    pair(set(POLICY, ["calls", 0, "argumentEquals"], [POLICY.calls[0].argumentEquals[0]])),
  );
  record(
    fn,
    "changed argument equality",
    pair(set(POLICY, ["calls", 0, "argumentEquals", 0, "value"], hex("77", 32))),
  );
  record(fn, "later validAfter", pair({ ...POLICY, validAfter: 150 }));
  record(fn, "earlier validAfter", pair({ ...POLICY, validAfter: 99 }));
  record(fn, "earlier validUntil", pair({ ...POLICY, validUntil: 150 }));
  record(fn, "later validUntil", pair({ ...POLICY, validUntil: 191 }));
  record(fn, "indefinite approval of finite request", pair({ ...POLICY, validUntil: null }));
  record(
    fn,
    "finite approval of indefinite request",
    pair(POLICY, { ...POLICY, validUntil: null }),
  );
  record(
    fn,
    "lower count",
    pair({ ...POLICY, perChainOperationLimit: { count: 1, intervalSeconds: null } }),
  );
  record(
    fn,
    "higher count",
    pair({ ...POLICY, perChainOperationLimit: { count: 11, intervalSeconds: null } }),
  );
  record(
    fn,
    "window added",
    pair({ ...POLICY, perChainOperationLimit: { count: 10, intervalSeconds: 60 } }),
  );
  record(
    fn,
    "window removed",
    pair(
      { ...POLICY, perChainOperationLimit: { count: 10, intervalSeconds: null } },
      { ...POLICY, perChainOperationLimit: { count: 10, intervalSeconds: 60 } },
    ),
  );
  record(
    fn,
    "window lengthened",
    pair(
      { ...POLICY, perChainOperationLimit: { count: 10, intervalSeconds: 120 } },
      { ...POLICY, perChainOperationLimit: { count: 10, intervalSeconds: 60 } },
    ),
  );
  record(fn, "invalid approved", pair({ ...POLICY, calls: [] }));
  record(fn, "invalid requested", pair(POLICY, { ...POLICY, version: "x" }));
  record(fn, "approved -0 validAfter", pair({ ...POLICY, validAfter: raw("-0") }));
}

// --------------------------------------------------- workspace and bootstrap

const CONTEXT = {
  version: "oaath.workspace-account-context/v1",
  workspaceId: "personal-1",
  workspaceKind: "personal",
  accountId: "account-1",
};

function identifierCases(fn, label, base, path) {
  for (const [name, value] of [
    ["64 characters", `a${"b".repeat(63)}`],
    ["65 characters", `a${"b".repeat(64)}`],
    ["uppercase", "Account-1"],
    ["leading hyphen", "-account"],
    ["leading dot", ".account"],
    ["digit first", "1account"],
    ["underscore and dot", "a_b.c-d"],
    ["tilde", "a~b"],
    ["space", "a b"],
    ["empty", ""],
    ["trailing newline", "account\n"],
  ]) {
    record(fn, `${label} ${name}`, set(base, path, value));
  }
}

{
  const fn = "parseWorkspaceAccountContext";
  record(fn, "personal", CONTEXT);
  record(fn, "team", { ...CONTEXT, workspaceKind: "team" });
  record(fn, "organization kind", { ...CONTEXT, workspaceKind: "organization" });
  record(fn, "version v2", { ...CONTEXT, version: "oaath.workspace-account-context/v2" });
  identifierCases(fn, "workspaceId", CONTEXT, ["workspaceId"]);
  identifierCases(fn, "accountId", CONTEXT, ["accountId"]);
  shapeCases(fn, "context", CONTEXT);
}

// ----------------------------------------------------- permission protocol

const REQUEST = {
  version: "oaath.permission-request/v2",
  requestId: "permission-request-1",
  context: CONTEXT,
  application: {
    applicationId: "oaath-tests",
    clientId: "permission-protocol",
    origin: "https://request.example",
    deviceId: "request-device",
  },
  chainScope: "all",
  logicalAccount: DERIVED_ACCOUNT,
  operatorCredential: OPERATOR_ECDSA,
  policy: { ...POLICY, perChainOperationLimit: { count: 10, intervalSeconds: null } },
  requestedAt: 100,
  expiresAt: 200,
  sessionSigner: null,
};
const REQUEST_VARIANTS = [
  ["frontend derived ecdsa", REQUEST],
  [
    "existing account webauthn operator",
    { ...REQUEST, logicalAccount: EXISTING_ACCOUNT, operatorCredential: OPERATOR_WEBAUTHN },
  ],
  [
    "p256 owner application backend",
    {
      ...REQUEST,
      logicalAccount: {
        ...DERIVED_ACCOUNT,
        ownerCredential: OWNER_P256,
        accountIndex: MAX_UINT256,
      },
      sessionSigner: { mode: "application_backend", providerId: "backend-kms" },
    },
  ],
  [
    "webauthn owner oaath hosted team",
    {
      ...REQUEST,
      context: { ...CONTEXT, workspaceKind: "team" },
      logicalAccount: { ...DERIVED_ACCOUNT, ownerCredential: OWNER_WEBAUTHN },
      sessionSigner: { mode: "oaath_hosted", providerId: "\u{1f511} hosted" },
    },
  ],
  [
    "existing 0.4.0 p256 windowed",
    {
      ...REQUEST,
      logicalAccount: {
        ...EXISTING_ACCOUNT,
        kernelVersion: "0.4.0",
        entryPoint: { version: "0.9" },
        ownerCredential: OWNER_P256,
      },
      policy: { ...REQUEST.policy, perChainOperationLimit: { count: 2, intervalSeconds: 86_400 } },
    },
  ],
  ["existing 0.4.0 webauthn owner", { ...REQUEST, logicalAccount: EXISTING_WEBAUTHN_ACCOUNT }],
];

for (const fn of ["parsePermissionRequest", "hashPermissionRequest"]) {
  for (const [label, request] of REQUEST_VARIANTS) record(fn, label, request);
  const origin = (value) => set(REQUEST, ["application", "origin"], value);
  for (const [label, value] of [
    ["uppercase host", "https://Request.Example"],
    ["default port", "https://request.example:443"],
    ["root slash", "https://request.example/"],
    ["http port", "http://request.example:8080"],
    ["http default port", "http://request.example:80"],
    ["path", "https://request.example/app"],
    ["query", "https://request.example/?q=1"],
    ["empty query", "https://request.example?"],
    ["empty fragment", "https://request.example#"],
    ["fragment", "https://request.example#x"],
    ["credentials", "https://user@request.example"],
    ["empty credentials", "https://@request.example"],
    ["empty password", "https://:@request.example"],
    ["surrounding spaces", "  https://request.example  "],
    ["embedded newline", "https://request.\nexample"],
    ["unicode host", "https://réquest.example"],
    ["ipv4 decimal", "http://2130706433"],
    ["ipv6", "https://[::1]:8443"],
    ["ftp", "ftp://request.example"],
    ["wss", "wss://request.example"],
    ["file", "file:///tmp"],
    ["no scheme", "request.example"],
    ["2049 characters", `https://${"a".repeat(2041)}`],
  ]) {
    record(fn, `origin ${label}`, origin(value));
  }
  const requestId = (value) => ({ ...REQUEST, requestId: value });
  for (const [label, value] of [
    ["256 units", "r".repeat(256)],
    ["257 units", "r".repeat(257)],
    ["surrogate pairs at 256 units", "\u{1f600}".repeat(128)],
    ["surrogate pairs at 258 units", "\u{1f600}".repeat(129)],
    ["leading space", " request"],
    ["trailing tab", "request\t"],
    ["trailing NEL (not JavaScript whitespace)", "request\u0085"],
    ["leading BOM (JavaScript whitespace)", "\uFEFFrequest"],
    ["trailing ideographic space", "request\u3000"],
    ["trailing line separator", "request\u2028"],
    ["trailing narrow no-break space", "request\u202F"],
    ["trailing zero width space (not whitespace)", "request\u200B"],
    ["inner spaces", "a request id"],
    ["empty", ""],
  ]) {
    record(fn, `requestId ${label}`, requestId(value));
  }
}
{
  const fn = "parsePermissionRequest";
  record(fn, "version v1", { ...REQUEST, version: "oaath.permission-request/v1" });
  record(fn, "chainScope one", { ...REQUEST, chainScope: "1" });
  record(fn, "expiresAt equals requestedAt", { ...REQUEST, expiresAt: 100 });
  record(fn, "policy validUntil null", set(REQUEST, ["policy", "validUntil"], null));
  record(fn, "policy validUntil equals requestedAt", {
    ...REQUEST,
    policy: { ...REQUEST.policy, validAfter: 0, validUntil: 100 },
  });
  record(fn, "policy validUntil before requestedAt", {
    ...REQUEST,
    policy: { ...REQUEST.policy, validAfter: 0, validUntil: 99 },
  });
  record(fn, "policy validUntil equals expiresAt", set(REQUEST, ["policy", "validUntil"], 200));
  record(fn, "policy invalid", set(REQUEST, ["policy", "calls"], []));
  record(fn, "operator p256", {
    ...REQUEST,
    operatorCredential: { ...OWNER_P256, version: OPERATOR_ECDSA.version },
  });
  record(fn, "context invalid", set(REQUEST, ["context", "accountId"], "Account"));
  for (const [label, value] of [
    ["frontend object", { mode: "frontend", providerId: "x" }],
    ["empty provider", { mode: "application_backend", providerId: "" }],
    ["257 provider", { mode: "application_backend", providerId: "p".repeat(257) }],
    ["null provider", { mode: "oaath_hosted", providerId: null }],
    ["extra key", { mode: "oaath_hosted", providerId: "x", region: "eu" }],
  ]) {
    record(fn, `sessionSigner ${label}`, { ...REQUEST, sessionSigner: value });
  }
  for (const [label, path] of [
    ["requestedAt", ["requestedAt"]],
    ["expiresAt", ["expiresAt"]],
  ]) {
    for (const [name, value] of [
      ["-0", raw("-0")],
      ["1e2", raw("1e2")],
      ["2^48", MAX_UINT48 + 1],
      ["negative", -1],
      ["fraction", raw("150.5")],
    ]) {
      record(fn, `${label} ${name}`, set(REQUEST, path, value));
    }
  }
  record(fn, "requestedAt 100.0 and expiresAt 2e2", {
    ...REQUEST,
    requestedAt: raw("100.0"),
    expiresAt: raw("2e2"),
  });
  record(fn, "expiresAt 2^48 - 1", { ...REQUEST, expiresAt: MAX_UINT48 });
  identifierCases(fn, "application deviceId", REQUEST, ["application", "deviceId"]);
  shapeCases(fn, "request", REQUEST);
  shapeCases(fn, "application", REQUEST, ["application"]);
}

const REQUEST_HASH = P.hashPermissionRequest(REQUEST);
const CAPABILITY_HASH = hex("55", 32);
const APPROVE = {
  version: "oaath.permission-decision/v1",
  kind: "approve",
  requestId: REQUEST.requestId,
  requestHash: REQUEST_HASH,
  decidedAt: 120,
  approvedPolicy: REQUEST.policy,
  capabilityHash: CAPABILITY_HASH,
};
const REJECT = {
  version: "oaath.permission-decision/v1",
  kind: "reject",
  requestId: REQUEST.requestId,
  requestHash: REQUEST_HASH,
  decidedAt: 120,
};

for (const fn of ["parsePermissionDecision", "hashPermissionDecision"]) {
  record(fn, "approve", APPROVE);
  record(fn, "reject", REJECT);
  record(
    fn,
    "approve narrowed policy",
    set(APPROVE, ["approvedPolicy", "calls"], [POLICY.calls[1]]),
  );
  record(fn, "approve zero requestHash", { ...APPROVE, requestHash: ZERO_HASH });
  record(fn, "approve zero capabilityHash", { ...APPROVE, capabilityHash: ZERO_HASH });
  record(fn, "reject decidedAt 1e2", { ...REJECT, decidedAt: raw("1e2") });
  record(fn, "reject decidedAt -0", { ...REJECT, decidedAt: raw("-0") });
  record(fn, "reject with approve fields", {
    ...REJECT,
    approvedPolicy: POLICY,
    capabilityHash: CAPABILITY_HASH,
  });
  record(fn, "approve without approve fields", { ...REJECT, kind: "approve" });
}
{
  const fn = "parsePermissionDecision";
  record(fn, "unknown kind", { ...REJECT, kind: "defer" });
  record(fn, "version v2", { ...APPROVE, version: "oaath.permission-decision/v2" });
  record(fn, "invalid approved policy", set(APPROVE, ["approvedPolicy", "version"], "x"));
  record(fn, "uppercase requestHash", { ...APPROVE, requestHash: hex("AB", 32) });
  record(fn, "uppercase capabilityHash", { ...APPROVE, capabilityHash: hex("AB", 32) });
  record(fn, "requestId with trailing space", { ...APPROVE, requestId: "permission-request-1 " });
  for (const [name, value] of [
    ["0", 0],
    ["2^48 - 1", MAX_UINT48],
    ["2^48", MAX_UINT48 + 1],
    ["1.5", raw("1.5")],
    ["string", "120"],
  ]) {
    record(fn, `decidedAt ${name}`, { ...APPROVE, decidedAt: value });
  }
  shapeCases(fn, "approve", APPROVE);
  shapeCases(fn, "reject", REJECT);
}

{
  const fn = "parseApprovedPermission";
  const approved = (plaintext, relayDecidedAt = 120_000, request = REQUEST) => ({
    plaintext,
    request,
    relayDecidedAt,
  });
  const text = (decision) => stringify(decision);
  record(fn, "approve at relay time", approved(text(APPROVE)));
  record(
    fn,
    "approve with install approval",
    approved(text({ ...APPROVE, installApproval: { version: "x", signature: "0x00" } })),
  );
  record(
    fn,
    "approve with null install approval",
    approved(text({ ...APPROVE, installApproval: null })),
  );
  record(fn, "relay time floors to decision second", approved(text(APPROVE), 120_999));
  record(fn, "relay time before decision", approved(text(APPROVE), 119_999));
  record(fn, "relay time long after", approved(text(APPROVE), 9_000_000_000));
  record(fn, "decidedAt equals requestedAt", approved(text({ ...APPROVE, decidedAt: 100 })));
  record(fn, "decidedAt before requestedAt", approved(text({ ...APPROVE, decidedAt: 99 })));
  record(fn, "decidedAt at expiresAt", approved(text({ ...APPROVE, decidedAt: 200 }), 300_000));
  record(
    fn,
    "decidedAt after policy validUntil",
    approved(text({ ...APPROVE, decidedAt: 191 }), 300_000),
  );
  record(
    fn,
    "decidedAt after narrowed validUntil",
    approved(text({ ...APPROVE, approvedPolicy: { ...APPROVE.approvedPolicy, validUntil: 110 } })),
  );
  record(
    fn,
    "decidedAt at narrowed validUntil",
    approved(text({ ...APPROVE, approvedPolicy: { ...APPROVE.approvedPolicy, validUntil: 120 } })),
  );
  record(fn, "decidedAt 1.2e2", approved(text({ ...APPROVE, decidedAt: raw("1.2e2") })));
  record(fn, "decidedAt -0", approved(text({ ...APPROVE, decidedAt: raw("-0") })));
  record(
    fn,
    "decidedAt -0 overwritten by duplicate",
    approved(text(APPROVE).replace('"decidedAt":120', '"decidedAt":-0,"decidedAt":120')),
  );
  record(
    fn,
    "decidedAt 120 overwritten by -0",
    approved(text(APPROVE).replace('"decidedAt":120', '"decidedAt":120,"decidedAt":-0')),
  );
  record(
    fn,
    "install approval holding -0",
    approved(text({ ...APPROVE, installApproval: { nonce: raw("-0") } })),
  );
  record(fn, "reject decision", approved(text(REJECT)));
  record(fn, "other requestId", approved(text({ ...APPROVE, requestId: "permission-request-2" })));
  record(fn, "other requestHash", approved(text({ ...APPROVE, requestHash: hex("66", 32) })));
  record(
    fn,
    "widened value limit",
    approved(text(set(APPROVE, ["approvedPolicy", "calls", 0, "valueLimit"], "101"))),
  );
  record(
    fn,
    "widened validUntil",
    approved(text(set(APPROVE, ["approvedPolicy", "validUntil"], 195))),
  );
  record(
    fn,
    "narrowed calls",
    approved(text(set(APPROVE, ["approvedPolicy", "calls"], [POLICY.calls[0]]))),
  );
  record(
    fn,
    "narrowed count",
    approved(text(set(APPROVE, ["approvedPolicy", "perChainOperationLimit", "count"], 1))),
  );
  record(
    fn,
    "changed window",
    approved(
      text(set(APPROVE, ["approvedPolicy", "perChainOperationLimit", "intervalSeconds"], 60)),
    ),
  );
  record(fn, "invalid decision", approved(text({ ...APPROVE, capabilityHash: ZERO_HASH })));
  record(fn, "unknown key", approved(text({ ...APPROVE, note: "x" })));
  record(
    fn,
    "duplicate kind last wins approve",
    approved(text(APPROVE).replace('"kind":"approve"', '"kind":"reject","kind":"approve"')),
  );
  record(
    fn,
    "duplicate kind last wins reject",
    approved(text(APPROVE).replace('"kind":"approve"', '"kind":"approve","kind":"reject"')),
  );
  record(fn, "surrounding whitespace", approved(`\n\t ${text(APPROVE)} \r\n`));
  record(fn, "escaped key", approved(text(APPROVE).replace('"kind"', '"\\u006bind"')));
  for (const [label, plaintext] of [
    ["empty", ""],
    ["truncated", text(APPROVE).slice(0, -1)],
    ["trailing comma", `${text(APPROVE).slice(0, -1)},}`],
    ["trailing garbage", `${text(APPROVE)}x`],
    ["leading BOM", `\uFEFF${text(APPROVE)}`],
    ["single quotes", "{'kind':'approve'}"],
    ["null", "null"],
    ["array", `[${text(APPROVE)}]`],
    ["string", JSON.stringify(text(APPROVE))],
    ["number", "120"],
  ]) {
    record(fn, `plaintext ${label}`, approved(plaintext));
  }
  const existing = REQUEST_VARIANTS[1][1];
  const existingApproval = { ...APPROVE, requestHash: P.hashPermissionRequest(existing) };
  record(fn, "existing account request", approved(text(existingApproval), 120_000, existing));
  record(fn, "decision for another request", approved(text(APPROVE), 120_000, existing));
  const webauthn = { ...REQUEST, logicalAccount: EXISTING_WEBAUTHN_ACCOUNT };
  const webauthnApproval = { ...APPROVE, requestHash: P.hashPermissionRequest(webauthn) };
  record(
    fn,
    "existing webauthn account request",
    approved(text(webauthnApproval), 120_000, webauthn),
  );
}

// ------------------------------------------------------ owner signing request

const MAIL_REQUEST = GOLDEN.ownerSigningRequest.scope.request;
const RAW_REQUEST = GOLDEN.rawDigestOwnerSigningRequest.scope.request;
const GOLDEN_KERNEL = GOLDEN.kernelEnableOwnerSigningRequest.scope.request;
const KERNEL_ACCOUNT = hex("66", 20);

function kernelRequest({
  account = KERNEL_ACCOUNT,
  nonce = "0",
  packages,
  ownerCredential = OWNER_P256,
}) {
  const typedData = JSON.parse(
    JSON.stringify(
      P.createKernelReplayableInstallTypedData({ account, nonce, packages: clone(packages) }),
    ),
  );
  return {
    version: "oaath.owner-signing-request/v1",
    kind: "eip712",
    purpose: "kernel-enable",
    signer: { account, ownerCredential },
    typedData,
    expectedDigest: P.hashCanonicalEip712TypedData(typedData),
    replay: { nonce, deadline: null },
  };
}

const GOLDEN_PACKAGES = GOLDEN_KERNEL.typedData.message.packages.map((install) => ({
  ...install,
  moduleType: Number(install.moduleType),
}));
const KERNEL_REQUEST = kernelRequest({ nonce: "7", packages: GOLDEN_PACKAGES });
const SIMPLE_PACKAGE = {
  moduleType: 1,
  module: hex("77", 20),
  moduleData: "0x",
  internalData: "0x",
};

/** Recomputes the digest so only the mutated fact differs. */
function rehash(request) {
  try {
    return { ...request, expectedDigest: P.hashCanonicalEip712TypedData(request.typedData) };
  } catch {
    return request;
  }
}

function typed(base, change) {
  return rehash(edit(base, (request) => change(request.typedData)));
}

{
  for (const fn of ["parseOwnerSigningRequest", "hashOwnerSigningRequest"]) {
    record(fn, "golden mail", MAIL_REQUEST);
    record(fn, "golden raw digest", RAW_REQUEST);
    record(fn, "golden kernel enable", GOLDEN_KERNEL);
    record(fn, "fixture kernel enable", KERNEL_REQUEST);
    record(
      fn,
      "mail with ecdsa owner",
      set(MAIL_REQUEST, ["signer", "ownerCredential"], OWNER_ECDSA),
    );
    record(
      fn,
      "mail with webauthn owner",
      set(MAIL_REQUEST, ["signer", "ownerCredential"], OWNER_WEBAUTHN),
    );
    record(
      fn,
      "mail with deadline",
      set(MAIL_REQUEST, ["replay"], { nonce: null, deadline: MAX_UINT256 }),
    );
    record(
      fn,
      "mail primaryType uint",
      typed(MAIL_REQUEST, (data) => {
        data.types.uint = [{ name: "value", type: "uint256" }];
        delete data.types.Mail;
        delete data.types.Person;
        data.primaryType = "uint";
        data.message = { value: "1" };
      }),
    );
    record(
      fn,
      "mail primaryType bytes33",
      typed(MAIL_REQUEST, (data) => {
        data.types.bytes33 = [{ name: "value", type: "uint256" }];
        delete data.types.Mail;
        delete data.types.Person;
        data.primaryType = "bytes33";
        data.message = { value: "1" };
      }),
    );
    record(fn, "raw digest reason with emoji", { ...RAW_REQUEST, reason: "\u{1f510} sign" });
  }
  const fn = "parseOwnerSigningRequest";
  record(fn, "raw digest reason 256", { ...RAW_REQUEST, reason: "r".repeat(256) });
  record(fn, "raw digest reason 257", { ...RAW_REQUEST, reason: "r".repeat(257) });
  record(fn, "raw digest reason empty", { ...RAW_REQUEST, reason: "" });
  record(fn, "raw digest reason bell", { ...RAW_REQUEST, reason: "a\u0007b" });
  record(fn, "raw digest reason delete", { ...RAW_REQUEST, reason: "a\u007fb" });
  record(fn, "raw digest reason C1 control", { ...RAW_REQUEST, reason: "a\u0085b" });
  record(fn, "raw digest reason surrogate pairs 128", {
    ...RAW_REQUEST,
    reason: "\u{1f600}".repeat(128),
  });
  record(fn, "raw digest reason surrogate pairs 129", {
    ...RAW_REQUEST,
    reason: "\u{1f600}".repeat(129),
  });
  record(fn, "raw digest decision approve", { ...RAW_REQUEST, decision: "approve-or-reject" });
  record(fn, "raw digest uppercase digest", { ...RAW_REQUEST, digest: hex("AB", 32) });
  shapeCases(fn, "raw digest", RAW_REQUEST);
  shapeCases(fn, "mail", MAIL_REQUEST);
  shapeCases(fn, "mail signer", MAIL_REQUEST, ["signer"]);
  shapeCases(fn, "mail replay", MAIL_REQUEST, ["replay"], { types: false });
  shapeCases(fn, "mail typedData", MAIL_REQUEST, ["typedData"], { types: false });
  for (const purpose of ["permit", "permit2", "application", "kernel-enable", "transfer"]) {
    record(fn, `purpose ${purpose}`, { ...MAIL_REQUEST, purpose });
  }
  record(fn, "kind raw", { ...MAIL_REQUEST, kind: "raw" });
  record(fn, "signer zero account", set(MAIL_REQUEST, ["signer", "account"], ZERO_ADDRESS));
  record(
    fn,
    "signer checksummed account",
    set(MAIL_REQUEST, ["signer", "account"], checksum(MIXED_ADDRESS)),
  );
  record(
    fn,
    "signer invalid owner",
    set(MAIL_REQUEST, ["signer", "ownerCredential", "kind"], "rsa"),
  );
  record(fn, "expectedDigest uppercase", { ...MAIL_REQUEST, expectedDigest: hex("AB", 32) });
  for (const [label, value] of [
    ["max", MAX_UINT256],
    ["max + 1", (2n ** 256n).toString()],
    ["leading zero", "01"],
    ["79 digits", "1".repeat(79)],
    ["negative", "-1"],
    ["number", 0],
  ]) {
    record(fn, `replay nonce ${label}`, set(MAIL_REQUEST, ["replay", "nonce"], value));
  }

  const mail = (change) => typed(MAIL_REQUEST, change);
  const field = (name, type) => ({ name, type });
  record(
    fn,
    "types without domain",
    mail((data) => {
      delete data.types.EIP712Domain;
    }),
  );
  record(
    fn,
    "unreferenced struct",
    mail((data) => {
      data.types.Extra = [field("x", "uint256")];
    }),
  );
  record(
    fn,
    "unknown type reference",
    mail((data) => {
      data.types.Mail[2] = field("contents", "Text");
    }),
  );
  record(
    fn,
    "repeated field",
    mail((data) => {
      data.types.Person.push(field("name", "string"));
    }),
  );
  record(
    fn,
    "reserved field name",
    mail((data) => {
      data.types.Person[0] = field("constructor", "string");
      data.message.from = { constructor: "Cow", wallet: data.message.from.wallet };
      data.message.to = { constructor: "Bob", wallet: data.message.to.wallet };
    }),
  );
  record(
    fn,
    "reserved struct name",
    mail((data) => {
      data.types.prototype = data.types.Person;
      delete data.types.Person;
      data.types.Mail = data.types.Mail.map((entry) =>
        entry.type === "Person" ? field(entry.name, "prototype") : entry,
      );
    }),
  );
  record(
    fn,
    "builtin struct name",
    mail((data) => {
      data.types.address = [field("x", "uint256")];
    }),
  );
  record(
    fn,
    "identifier with dollar",
    mail((data) => {
      data.types.Person[0] = field("$name", "string");
    }),
  );
  record(
    fn,
    "identifier 64 characters",
    mail((data) => {
      const name = `n${"a".repeat(63)}`;
      data.types.Mail[2] = field(name, "string");
      data.message = {
        from: data.message.from,
        to: data.message.to,
        [name]: data.message.contents,
      };
    }),
  );
  record(
    fn,
    "identifier 65 characters",
    mail((data) => {
      const name = `n${"a".repeat(64)}`;
      data.types.Mail[2] = field(name, "string");
      data.message = {
        from: data.message.from,
        to: data.message.to,
        [name]: data.message.contents,
      };
    }),
  );
  record(
    fn,
    "primaryType domain",
    mail((data) => {
      data.primaryType = "EIP712Domain";
    }),
  );
  record(
    fn,
    "primaryType undeclared",
    mail((data) => {
      data.primaryType = "Letter";
    }),
  );
  record(
    fn,
    "domain unsupported field",
    mail((data) => {
      data.types.EIP712Domain.push(field("extra", "string"));
      data.domain.extra = "x";
    }),
  );
  record(
    fn,
    "domain wrong field type",
    mail((data) => {
      data.types.EIP712Domain[2] = field("chainId", "uint64");
    }),
  );
  record(
    fn,
    "domain wrong order",
    mail((data) => {
      data.types.EIP712Domain.reverse();
    }),
  );
  record(
    fn,
    "domain empty",
    mail((data) => {
      data.types.EIP712Domain = [];
      data.domain = {};
    }),
  );
  record(
    fn,
    "domain with salt only",
    mail((data) => {
      data.types.EIP712Domain = [field("salt", "bytes32")];
      data.domain = { salt: hex("ab", 32) };
    }),
  );
  record(
    fn,
    "domain chainId leading zero",
    mail((data) => {
      data.domain.chainId = "01";
    }),
  );
  record(
    fn,
    "domain chainId number",
    mail((data) => {
      data.domain.chainId = 1;
    }),
  );
  record(
    fn,
    "message wallet uppercase",
    mail((data) => {
      data.message.from.wallet = hex("AB", 20);
    }),
  );
  record(
    fn,
    "message wallet zero",
    mail((data) => {
      data.message.from.wallet = ZERO_ADDRESS;
    }),
  );
  record(
    fn,
    "message extra field",
    mail((data) => {
      data.message.extra = "x";
    }),
  );

  /** One-field struct `Value { value: <type> }` as primary type. */
  const scalar = (type, value, extra = {}) =>
    rehash(
      edit(MAIL_REQUEST, (request) => {
        request.typedData = {
          types: {
            EIP712Domain: request.typedData.types.EIP712Domain,
            Value: [field("value", type)],
            ...extra,
          },
          primaryType: "Value",
          domain: request.typedData.domain,
          message: { value },
        };
      }),
    );
  for (const [label, type, value] of [
    ["uint8 max", "uint8", "255"],
    ["uint8 overflow", "uint8", "256"],
    ["uint8 negative", "uint8", "-1"],
    ["int8 min", "int8", "-128"],
    ["int8 below min", "int8", "-129"],
    ["int8 max", "int8", "127"],
    ["int8 above max", "int8", "128"],
    ["int8 negative zero", "int8", "-0"],
    ["int8 leading zero", "int8", "-01"],
    ["int256 min", "int256", (-(2n ** 255n)).toString()],
    ["int256 below min", "int256", (-(2n ** 255n) - 1n).toString()],
    ["uint256 max", "uint256", MAX_UINT256],
    ["uint256 hex", "uint256", "0x1"],
    ["uint48 number", "uint48", 1],
    ["uint alias", "uint", "1"],
    ["int alias", "int", "1"],
    ["uint7 width", "uint7", "1"],
    ["uint264 width", "uint264", "1"],
    ["uint08 width", "uint08", "1"],
    ["bool true", "bool", true],
    ["bool string", "bool", "true"],
    ["bytes empty", "bytes", "0x"],
    ["bytes odd", "bytes", "0x123"],
    ["bytes uppercase", "bytes", "0xAB"],
    ["bytes4 exact", "bytes4", "0x12345678"],
    ["bytes4 short", "bytes4", "0x123456"],
    ["bytes32 exact", "bytes32", hex("ab", 32)],
    ["bytes0 width", "bytes0", "0x"],
    ["bytes33 width", "bytes33", hex("ab", 33)],
    ["bytes01 width", "bytes01", "0xab"],
    ["string unicode", "string", "café \u{1f600}"],
    ["string empty", "string", ""],
    ["address zero", "address", ZERO_ADDRESS],
    ["address checksummed", "address", checksum(MIXED_ADDRESS)],
    ["string 16384 bytes", "string", "s".repeat(16_384)],
    ["string 16385 bytes", "string", "s".repeat(16_385)],
    ["string 8193 two-byte characters", "string", "é".repeat(8_193)],
    ["bytes 16384", "bytes", `0x${"ab".repeat(16_384)}`],
    ["bytes 16385", "bytes", `0x${"ab".repeat(16_385)}`],
    ["dynamic array", "uint8[]", ["1", "2"]],
    ["fixed array", "uint8[2]", ["1", "2"]],
    ["fixed array wrong length", "uint8[3]", ["1", "2"]],
    ["fixed array zero length", "uint8[0]", []],
    ["fixed array leading zero", "uint8[02]", ["1", "2"]],
    ["fixed array 256", "uint8[256]", Array.from({ length: 256 }, () => "1")],
    ["fixed array 257", "uint8[257]", Array.from({ length: 257 }, () => "1")],
    ["dynamic array 257", "uint8[]", Array.from({ length: 257 }, () => "1")],
    [
      "nested arrays",
      "uint8[2][]",
      [
        ["1", "2"],
        ["3", "4"],
        ["5", "6"],
      ],
    ],
    ["nested arrays wrong inner", "uint8[2][]", [["1", "2"], ["3"]]],
    ["array suffix garbage", "uint8[x]", ["1"]],
    ["array suffix unclosed", "uint8[", ["1"]],
    ["array suffix spaces", "uint8[ 1]", ["1"]],
    ["array of strings", "string[]", ["a", "b"]],
    [
      "sixteen array levels",
      `uint8${"[]".repeat(16)}`,
      Array.from({ length: 15 }).reduce((inner) => [inner], ["1"]),
    ],
    [
      "seventeen array levels",
      `uint8${"[]".repeat(17)}`,
      Array.from({ length: 16 }).reduce((inner) => [inner], ["1"]),
    ],
    ["type 128 characters", `uint8${"[]".repeat(60)}[1]`, "1"],
    ["type 129 characters", `uint8${"[]".repeat(62)}`, "1"],
  ]) {
    record(fn, `scalar ${label}`, scalar(type, value));
    record("hashOwnerSigningRequest", `scalar ${label}`, scalar(type, value));
  }
  record(
    fn,
    "values over budget",
    scalar(
      "uint8[256][16]",
      Array.from({ length: 16 }, () => Array.from({ length: 256 }, () => "1")),
    ),
  );
  record(
    fn,
    "values within budget",
    scalar(
      "uint8[256][15]",
      Array.from({ length: 15 }, () => Array.from({ length: 256 }, () => "1")),
    ),
  );
  record(
    fn,
    "bytes over total budget",
    scalar(
      "bytes[4]",
      Array.from({ length: 4 }, () => `0x${"ab".repeat(8_200)}`),
    ),
  );
  record(
    fn,
    "strings over total budget",
    scalar(
      "string[5]",
      Array.from({ length: 5 }, () => "s".repeat(13_200)),
    ),
  );
  record(
    fn,
    "strings within total budget",
    scalar(
      "string[4]",
      Array.from({ length: 4 }, () => "s".repeat(15_000)),
    ),
  );
  record(
    fn,
    "struct array",
    scalar("Item[]", [{ id: "1" }, { id: "2" }], { Item: [field("id", "uint256")] }),
  );
  record(fn, "recursive struct", scalar("Node", { next: [] }, { Node: [field("next", "Node[]")] }));
  record(fn, "struct referencing domain", scalar("EIP712Domain", MAIL_REQUEST.typedData.domain));
  record(
    fn,
    "deep struct nesting",
    scalar(
      "N",
      Array.from({ length: 16 }).reduce((inner) => ({ n: [inner] }), { n: [] }),
      { N: [field("n", "N[]")] },
    ),
  );
  record(
    fn,
    "too deep struct nesting",
    scalar(
      "N",
      Array.from({ length: 17 }).reduce((inner) => ({ n: [inner] }), { n: [] }),
      { N: [field("n", "N[]")] },
    ),
  );
  /** Primary struct `Value` with the given fields and message. */
  const custom = (types, message) =>
    rehash(
      edit(MAIL_REQUEST, (request) => {
        request.typedData = {
          types: { EIP712Domain: request.typedData.types.EIP712Domain, ...types },
          primaryType: "Value",
          domain: request.typedData.domain,
          message,
        };
      }),
    );
  for (const count of [62, 63]) {
    const names = Array.from({ length: count }, (_, index) => `T${index}`);
    record(
      fn,
      `${count + 2} types`,
      custom(
        {
          Value: names.map((name, index) => field(`t${index}`, name)),
          ...Object.fromEntries(names.map((name) => [name, [field("x", "uint8")]])),
        },
        Object.fromEntries(names.map((_, index) => [`t${index}`, { x: "1" }])),
      ),
    );
  }
  for (const count of [64, 65]) {
    record(
      fn,
      `${count} fields`,
      custom(
        { Value: Array.from({ length: count }, (_, index) => field(`f${index}`, "uint8")) },
        Object.fromEntries(Array.from({ length: count }, (_, index) => [`f${index}`, "1"])),
      ),
    );
  }
}
{
  const fn = "hashOwnerSigningRequest";
  record(fn, "mail nonce max", set(MAIL_REQUEST, ["replay", "nonce"], MAX_UINT256));
  record(fn, "mail invalid", { ...MAIL_REQUEST, kind: "raw" });
  record(fn, "raw digest invalid", { ...RAW_REQUEST, decision: "approve" });
}

{
  const fn = "parseKernelReplayableInstallOwnerSigningRequest";
  record(fn, "golden", GOLDEN_KERNEL);
  record(fn, "fixture", KERNEL_REQUEST);
  record(fn, "single validator install", kernelRequest({ packages: [SIMPLE_PACKAGE] }));
  record(
    fn,
    "every module type",
    kernelRequest({
      nonce: MAX_UINT256,
      packages: [
        SIMPLE_PACKAGE,
        { ...SIMPLE_PACKAGE, moduleType: 2 },
        { ...SIMPLE_PACKAGE, moduleType: 3, moduleData: "0x1234" },
        { ...SIMPLE_PACKAGE, moduleType: 5, internalData: "0xaabbccdd" },
        { ...SIMPLE_PACKAGE, moduleType: 6, internalData: "0xaabbccdd01" },
        { ...SIMPLE_PACKAGE, moduleType: 11 },
      ],
    }),
  );
  record(
    fn,
    "ecdsa owner",
    kernelRequest({ packages: [SIMPLE_PACKAGE], ownerCredential: OWNER_ECDSA }),
  );
  record(
    fn,
    "webauthn owner",
    kernelRequest({ packages: [SIMPLE_PACKAGE], ownerCredential: OWNER_WEBAUTHN }),
  );
  record(fn, "mail request", MAIL_REQUEST);
  record(fn, "raw digest request", RAW_REQUEST);
  record(fn, "purpose application", { ...KERNEL_REQUEST, purpose: "application" });
  record(fn, "replay deadline", set(KERNEL_REQUEST, ["replay", "deadline"], "1"));
  record(fn, "replay nonce null", set(KERNEL_REQUEST, ["replay", "nonce"], null));
  record(fn, "replay nonce differs", set(KERNEL_REQUEST, ["replay", "nonce"], "8"));
  record(
    fn,
    "message nonce differs",
    typed(KERNEL_REQUEST, (data) => {
      data.message.nonce = "8";
    }),
  );
  record(fn, "digest differs", { ...KERNEL_REQUEST, expectedDigest: hex("ab", 32) });
  record(
    fn,
    "domain name",
    typed(KERNEL_REQUEST, (data) => {
      data.domain.name = "Kernel2";
    }),
  );
  record(
    fn,
    "domain version",
    typed(KERNEL_REQUEST, (data) => {
      data.domain.version = "0.3.3";
    }),
  );
  record(
    fn,
    "domain verifyingContract",
    typed(KERNEL_REQUEST, (data) => {
      data.domain.verifyingContract = hex("67", 20);
    }),
  );
  record(
    fn,
    "domain with chainId",
    typed(KERNEL_REQUEST, (data) => {
      data.types.EIP712Domain.splice(2, 0, { name: "chainId", type: "uint256" });
      data.domain = {
        name: "Kernel",
        version: "0.4.0",
        chainId: "1",
        verifyingContract: KERNEL_ACCOUNT,
      };
    }),
  );
  record(
    fn,
    "install field renamed",
    typed(KERNEL_REQUEST, (data) => {
      data.types.Install[3] = { name: "internal", type: "bytes" };
      for (const install of data.message.packages) {
        install.internal = install.internalData;
        delete install.internalData;
      }
    }),
  );
  record(
    fn,
    "packages type renamed",
    typed(KERNEL_REQUEST, (data) => {
      data.types.Package = data.types.Install;
      delete data.types.Install;
      data.types.InstallPackages[1] = { name: "packages", type: "Package[]" };
    }),
  );
  record(
    fn,
    "primary type renamed",
    typed(KERNEL_REQUEST, (data) => {
      data.types.Packages = data.types.InstallPackages;
      delete data.types.InstallPackages;
      data.primaryType = "Packages";
    }),
  );
  for (const [label, packages] of [
    ["module type 4", [{ ...SIMPLE_PACKAGE, moduleType: 4 }]],
    ["module type 7", [{ ...SIMPLE_PACKAGE, moduleType: 7 }]],
    ["module type 0", [{ ...SIMPLE_PACKAGE, moduleType: 0 }]],
    ["zero module", [{ ...SIMPLE_PACKAGE, module: ZERO_ADDRESS }]],
    ["signer without policy", [{ ...SIMPLE_PACKAGE, moduleType: 6, internalData: "0xaabbccdd" }]],
    ["policy without signer", [{ ...SIMPLE_PACKAGE, moduleType: 5, internalData: "0xaabbccdd" }]],
    [
      "policy short internal data",
      [
        { ...SIMPLE_PACKAGE, moduleType: 5, internalData: "0xaabbcc" },
        { ...SIMPLE_PACKAGE, moduleType: 6, internalData: "0xaabbccdd" },
      ],
    ],
    [
      "policy and signer differ",
      [
        { ...SIMPLE_PACKAGE, moduleType: 5, internalData: "0xaabbccdd" },
        { ...SIMPLE_PACKAGE, moduleType: 6, internalData: "0xaabbccde" },
      ],
    ],
    [
      "two policies one signer",
      [
        { ...SIMPLE_PACKAGE, moduleType: 5, internalData: "0xaabbccdd" },
        { ...SIMPLE_PACKAGE, moduleType: 5, internalData: "0xaabbccdd00" },
        { ...SIMPLE_PACKAGE, moduleType: 6, internalData: "0xaabbccdd" },
      ],
    ],
    [
      "validator between policy and signer",
      [
        { ...SIMPLE_PACKAGE, moduleType: 5, internalData: "0xaabbccdd" },
        SIMPLE_PACKAGE,
        { ...SIMPLE_PACKAGE, moduleType: 6, internalData: "0xaabbccdd" },
      ],
    ],
    [
      "two complete permissions",
      [
        { ...SIMPLE_PACKAGE, moduleType: 5, internalData: "0xaabbccdd" },
        { ...SIMPLE_PACKAGE, moduleType: 6, internalData: "0xaabbccdd" },
        { ...SIMPLE_PACKAGE, moduleType: 5, internalData: "0x11223344" },
        { ...SIMPLE_PACKAGE, moduleType: 6, internalData: "0x11223344" },
      ],
    ],
  ]) {
    const request = edit(kernelRequest({ packages: [SIMPLE_PACKAGE] }), (draft) => {
      draft.typedData.message.packages = packages.map((install) => ({
        ...install,
        moduleType: String(install.moduleType),
      }));
    });
    record(fn, `packages ${label}`, rehash(request));
  }
  record(
    fn,
    "packages empty",
    rehash(
      edit(KERNEL_REQUEST, (draft) => {
        draft.typedData.message.packages = [];
      }),
    ),
  );
  record(
    fn,
    "packages 256",
    kernelRequest({ packages: Array.from({ length: 256 }, () => SIMPLE_PACKAGE) }),
  );
  record(
    fn,
    "packages 257",
    rehash(
      edit(kernelRequest({ packages: [SIMPLE_PACKAGE] }), (draft) => {
        draft.typedData.message.packages = Array.from({ length: 257 }, () => ({
          ...SIMPLE_PACKAGE,
          moduleType: "1",
        }));
      }),
    ),
  );
  record(
    fn,
    "packages module type 01",
    rehash(
      edit(kernelRequest({ packages: [SIMPLE_PACKAGE] }), (draft) => {
        draft.typedData.message.packages[0].moduleType = "01";
      }),
    ),
  );
}

// --------------------------------------------- stored scope classification

{
  const fn = "classifyStoredAuthorizationScope";
  const { requestId: _requestId, ...scope } = REQUEST;
  const classify = (requestedScope, requestId = REQUEST.requestId) => ({
    requestedScope,
    requestId,
  });
  record(fn, "permission request scope", classify(JSON.stringify(scope)));
  record(fn, "permission request with stored id", classify(JSON.stringify(REQUEST)));
  record(
    fn,
    "permission request with other embedded id",
    classify(JSON.stringify({ ...REQUEST, requestId: "embedded" })),
  );
  record(
    fn,
    "permission request under another request id",
    classify(JSON.stringify(scope), "other-request"),
  );
  record(fn, "permission request invalid request id", classify(JSON.stringify(scope), " padded"));
  record(
    fn,
    "permission request invalid policy",
    classify(JSON.stringify(set(scope, ["policy", "calls"], []))),
  );
  record(
    fn,
    "permission request existing account",
    classify(JSON.stringify({ ...scope, logicalAccount: EXISTING_ACCOUNT })),
  );
  record(
    fn,
    "permission request existing webauthn account",
    classify(JSON.stringify({ ...scope, logicalAccount: EXISTING_WEBAUTHN_ACCOUNT })),
  );
  record(fn, "kernel p256 request", classify(JSON.stringify(KERNEL_REQUEST)));
  record(fn, "kernel golden request", classify(JSON.stringify(GOLDEN_KERNEL)));
  record(
    fn,
    "kernel ecdsa request",
    classify(
      JSON.stringify(kernelRequest({ packages: [SIMPLE_PACKAGE], ownerCredential: OWNER_ECDSA })),
    ),
  );
  record(
    fn,
    "kernel request with wrong digest",
    classify(JSON.stringify({ ...KERNEL_REQUEST, expectedDigest: hex("ab", 32) })),
  );
  record(fn, "mail request", classify(JSON.stringify(MAIL_REQUEST)));
  record(fn, "raw digest request", classify(JSON.stringify(RAW_REQUEST)));
  record(
    fn,
    "invalid owner signing request",
    classify(JSON.stringify({ ...RAW_REQUEST, decision: "approve" })),
  );
  record(
    fn,
    "owner signing request with requestId",
    classify(JSON.stringify({ ...RAW_REQUEST, requestId: "x" })),
  );
  record(fn, "pretty printed permission request", classify(JSON.stringify(scope, null, 2)));
  // String contents must never be read as number tokens.
  for (const [label, providerId, expiresAt] of [
    ["quoted -0 in a string", 'said "-0" twice -0', 200],
    ["string ending in a backslash before -0", "kms\\", raw("-0")],
    ["string ending in a backslash", "kms\\", 200],
    ["escaped quote then -0", 'a\\"-0', 200],
  ]) {
    const { expiresAt: _expiresAt, sessionSigner: _sessionSigner, ...rest } = scope;
    const signed = {
      ...rest,
      sessionSigner: { mode: "application_backend", providerId },
      expiresAt,
    };
    record(fn, `scope ${label}`, classify(stringify(signed)));
  }
  for (const [label, text] of [
    ["empty", ""],
    ["null", "null"],
    ["array", "[]"],
    ["array of request", `[${JSON.stringify(scope)}]`],
    ["number", "42"],
    ["string", '"scope"'],
    ["empty object", "{}"],
    ["legacy scope", JSON.stringify({ scope: "openid wallet" })],
    ["plain text", "openid wallet"],
    ["truncated", JSON.stringify(scope).slice(0, -1)],
    ["trailing garbage", `${JSON.stringify(scope)}]`],
  ]) {
    record(fn, `scope ${label}`, classify(text));
  }
}

// ------------------------------------------------------- grant reference

const VERIFY_INPUT = {
  grantId: "grant-1",
  revision: 1,
  subject: "subject-1",
  clientId: "client-1",
  organizationAudience: "org.example",
  requiredCallsDigest: P.hashGrantPolicyCalls(POLICY.calls),
};
const GRANT_REF = {
  version: "oaath.grant-reference/v1",
  grantId: "grant-1",
  revision: 1,
  subject: "subject-1",
  clientId: "client-1",
  organizationAudience: "org.example",
  state: "active",
  policyDigest: P.hashGrantPolicy(POLICY),
};

function referenceCases(fn, base) {
  record(fn, "valid", base);
  for (const [label, value] of [
    ["0", 0],
    ["2", 2],
    ["2^48 - 1", MAX_UINT48],
    ["2^48", MAX_UINT48 + 1],
    ["-0", raw("-0")],
    ["1.0", raw("1.0")],
    ["1e0", raw("1e0")],
    ["string", "1"],
  ]) {
    record(fn, `revision ${label}`, { ...base, revision: value });
  }
  for (const key of ["subject", "clientId", "organizationAudience"]) {
    for (const [label, value] of [
      ["URL-safe punctuation", "A-z_0.9~"],
      ["256 characters", "s".repeat(256)],
      ["257 characters", "s".repeat(257)],
      ["space", "a b"],
      ["slash", "a/b"],
      ["unicode", "café"],
      ["empty", ""],
    ]) {
      record(fn, `${key} ${label}`, { ...base, [key]: value });
    }
  }
  for (const [label, value] of [
    ["inner space", "grant 1"],
    ["leading space", " grant"],
    ["trailing NEL", "grant\u0085"],
    ["256 units", "g".repeat(256)],
    ["257 units", "g".repeat(257)],
    ["unicode", "\u{1f600}"],
  ]) {
    record(fn, `grantId ${label}`, { ...base, grantId: value });
  }
  shapeCases(fn, "input", base);
}

referenceCases("parseVerifyGrantRevisionInput", VERIFY_INPUT);
record("parseVerifyGrantRevisionInput", "uppercase digest", {
  ...VERIFY_INPUT,
  requiredCallsDigest: hex("AB", 32),
});
referenceCases("parseOaathGrantRef", GRANT_REF);
for (const state of ["pending", "revoked", "expired", "approved"]) {
  record("parseOaathGrantRef", `state ${state}`, { ...GRANT_REF, state });
}
record("parseOaathGrantRef", "version v2", { ...GRANT_REF, version: "oaath.grant-reference/v2" });
{
  const fn = "parseGrantVerificationResult";
  record(fn, "authorized", { state: "authorized", ref: GRANT_REF });
  record(fn, "authorized invalid ref", { state: "authorized", ref: { ...GRANT_REF, revision: 0 } });
  record(fn, "authorized with code", {
    state: "authorized",
    ref: GRANT_REF,
    code: "grant_pending",
  });
  for (const code of [
    "grant_pending",
    "grant_rejected",
    "grant_revoked",
    "grant_expired",
    "grant_revision_mismatch",
    "grant_subject_mismatch",
    "grant_client_mismatch",
    "grant_audience_mismatch",
    "grant_calls_mismatch",
    "grant_unknown",
    "grant_unreadable",
    "grant_other",
  ]) {
    record(fn, `denied ${code}`, { state: "denied", code });
    record(fn, `unknown ${code}`, { state: "unknown", code });
  }
  record(fn, "denied with ref", { state: "denied", code: "grant_pending", ref: GRANT_REF });
  record(fn, "state other", { state: "pending", code: "grant_pending" });
  record(fn, "missing state", { code: "grant_pending" });
  record(fn, "null", null);
  record(fn, "array", []);
}

// ------------------------------------------- Kernel v4 account derivation

/**
 * The expected address is the deployed factory's own `getAddress`, read on two
 * local loopback Anvil chains with different chain IDs (no public RPC), over the
 * root package the SDK's owner operator installs for the credential. Rejections
 * mirror the SDK: a malformed profile fails its parse; an existing account, a
 * non-factory route, or a validator that does not match the owner kind is not
 * derivable (`kernel_account_derivation_invalid`).
 */
{
  const fn = "deriveKernelV4AccountAddress";
  const { startAnvil, deployKernelStack } = await import(
    `${root}packages/testing/src/anvil-process.mjs`
  );
  const { credentialKey } = await import(`${root}packages/sdk/src/kernel/key/credential.ts`);
  const { ownerOperator } = await import(`${root}packages/sdk/src/kernel/operator/owner.ts`);
  const { encodeKernelV4FactoryAddressRead, kernelV4Deployment } = await import(
    `${root}packages/sdk/src/kernel-v4.ts`
  );
  const ECDSA_VALIDATOR = "0x845adb2c711129d4f3966735ed98a9f09fc4ce57";
  const chains = [];
  try {
    for (const chainId of [31_337, 8_453]) {
      const chain = await startAnvil(chainId);
      chains.push(chain);
      await deployKernelStack(chain);
    }
    const derive = async (value) => {
      const account = P.parseKernelAccountProfile(value.account);
      if (P.isKernelExistingAccountProfile(account) || account.factoryRoute !== "kernel_factory") {
        throw Object.assign(new Error("not derivable"), {
          code: "kernel_account_derivation_invalid",
        });
      }
      const addresses = [];
      for (const chain of chains) {
        const deployment = kernelV4Deployment(chain.chainId);
        let initialPackages;
        try {
          const key = credentialKey({
            credential: account.ownerCredential,
            validator: value.ownerValidator,
          });
          initialPackages = ownerOperator({ key }).resolvePackages(deployment);
        } catch (error) {
          if (!String(error?.code).startsWith("kernel_runtime_")) throw error;
          throw Object.assign(new Error("not derivable"), {
            code: "kernel_account_derivation_invalid",
          });
        }
        const data = encodeKernelV4FactoryAddressRead({
          initialPackages,
          accountIndex: account.accountIndex,
        });
        const result = await chain.rpc("eth_call", [{ to: deployment.factory, data }, "latest"]);
        addresses.push(`0x${result.slice(-40)}`);
      }
      if (addresses[0] !== addresses[1]) throw new Error("factory address depends on the chain");
      return addresses[0];
    };
    const cases = [];
    const add = (name, account, ownerValidator = null) =>
      cases.push([name, { account, ownerValidator }]);
    const derived = (ownerCredential, accountIndex, extra = {}) => ({
      ...DERIVED_ACCOUNT,
      factoryRoute: "kernel_factory",
      ownerCredential,
      accountIndex,
      ...extra,
    });
    for (const index of ["0", "1", "7", "4294967296", MAX_UINT256]) {
      add(`ecdsa index ${index}`, derived(OWNER_ECDSA, index), ECDSA_VALIDATOR);
      add(`p256 index ${index}`, derived(OWNER_P256, index));
      add(`webauthn index ${index}`, derived(OWNER_WEBAUTHN, index));
    }
    add(
      "ecdsa other owner",
      derived({ ...OWNER_ECDSA, address: hex("ab", 20) }, "0"),
      ECDSA_VALIDATOR,
    );
    add("ecdsa other validator", derived(OWNER_ECDSA, "0"), hex("22", 20));
    add("ecdsa checksummed validator", derived(OWNER_ECDSA, "0"), checksum(MIXED_ADDRESS));
    add(
      "ecdsa checksummed owner",
      derived({ ...OWNER_ECDSA, address: checksum(MIXED_ADDRESS) }, "0"),
      ECDSA_VALIDATOR,
    );
    add("p256 other key", derived({ ...OWNER_P256, publicKey: OTHER_PUBLIC_KEY }, "0"));
    add(
      "webauthn other authenticator",
      derived({ ...OWNER_WEBAUTHN, authenticatorIdHash: hex("99", 32) }, "0"),
    );
    add(
      "webauthn same key as p256",
      derived({ ...OWNER_WEBAUTHN, publicKey: OWNER_PUBLIC_KEY }, "0"),
    );
    add("ecdsa without validator", derived(OWNER_ECDSA, "0"));
    add("ecdsa zero validator", derived(OWNER_ECDSA, "0"), ZERO_ADDRESS);
    add("ecdsa short validator", derived(OWNER_ECDSA, "0"), hex("22", 19));
    add("p256 with validator", derived(OWNER_P256, "0"), ECDSA_VALIDATOR);
    add("webauthn with validator", derived(OWNER_WEBAUTHN, "0"), ECDSA_VALIDATOR);
    add("meta factory route", derived(OWNER_P256, "0", { factoryRoute: "meta_factory" }));
    add("index above uint256", derived(OWNER_P256, (2n ** 256n).toString()));
    add("index negative", derived(OWNER_P256, "-1"));
    add("index leading zero", derived(OWNER_P256, "01"));
    add("index number", derived(OWNER_P256, 0));
    add("existing 0.4.0 p256", {
      ...EXISTING_ACCOUNT,
      kernelVersion: "0.4.0",
      entryPoint: { version: "0.9" },
      ownerCredential: OWNER_P256,
    });
    add("existing 0.3.3 ecdsa", EXISTING_ACCOUNT, ECDSA_VALIDATOR);
    add(
      "kernel 0.3.3 derived",
      derived(OWNER_ECDSA, "0", { kernelVersion: "0.3.3", entryPoint: { version: "0.7" } }),
      ECDSA_VALIDATOR,
    );
    add(
      "unsupported owner kind",
      derived({ ...OWNER_ECDSA, kind: "weighted-ecdsa" }, "0"),
      ECDSA_VALIDATOR,
    );
    for (const [name, input] of cases) {
      let expect;
      try {
        expect = { ok: await derive(JSON.parse(JSON.stringify(input))) };
      } catch (error) {
        if (typeof error?.code !== "string") throw error;
        expect = { error: error.code };
      }
      const list = files.get(fn) ?? [];
      list.push({ name, fn, input: JSON.parse(JSON.stringify(input)), expect });
      files.set(fn, list);
    }
  } finally {
    for (const chain of chains) chain.stop();
  }
}

// ------------------------------------------------------------------ output

rmSync(OUTPUT, { recursive: true, force: true });
mkdirSync(OUTPUT, { recursive: true });
let total = 0;
for (const [fn, cases] of [...files].sort(([left], [right]) => left.localeCompare(right))) {
  writeFileSync(`${OUTPUT}/${fn}.json`, `${JSON.stringify(cases, null, 2)}\n`);
  total += cases.length;
  console.log(`${fn}: ${cases.length}`);
}
// The repository-pinned formatter owns the committed layout of generated JSON.
console.log(`total: ${total} cases in ${readdirSync(OUTPUT).length} files`);
