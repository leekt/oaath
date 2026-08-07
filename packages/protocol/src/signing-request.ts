/**
 * Current-version owner-signing wire owner.
 *
 * Structured EIP-712 input is captured once into immutable canonical values;
 * a raw digest is representable only as reject-only evidence. This module
 * derives hashes but never authorizes, signs, displays, or releases an
 * artifact. Those facts remain with the owner-device consent lifecycle.
 *
 * @author taek <leekt216@gmail.com>
 */
import { encodeAbiParameters, type Hex, hashTypedData, keccak256, type TypedData } from "viem";
import { capturedByProtocol, type ProtocolContractErrorCode, protocolFailure } from "./errors.js";
import {
  captureOwnerCredentialProfile,
  hashOwnerCredentialProfile,
  type OwnerCredentialProfile,
} from "./identity-profile.js";
import {
  type CaptureContext,
  type CaptureFailure,
  captureDenseArray,
  captureRecord,
  exactCapturedRecord,
  exactRecord,
} from "./internal/exact-record.js";

export const OAATH_OWNER_SIGNING_REQUEST_VERSION = "oaath.owner-signing-request/v1" as const;
export const OAATH_OWNER_SIGNING_REQUEST_HASH_DOMAIN =
  "@oaath/protocol:owner-signing-request" as const;

const ERROR_CODE = "signing_request_invalid" satisfies ProtocolContractErrorCode;
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const ADDRESS = /^0x[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]*)$/u;
const DECIMAL_INT = /^(?:0|-?[1-9][0-9]*)$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const RESERVED_RECORD_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const MAX_TYPES = 64;
const MAX_FIELDS = 64;
const MAX_IDENTIFIER_LENGTH = 64;
const MAX_DEPTH = 16;
const MAX_ARRAY_LENGTH = 256;
const MAX_SCALAR_BYTES = 16 * 1024;
const MAX_TOTAL_BYTES = 64 * 1024;
const MAX_TOTAL_VALUES = 4_096;
const MAX_UINT256 = (1n << 256n) - 1n;

export type Eip712SigningPurpose = "permit" | "permit2" | "application";

export interface CanonicalEip712Field {
  readonly name: string;
  readonly type: string;
}

export interface CanonicalEip712Array extends ReadonlyArray<CanonicalEip712Value> {}

export interface CanonicalEip712Object {
  readonly [key: string]: CanonicalEip712Value;
}

export type CanonicalEip712Value = string | boolean | CanonicalEip712Array | CanonicalEip712Object;

export interface CanonicalEip712TypedData {
  readonly types: Readonly<Record<string, readonly Readonly<CanonicalEip712Field>[]>>;
  readonly primaryType: string;
  readonly domain: Readonly<Record<string, CanonicalEip712Value>>;
  readonly message: Readonly<Record<string, CanonicalEip712Value>>;
}

export interface OwnerSigningRequestSigner {
  readonly account: `0x${string}`;
  readonly ownerCredential: Readonly<OwnerCredentialProfile>;
}

export interface OwnerSigningReplayFacts {
  readonly nonce: string | null;
  readonly deadline: string | null;
}

export interface Eip712OwnerSigningRequest {
  readonly version: typeof OAATH_OWNER_SIGNING_REQUEST_VERSION;
  readonly kind: "eip712";
  readonly purpose: Eip712SigningPurpose;
  readonly signer: Readonly<OwnerSigningRequestSigner>;
  readonly typedData: Readonly<CanonicalEip712TypedData>;
  readonly expectedDigest: `0x${string}`;
  readonly replay: Readonly<OwnerSigningReplayFacts>;
}

export interface RawDigestOwnerSigningRequest {
  readonly version: typeof OAATH_OWNER_SIGNING_REQUEST_VERSION;
  readonly kind: "raw-digest";
  readonly digest: `0x${string}`;
  readonly reason: string;
  readonly decision: "reject-only";
}

export type OwnerSigningRequest = Eip712OwnerSigningRequest | RawDigestOwnerSigningRequest;

interface ParsedType {
  readonly base: string;
  /** Array suffixes from innermost to outermost. `null` is dynamic. */
  readonly dimensions: readonly (number | null)[];
}

interface CaptureBudget {
  values: number;
  bytes: number;
}

const textEncoder = new TextEncoder();

function consumeBytes(
  text: string,
  budget: CaptureBudget,
  fail: CaptureFailure,
  maximum = MAX_SCALAR_BYTES,
): void {
  const bytes = textEncoder.encode(text).length;
  if (bytes > maximum || budget.bytes + bytes > MAX_TOTAL_BYTES) {
    fail("owner signing typed data exceeds its byte limit");
  }
  budget.bytes += bytes;
}

function consumeValue(budget: CaptureBudget, fail: CaptureFailure): void {
  budget.values += 1;
  if (budget.values > MAX_TOTAL_VALUES) fail("owner signing typed data has too many values");
}

function identifier(value: unknown, label: string, fail: CaptureFailure): string {
  if (
    typeof value !== "string" ||
    value.length > MAX_IDENTIFIER_LENGTH ||
    !IDENTIFIER.test(value) ||
    RESERVED_RECORD_KEYS.has(value)
  ) {
    return fail(`${label} must be a bounded EIP-712 identifier`);
  }
  return value;
}

function address(value: unknown, label: string, allowZero: boolean, fail: CaptureFailure): Hex {
  if (typeof value !== "string" || !ADDRESS.test(value) || (!allowZero && value === ZERO_ADDRESS)) {
    return fail(`${label} must be a canonical lowercase address`);
  }
  return value as Hex;
}

function hash(value: unknown, label: string, fail: CaptureFailure): Hex {
  if (typeof value !== "string" || !HASH.test(value)) {
    return fail(`${label} must be a lowercase 32-byte hash`);
  }
  return value as Hex;
}

function decimalUint(value: unknown, label: string, fail: CaptureFailure): string {
  if (
    typeof value !== "string" ||
    !DECIMAL_UINT.test(value) ||
    value.length > 78 ||
    BigInt(value) > MAX_UINT256
  ) {
    return fail(`${label} must be a canonical decimal uint256 string`);
  }
  return value;
}

function boundedReason(value: unknown, fail: CaptureFailure): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 256) {
    return fail("raw digest reason must be bounded non-empty text");
  }
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code !== undefined && (code < 0x20 || code === 0x7f)) {
      return fail("raw digest reason contains a control character");
    }
  }
  return value;
}

function parseType(value: unknown, label: string, fail: CaptureFailure): ParsedType {
  if (typeof value !== "string" || value.length > MAX_IDENTIFIER_LENGTH * 2) {
    return fail(`${label} is not a bounded EIP-712 type`);
  }
  const bracket = value.indexOf("[");
  const base = bracket < 0 ? value : value.slice(0, bracket);
  const suffix = bracket < 0 ? "" : value.slice(bracket);
  if (!IDENTIFIER.test(base)) return fail(`${label} has an invalid base type`);

  const dimensions: (number | null)[] = [];
  let rest = suffix;
  while (rest.length > 0) {
    const match = /^\[([0-9]*)\]/u.exec(rest);
    if (!match) return fail(`${label} has an invalid array suffix`);
    const length = match[1] ?? "";
    if (length === "") {
      dimensions.push(null);
    } else {
      if (!DECIMAL_UINT.test(length) || length === "0") {
        return fail(`${label} has a noncanonical fixed-array length`);
      }
      const parsed = Number(length);
      if (!Number.isSafeInteger(parsed) || parsed > MAX_ARRAY_LENGTH) {
        return fail(`${label} fixed-array length exceeds its limit`);
      }
      dimensions.push(parsed);
    }
    rest = rest.slice(match[0].length);
  }

  if (base === "uint" || base === "int") return fail(`${label} uses a forbidden integer alias`);
  if (base.startsWith("uint") || base.startsWith("int")) {
    const prefix = base.startsWith("uint") ? "uint" : "int";
    const widthText = base.slice(prefix.length);
    if (!DECIMAL_UINT.test(widthText)) {
      return fail(`${label} has a noncanonical integer width`);
    }
    const width = Number(widthText);
    if (width < 8 || width > 256 || width % 8 !== 0) {
      return fail(`${label} has an unsupported integer width`);
    }
  } else if (base.startsWith("bytes") && base !== "bytes") {
    const widthText = base.slice("bytes".length);
    if (!DECIMAL_UINT.test(widthText)) return fail(`${label} has a noncanonical bytes width`);
    const width = Number(widthText);
    if (width < 1 || width > 32) return fail(`${label} has an unsupported bytes width`);
  }
  return Object.freeze({ base, dimensions: Object.freeze(dimensions) });
}

function isBuiltin(base: string): boolean {
  return (
    base === "address" ||
    base === "bool" ||
    base === "string" ||
    base === "bytes" ||
    /^bytes(?:[1-9]|[12][0-9]|3[0-2])$/u.test(base) ||
    /^(?:u?int)(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)$/u.test(
      base,
    )
  );
}

function captureTypes(
  value: unknown,
  context: CaptureContext,
  budget: CaptureBudget,
  fail: CaptureFailure,
): Readonly<Record<string, readonly Readonly<CanonicalEip712Field>[]>> {
  const record = captureRecord(value, "EIP-712 types", context, fail);
  const names = Object.keys(record).sort();
  if (names.length < 2 || names.length > MAX_TYPES || !names.includes("EIP712Domain")) {
    return fail("EIP-712 types must include a domain and a primary struct within limits");
  }
  const result = Object.create(null) as Record<string, readonly Readonly<CanonicalEip712Field>[]>;
  for (const name of names) {
    identifier(name, "EIP-712 type name", fail);
    consumeBytes(name, budget, fail);
    if (isBuiltin(name)) return fail("EIP-712 struct names must not shadow built-in types");
    const entries = captureDenseArray(record[name], `EIP-712 ${name} fields`, context, fail);
    if (entries.length > MAX_FIELDS) return fail(`EIP-712 ${name} has too many fields`);
    const fieldNames = new Set<string>();
    const fields = entries.map((entry, index) => {
      const field = exactRecord(
        entry,
        ["name", "type"],
        `EIP-712 ${name} field ${index}`,
        context,
        fail,
      );
      const fieldName = identifier(field.name, `EIP-712 ${name} field name`, fail);
      if (fieldNames.has(fieldName)) return fail(`EIP-712 ${name} repeats a field name`);
      fieldNames.add(fieldName);
      const type = field.type;
      parseType(type, `EIP-712 ${name}.${fieldName} type`, fail);
      consumeBytes(fieldName, budget, fail);
      consumeBytes(type as string, budget, fail);
      return Object.freeze({ name: fieldName, type: type as string });
    });
    result[name] = Object.freeze(fields);
  }

  const domainFields = result.EIP712Domain ?? [];
  const domainOrder = ["name", "version", "chainId", "verifyingContract", "salt"];
  const domainTypes: Record<string, string> = {
    name: "string",
    version: "string",
    chainId: "uint256",
    verifyingContract: "address",
    salt: "bytes32",
  };
  if (domainFields.length < 1) return fail("EIP712Domain must contain at least one field");
  let previous = -1;
  for (const field of domainFields) {
    const index = domainOrder.indexOf(field.name);
    if (index < 0 || domainTypes[field.name] !== field.type || index <= previous) {
      return fail("EIP712Domain fields must use the canonical supported order and types");
    }
    previous = index;
  }

  for (const [name, fields] of Object.entries(result)) {
    for (const field of fields) {
      const parsed = parseType(field.type, `EIP-712 ${name}.${field.name} type`, fail);
      if (!isBuiltin(parsed.base) && result[parsed.base] === undefined) {
        return fail(`EIP-712 ${name}.${field.name} references an unknown type`);
      }
    }
  }
  return Object.freeze(result);
}

function captureScalar(
  value: unknown,
  base: string,
  label: string,
  budget: CaptureBudget,
  fail: CaptureFailure,
): string | boolean {
  consumeValue(budget, fail);
  if (base === "bool") {
    if (typeof value !== "boolean") return fail(`${label} must be a boolean`);
    return value;
  }
  if (base === "address") {
    const captured = address(value, label, true, fail);
    consumeBytes(captured, budget, fail);
    return captured;
  }
  if (base === "string") {
    if (typeof value !== "string") return fail(`${label} must be a string`);
    consumeBytes(value, budget, fail);
    return value;
  }
  if (base === "bytes" || base.startsWith("bytes")) {
    if (typeof value !== "string" || !BYTES.test(value)) {
      return fail(`${label} must be canonical lowercase even-length hex`);
    }
    const expected = base === "bytes" ? null : Number(base.slice(5));
    const byteLength = (value.length - 2) / 2;
    if ((expected !== null && byteLength !== expected) || byteLength > MAX_SCALAR_BYTES) {
      return fail(`${label} has the wrong byte length`);
    }
    consumeBytes(value, budget, fail, 2 + MAX_SCALAR_BYTES * 2);
    return value;
  }
  if (base.startsWith("uint") || base.startsWith("int")) {
    const signed = base.startsWith("int");
    const width = Number(base.slice(signed ? 3 : 4));
    const pattern = signed ? DECIMAL_INT : DECIMAL_UINT;
    if (typeof value !== "string" || !pattern.test(value) || value.length > 79) {
      return fail(`${label} must be a canonical decimal ${base} string`);
    }
    const integer = BigInt(value);
    const minimum = signed ? -(1n << BigInt(width - 1)) : 0n;
    const maximum = signed ? (1n << BigInt(width - 1)) - 1n : (1n << BigInt(width)) - 1n;
    if (integer < minimum || integer > maximum) return fail(`${label} is outside ${base}`);
    consumeBytes(value, budget, fail);
    return value;
  }
  return fail(`${label} uses an unsupported scalar type`);
}

function captureValue(
  value: unknown,
  parsed: ParsedType,
  types: Readonly<Record<string, readonly Readonly<CanonicalEip712Field>[]>>,
  label: string,
  depth: number,
  context: CaptureContext,
  budget: CaptureBudget,
  fail: CaptureFailure,
): CanonicalEip712Value {
  if (depth > MAX_DEPTH) return fail(`${label} exceeds the EIP-712 nesting limit`);
  if (parsed.dimensions.length > 0) {
    consumeValue(budget, fail);
    const entries = captureDenseArray(value, label, context, fail);
    const expected = parsed.dimensions.at(-1);
    if (entries.length > MAX_ARRAY_LENGTH || (expected !== null && entries.length !== expected)) {
      return fail(`${label} has the wrong array length`);
    }
    const nested = Object.freeze({
      base: parsed.base,
      dimensions: Object.freeze(parsed.dimensions.slice(0, -1)),
    });
    return Object.freeze(
      entries.map((entry, index) =>
        captureValue(entry, nested, types, `${label}[${index}]`, depth + 1, context, budget, fail),
      ),
    );
  }
  const fields = types[parsed.base];
  if (fields === undefined) return captureScalar(value, parsed.base, label, budget, fail);
  consumeValue(budget, fail);
  const record = exactRecord(
    value,
    fields.map((field) => field.name),
    label,
    context,
    fail,
  );
  const result = Object.create(null) as Record<string, CanonicalEip712Value>;
  for (const field of fields) {
    result[field.name] = captureValue(
      record[field.name],
      parseType(field.type, `${label}.${field.name} type`, fail),
      types,
      `${label}.${field.name}`,
      depth + 1,
      context,
      budget,
      fail,
    );
  }
  return Object.freeze(result);
}

export function captureCanonicalEip712TypedData(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<CanonicalEip712TypedData> {
  const budget: CaptureBudget = { values: 0, bytes: 0 };
  const record = exactRecord(
    value,
    ["types", "primaryType", "domain", "message"],
    "canonical EIP-712 typed data",
    context,
    fail,
  );
  const types = captureTypes(record.types, context, budget, fail);
  const primaryType = identifier(record.primaryType, "EIP-712 primaryType", fail);
  if (primaryType === "EIP712Domain" || types[primaryType] === undefined) {
    return fail("EIP-712 primaryType must name a declared message struct");
  }
  const reachable = new Set<string>(["EIP712Domain"]);
  const pending = [primaryType];
  while (pending.length > 0) {
    const name = pending.pop();
    if (name === undefined || reachable.has(name)) continue;
    reachable.add(name);
    for (const field of types[name] ?? []) {
      const dependency = parseType(field.type, `EIP-712 ${name}.${field.name} type`, fail).base;
      if (!isBuiltin(dependency) && !reachable.has(dependency)) pending.push(dependency);
    }
  }
  if (reachable.size !== Object.keys(types).length) {
    return fail("EIP-712 types contain an unreferenced struct");
  }
  const domain = captureValue(
    record.domain,
    Object.freeze({ base: "EIP712Domain", dimensions: Object.freeze([]) }),
    types,
    "EIP-712 domain",
    0,
    context,
    budget,
    fail,
  );
  const message = captureValue(
    record.message,
    Object.freeze({ base: primaryType, dimensions: Object.freeze([]) }),
    types,
    "EIP-712 message",
    0,
    context,
    budget,
    fail,
  );
  if (typeof domain !== "object" || Array.isArray(domain)) return fail("invalid EIP-712 domain");
  if (typeof message !== "object" || Array.isArray(message)) return fail("invalid EIP-712 message");
  return Object.freeze({
    types,
    primaryType,
    domain: domain as Readonly<Record<string, CanonicalEip712Value>>,
    message: message as Readonly<Record<string, CanonicalEip712Value>>,
  });
}

function captureReplay(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<OwnerSigningReplayFacts> {
  const record = exactRecord(value, ["nonce", "deadline"], "owner signing replay", context, fail);
  return Object.freeze({
    nonce: record.nonce === null ? null : decimalUint(record.nonce, "replay nonce", fail),
    deadline:
      record.deadline === null ? null : decimalUint(record.deadline, "replay deadline", fail),
  });
}

export function captureOwnerSigningRequest(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<OwnerSigningRequest> {
  const captured = captureRecord(value, "owner signing request", context, fail);
  if (captured.kind === "raw-digest") {
    const record = exactCapturedRecord(
      captured,
      ["version", "kind", "digest", "reason", "decision"],
      "raw digest owner signing request",
      fail,
    );
    if (
      record.version !== OAATH_OWNER_SIGNING_REQUEST_VERSION ||
      record.decision !== "reject-only"
    ) {
      return fail("raw digest owner signing request version or decision is unsupported");
    }
    return Object.freeze({
      version: OAATH_OWNER_SIGNING_REQUEST_VERSION,
      kind: "raw-digest",
      digest: hash(record.digest, "raw digest", fail),
      reason: boundedReason(record.reason, fail),
      decision: "reject-only",
    });
  }
  const record = exactCapturedRecord(
    captured,
    ["version", "kind", "purpose", "signer", "typedData", "expectedDigest", "replay"],
    "EIP-712 owner signing request",
    fail,
  );
  if (record.version !== OAATH_OWNER_SIGNING_REQUEST_VERSION || record.kind !== "eip712") {
    return fail("owner signing request version or kind is unsupported");
  }
  if (
    record.purpose !== "permit" &&
    record.purpose !== "permit2" &&
    record.purpose !== "application"
  ) {
    return fail("EIP-712 owner signing purpose is unsupported");
  }
  const signer = exactRecord(
    record.signer,
    ["account", "ownerCredential"],
    "owner signing signer",
    context,
    fail,
  );
  return Object.freeze({
    version: OAATH_OWNER_SIGNING_REQUEST_VERSION,
    kind: "eip712",
    purpose: record.purpose,
    signer: Object.freeze({
      account: address(signer.account, "owner signing account", false, fail),
      ownerCredential: captureOwnerCredentialProfile(signer.ownerCredential, context, fail),
    }),
    typedData: captureCanonicalEip712TypedData(record.typedData, context, fail),
    expectedDigest: hash(record.expectedDigest, "owner signing expected digest", fail),
    replay: captureReplay(record.replay, context, fail),
  });
}

export function parseOwnerSigningRequest(value: unknown): Readonly<OwnerSigningRequest> {
  return capturedByProtocol(ERROR_CODE, "owner signing request could not be captured safely", () =>
    captureOwnerSigningRequest(value, new WeakSet(), protocolFailure(ERROR_CODE)),
  );
}

export function parseCanonicalEip712TypedData(value: unknown): Readonly<CanonicalEip712TypedData> {
  return capturedByProtocol(ERROR_CODE, "EIP-712 typed data could not be captured safely", () =>
    captureCanonicalEip712TypedData(value, new WeakSet(), protocolFailure(ERROR_CODE)),
  );
}

function hashCapturedTypedData(value: CanonicalEip712TypedData): Hex {
  return hashTypedData({
    types: value.types as TypedData,
    primaryType: value.primaryType,
    domain: value.domain as never,
    message: value.message as never,
  });
}

export function hashCanonicalEip712TypedData(value: unknown): Hex {
  return capturedByProtocol(ERROR_CODE, "EIP-712 typed data could not be hashed safely", () =>
    hashCapturedTypedData(parseCanonicalEip712TypedData(value)),
  );
}

function encodeCapturedOwnerSigningRequest(request: OwnerSigningRequest): Hex {
  if (request.kind === "raw-digest") {
    return encodeAbiParameters(
      [
        { type: "string" },
        { type: "string" },
        { type: "string" },
        { type: "bytes32" },
        { type: "string" },
        { type: "string" },
      ],
      [
        OAATH_OWNER_SIGNING_REQUEST_HASH_DOMAIN,
        request.version,
        request.kind,
        request.digest,
        request.reason,
        request.decision,
      ],
    );
  }
  return encodeAbiParameters(
    [
      { type: "string" },
      { type: "string" },
      { type: "string" },
      { type: "string" },
      { type: "address" },
      { type: "bytes32" },
      { type: "bytes32" },
      { type: "bytes32" },
      { type: "bool" },
      { type: "uint256" },
      { type: "bool" },
      { type: "uint256" },
    ],
    [
      OAATH_OWNER_SIGNING_REQUEST_HASH_DOMAIN,
      request.version,
      request.kind,
      request.purpose,
      request.signer.account,
      hashOwnerCredentialProfile(request.signer.ownerCredential),
      hashCapturedTypedData(request.typedData),
      request.expectedDigest,
      request.replay.nonce !== null,
      BigInt(request.replay.nonce ?? "0"),
      request.replay.deadline !== null,
      BigInt(request.replay.deadline ?? "0"),
    ],
  );
}

export function encodeOwnerSigningRequest(value: unknown): Hex {
  return capturedByProtocol(ERROR_CODE, "owner signing request could not be encoded safely", () =>
    encodeCapturedOwnerSigningRequest(parseOwnerSigningRequest(value)),
  );
}

export function hashOwnerSigningRequest(value: unknown): Hex {
  return keccak256(encodeOwnerSigningRequest(value));
}
