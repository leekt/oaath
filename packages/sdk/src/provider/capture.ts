/**
 * Exact hostile-input capture for Final EIP-5792 and experimental ERC-7836
 * wallet-call params.
 *
 * This boundary converts the application-owned graph into one deeply immutable
 * representation. Downstream orchestration can consume it without reading the
 * application object again or interpreting aliases, accessors, and prototypes.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type CaptureContext,
  captureDenseArray,
  captureRecord,
  type ExactRecord,
} from "@oaath/protocol";
import { type Hash, type Hex, keccak256, stringToBytes } from "viem";
import {
  captureAtomicCapability,
  capturePaymasterServiceCapability,
  isHandledWalletCapability,
  type WalletCapabilityMethod,
  type WalletCapabilityScope,
} from "./capabilities.js";
import {
  INTERNAL_ERROR,
  invalidProviderParams,
  refuseProviderExecution,
  rpcFail,
} from "./errors.js";

const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const BYTES = /^0x(?:[0-9a-fA-F]{2})*$/u;
const LOWERCASE_BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const CANONICAL_CHAIN_ID = /^0x[1-9a-fA-F][0-9a-fA-F]*$/u;
const CANONICAL_QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const UNCOMPRESSED_SECP256K1_PUBLIC_KEY = /^0x04[0-9a-f]{128}$/u;

const BUNDLE_KEYS = Object.freeze([
  "version",
  "id",
  "from",
  "chainId",
  "atomicRequired",
  "calls",
  "capabilities",
]);
const REQUIRED_BUNDLE_KEYS = Object.freeze(["version", "chainId", "atomicRequired", "calls"]);
const CALL_KEYS = Object.freeze(["to", "data", "value", "capabilities"]);
const PREPARE_CALLS_KEYS = Object.freeze([
  "version",
  "chainId",
  "from",
  "calls",
  "capabilities",
  "key",
]);
const REQUIRED_PREPARE_CALLS_KEYS = Object.freeze(["version", "calls", "key"]);
const SEND_PREPARED_CALLS_KEYS = Object.freeze([
  "version",
  "chainId",
  "capabilities",
  "context",
  "key",
  "signature",
]);
const PREPARED_CALLS_KEY_KEYS = Object.freeze(["type", "publicKey", "prehash"]);
const PREPARED_CALLS_CONTEXT_KEYS = Object.freeze(["version", "id"]);

export const EIP5792_CAPTURE_LIMITS = Object.freeze({
  idUtf8Bytes: 4_096,
  calls: 64,
  calldataBytes: 128 * 1_024,
  capabilityJsonBytes: 64 * 1_024,
  bundleBytes: 256 * 1_024,
});

/** Bounds for OAAth's experimental ERC-7836 wire profile. */
export const ERC7836_CAPTURE_LIMITS = Object.freeze({
  secp256k1PublicKeyBytes: 65,
  webauthnPublicKeyBytes: 4_096,
  signatureBytes: 4_096,
});

export const OAATH_PREPARED_CALL_CONTEXT_TOKEN_VERSION =
  "oaath.prepared-call-context-token/v1" as const;

export type CapturedHex = `0x${string}`;
export type CapturedAddress = `0x${string}`;

export type CapturedJsonValue =
  | null
  | boolean
  | number
  | string
  | CapturedJsonObject
  | readonly CapturedJsonValue[];

export interface CapturedJsonObject {
  readonly [key: string]: CapturedJsonValue;
}

/** Exact handled ERC-7677 selection derived from retained capability values. */
export interface CapturedWalletPaymasterService {
  readonly url: string;
  readonly context: CapturedJsonObject;
  /** Missing `optional` is normalized to required. */
  readonly optional: boolean;
}

/**
 * Capability input, retained hash material, and explicit disposition. Unknown
 * optional names remain in `ignored`; handled selections are derived once from
 * the exact JSON-compatible `values` captured at this boundary.
 */
export interface CapturedWalletCapabilities {
  readonly values: Readonly<Record<string, CapturedJsonObject>>;
  readonly ignored: readonly string[];
  readonly paymasterService?: CapturedWalletPaymasterService;
}

export interface CapturedWalletCall {
  readonly to: CapturedAddress;
  readonly data?: CapturedHex;
  readonly value?: CapturedHex;
  readonly capabilities?: CapturedWalletCapabilities;
}

export interface CapturedWalletSendCallsParams {
  readonly version: "2.0.0";
  readonly id?: string;
  readonly from?: CapturedAddress;
  readonly chainId: CapturedHex;
  readonly atomicRequired: boolean;
  readonly calls: readonly CapturedWalletCall[];
  readonly capabilities?: CapturedWalletCapabilities;
}

export type CapturedWalletPreparedCallsKey = Readonly<{
  readonly type: "secp256k1" | "webauthn-p256";
  readonly publicKey: CapturedHex;
  readonly prehash: false;
}>;

export interface CapturedWalletPrepareCallsParams {
  readonly version: "1";
  readonly chainId: CapturedHex;
  readonly from?: CapturedAddress;
  readonly calls: readonly CapturedWalletCall[];
  readonly capabilities?: CapturedWalletCapabilities;
  readonly key: CapturedWalletPreparedCallsKey;
}

export interface CapturedWalletPreparedCallsContext {
  readonly version: typeof OAATH_PREPARED_CALL_CONTEXT_TOKEN_VERSION;
  readonly id: Hash;
}

export interface CapturedWalletSendPreparedCallsParams {
  readonly version: "1";
  readonly chainId: CapturedHex;
  readonly capabilities: CapturedWalletCapabilities;
  readonly context: CapturedWalletPreparedCallsContext;
  readonly key: CapturedWalletPreparedCallsKey;
  readonly signature: CapturedHex;
}

export interface CapturedWalletGetCapabilitiesParams {
  readonly address: CapturedAddress;
  readonly chainIds?: readonly CapturedHex[];
}

function canonicalJson(value: CapturedJsonValue): string {
  type Task = Readonly<{ kind: "value"; value: CapturedJsonValue }> | string;
  const output: string[] = [];
  const tasks: Task[] = [{ kind: "value", value }];
  while (tasks.length > 0) {
    const task = tasks.pop();
    if (task === undefined) return invalidProviderParams();
    if (typeof task === "string") {
      output.push(task);
      continue;
    }
    const entry = task.value;
    if (entry === null || typeof entry === "boolean" || typeof entry === "number") {
      output.push(JSON.stringify(entry));
      continue;
    }
    if (typeof entry === "string") {
      output.push(JSON.stringify(entry));
      continue;
    }
    if (isCapturedJsonArray(entry)) {
      tasks.push("]");
      for (let index = entry.length - 1; index >= 0; index -= 1) {
        const child = entry[index];
        if (child === undefined) return invalidProviderParams();
        tasks.push({ kind: "value", value: child });
        if (index > 0) tasks.push(",");
      }
      tasks.push("[");
      continue;
    }
    const keys = Object.keys(entry).sort();
    tasks.push("}");
    for (let index = keys.length - 1; index >= 0; index -= 1) {
      const key = keys[index];
      if (key === undefined) return invalidProviderParams();
      const child = entry[key];
      if (child === undefined) return invalidProviderParams();
      tasks.push({ kind: "value", value: child });
      tasks.push(":");
      tasks.push(JSON.stringify(key));
      if (index > 0) tasks.push(",");
    }
    tasks.push("{");
  }
  return output.join("");
}

function hashCapabilities(capabilities: CapturedWalletCapabilities): CapturedJsonObject {
  return Object.freeze({
    ignored: Object.freeze([...capabilities.ignored].sort()),
    values: capabilities.values,
  });
}

function hashWalletCalls(calls: readonly CapturedWalletCall[]): readonly CapturedJsonObject[] {
  return Object.freeze(
    calls.map((call) =>
      Object.freeze({
        to: call.to,
        ...(call.data === undefined ? {} : { data: call.data }),
        ...(call.value === undefined ? {} : { value: call.value }),
        ...(call.capabilities === undefined
          ? {}
          : { capabilities: hashCapabilities(call.capabilities) }),
      }),
    ),
  );
}

function hashPreparedCallsKey(key: CapturedWalletPreparedCallsKey): CapturedJsonObject {
  return Object.freeze({
    type: key.type,
    publicKey: key.publicKey,
    prehash: key.prehash,
  });
}

/** Deterministic identity of one exactly captured experimental prepare request. */
export function hashCapturedWalletPrepareCallsRequest(
  request: Readonly<CapturedWalletPrepareCallsParams>,
): Hash {
  const material: CapturedJsonObject = Object.freeze({
    version: request.version,
    chainId: request.chainId,
    ...(request.from === undefined ? {} : { from: request.from }),
    calls: hashWalletCalls(request.calls),
    ...(request.capabilities === undefined
      ? {}
      : { capabilities: hashCapabilities(request.capabilities) }),
    key: hashPreparedCallsKey(request.key),
  });
  return keccak256(stringToBytes(canonicalJson(material)));
}

/** Deterministic identity of one exactly captured experimental send request. */
export function hashCapturedWalletSendPreparedCallsRequest(
  request: Readonly<CapturedWalletSendPreparedCallsParams>,
): Hash {
  const material: CapturedJsonObject = Object.freeze({
    version: request.version,
    chainId: request.chainId,
    capabilities: hashCapabilities(request.capabilities),
    context: Object.freeze({
      version: request.context.version,
      id: request.context.id,
    }),
    key: hashPreparedCallsKey(request.key),
    signature: request.signature,
  });
  return keccak256(stringToBytes(canonicalJson(material)));
}

/** Internal deterministic identity for one already-captured request and its exact chosen ID. */
export function hashCapturedWalletSendCallsRequest(
  request: Readonly<CapturedWalletSendCallsParams>,
  id: string,
): Hash {
  const calls = request.calls.map((call) =>
    Object.freeze({
      to: call.to,
      ...(call.data === undefined ? {} : { data: call.data }),
      ...(call.value === undefined ? {} : { value: call.value }),
      ...(call.capabilities === undefined
        ? {}
        : { capabilities: hashCapabilities(call.capabilities) }),
    }),
  );
  const material: CapturedJsonObject = Object.freeze({
    version: request.version,
    id,
    ...(request.from === undefined ? {} : { from: request.from }),
    chainId: request.chainId,
    atomicRequired: request.atomicRequired,
    calls: Object.freeze(calls),
    ...(request.capabilities === undefined
      ? {}
      : { capabilities: hashCapabilities(request.capabilities) }),
  });
  return keccak256(stringToBytes(canonicalJson(material)));
}

/** Binds canonical request bytes to one unrepeatable durable bundle generation. */
export function hashWalletCallBundleProvenance(requestHash: unknown, generation: unknown): Hash {
  if (
    typeof requestHash !== "string" ||
    !HASH.test(requestHash) ||
    typeof generation !== "string" ||
    !HASH.test(generation)
  ) {
    return rpcFail(INTERNAL_ERROR);
  }
  return keccak256(`${requestHash}${generation.slice(2)}` as Hex);
}

interface CaptureBudget {
  calldataBytes: number;
  capabilityJsonBytes: number;
  hasUnsupportedRequiredCapability: boolean;
}

interface CapturedWalletCallDraft {
  readonly to: CapturedAddress | null;
  readonly data?: CapturedHex;
  readonly value?: CapturedHex;
  readonly capabilities?: CapturedWalletCapabilities;
  readonly wire: CapturedJsonObject;
}

export function isWalletAddress(value: unknown): value is CapturedAddress {
  return typeof value === "string" && ADDRESS.test(value);
}

export function isHexBytes(value: unknown): value is CapturedHex {
  return typeof value === "string" && BYTES.test(value);
}

export function isCanonicalChainId(value: unknown): value is CapturedHex {
  return typeof value === "string" && CANONICAL_CHAIN_ID.test(value);
}

function canonicalChainId(value: unknown): CapturedHex {
  if (!isCanonicalChainId(value)) return invalidProviderParams();
  return `0x${value.slice(2).toLowerCase()}`;
}

export function isCanonicalQuantity(value: unknown): value is CapturedHex {
  return typeof value === "string" && CANONICAL_QUANTITY.test(value);
}

function canonicalAddress(value: unknown): CapturedAddress {
  if (!isWalletAddress(value)) return invalidProviderParams();
  const canonical = value.toLowerCase();
  if (!isWalletAddress(canonical)) return invalidProviderParams();
  return canonical;
}

function canonicalBytes(value: unknown): CapturedHex {
  if (!isHexBytes(value)) return invalidProviderParams();
  const canonical = value.toLowerCase();
  if (!isHexBytes(canonical)) return invalidProviderParams();
  return canonical;
}

function exactLowercaseBytes(
  value: unknown,
  minimumBytes: number,
  maximumBytes: number,
): CapturedHex {
  if (typeof value !== "string" || !LOWERCASE_BYTES.test(value)) return invalidProviderParams();
  const byteLength = (value.length - 2) / 2;
  if (byteLength < minimumBytes || byteLength > maximumBytes) return invalidProviderParams();
  return value as CapturedHex;
}

function acceptOnly(record: ExactRecord, keys: readonly string[]): void {
  for (const key of Object.keys(record)) {
    if (!keys.includes(key)) invalidProviderParams();
  }
}

function requireFields(record: ExactRecord, keys: readonly string[]): void {
  for (const key of keys) {
    if (!Object.hasOwn(record, key)) invalidProviderParams();
  }
}

function isArray(value: object): boolean {
  try {
    return Array.isArray(value);
  } catch {
    return invalidProviderParams();
  }
}

type CaptureJsonAssignment = (value: CapturedJsonValue) => void;

type CaptureJsonTask =
  | Readonly<{ kind: "value"; value: unknown; assign: CaptureJsonAssignment }>
  | Readonly<{ kind: "record"; record: ExactRecord; assign: CaptureJsonAssignment }>
  | Readonly<{
      kind: "complete-array";
      output: CapturedJsonValue[];
      assign: CaptureJsonAssignment;
    }>
  | Readonly<{
      kind: "complete-record";
      output: Record<string, CapturedJsonValue>;
      assign: CaptureJsonAssignment;
    }>;

type CaptureJsonSeed =
  | Readonly<{ kind: "value"; value: unknown }>
  | Readonly<{ kind: "record"; record: ExactRecord }>;

function runJsonCapture(seed: CaptureJsonSeed, context: CaptureContext): CapturedJsonValue {
  let result: CapturedJsonValue | undefined;
  const assignResult: CaptureJsonAssignment = (value) => {
    result = value;
  };
  const tasks: CaptureJsonTask[] = [
    seed.kind === "value"
      ? { kind: "value", value: seed.value, assign: assignResult }
      : { kind: "record", record: seed.record, assign: assignResult },
  ];

  while (tasks.length > 0) {
    const task = tasks.pop();
    if (task === undefined) return invalidProviderParams();

    if (task.kind === "complete-array") {
      task.assign(Object.freeze(task.output));
      continue;
    }
    if (task.kind === "complete-record") {
      task.assign(Object.freeze(task.output));
      continue;
    }

    if (task.kind === "record") {
      const output: Record<string, CapturedJsonValue> = Object.create(null);
      tasks.push({ kind: "complete-record", output, assign: task.assign });
      const keys = Object.keys(task.record);
      for (let index = keys.length - 1; index >= 0; index -= 1) {
        const key = keys[index];
        if (key === undefined) return invalidProviderParams();
        tasks.push({
          kind: "value",
          value: task.record[key],
          assign(value) {
            output[key] = value;
          },
        });
      }
      continue;
    }

    const value = task.value;
    if (value === null || typeof value === "string" || typeof value === "boolean") {
      task.assign(value);
      continue;
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value)) return invalidProviderParams();
      task.assign(value);
      continue;
    }
    if (typeof value !== "object") return invalidProviderParams();

    if (isArray(value)) {
      const entries = captureDenseArray(
        value,
        "wallet_sendCalls capability JSON array",
        context,
        invalidProviderParams,
      );
      const output: CapturedJsonValue[] = [];
      tasks.push({ kind: "complete-array", output, assign: task.assign });
      for (let index = entries.length - 1; index >= 0; index -= 1) {
        tasks.push({
          kind: "value",
          value: entries[index],
          assign(captured) {
            output[index] = captured;
          },
        });
      }
      continue;
    }

    tasks.push({
      kind: "record",
      record: captureRecord(
        value,
        "wallet_sendCalls capability JSON object",
        context,
        invalidProviderParams,
      ),
      assign: task.assign,
    });
  }

  if (result === undefined) return invalidProviderParams();
  return result;
}

function captureJsonObject(record: ExactRecord, context: CaptureContext): CapturedJsonObject {
  const captured = runJsonCapture({ kind: "record", record }, context);
  if (captured === null || typeof captured !== "object" || isCapturedJsonArray(captured)) {
    return invalidProviderParams();
  }
  return captured;
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function isCapturedJsonArray(value: CapturedJsonValue): value is readonly CapturedJsonValue[] {
  return Array.isArray(value);
}

function jsonStringByteLength(value: string): number {
  let bytes = 2;
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit === 0x22 || codeUnit === 0x5c) {
      bytes += 2;
    } else if (
      codeUnit === 0x08 ||
      codeUnit === 0x09 ||
      codeUnit === 0x0a ||
      codeUnit === 0x0c ||
      codeUnit === 0x0d
    ) {
      bytes += 2;
    } else if (codeUnit <= 0x1f) {
      bytes += 6;
    } else if (codeUnit <= 0x7f) {
      bytes += 1;
    } else if (codeUnit <= 0x7ff) {
      bytes += 2;
    } else if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else {
        bytes += 6;
      }
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      bytes += 6;
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

/** Descriptor-free byte length of the JSON encoding for an already captured value. */
function jsonByteLength(value: CapturedJsonValue): number {
  let bytes = 0;
  const pending: CapturedJsonValue[] = [value];
  while (pending.length > 0) {
    const entry = pending.pop();
    if (entry === undefined) return invalidProviderParams();
    if (entry === null) {
      bytes += 4;
    } else if (entry === true) {
      bytes += 4;
    } else if (entry === false) {
      bytes += 5;
    } else if (typeof entry === "string") {
      bytes += jsonStringByteLength(entry);
    } else if (typeof entry === "number") {
      bytes += String(Object.is(entry, -0) ? 0 : entry).length;
    } else if (isCapturedJsonArray(entry)) {
      bytes += 2 + Math.max(0, entry.length - 1);
      for (const child of entry) pending.push(child);
    } else {
      const keys = Object.keys(entry);
      bytes += 2 + Math.max(0, keys.length - 1);
      for (const key of keys) {
        const child = entry[key];
        if (child === undefined) return invalidProviderParams();
        bytes += jsonStringByteLength(key) + 1;
        pending.push(child);
      }
    }
  }
  return bytes;
}

function captureCapabilities(
  value: unknown,
  scope: WalletCapabilityScope,
  method: WalletCapabilityMethod,
  context: CaptureContext,
  budget: CaptureBudget,
): CapturedWalletCapabilities {
  const capabilityMap = captureRecord(
    value,
    "wallet_sendCalls capabilities",
    context,
    invalidProviderParams,
  );
  const values: Record<string, CapturedJsonObject> = Object.create(null);
  const ignored: string[] = [];
  let paymasterService: CapturedWalletPaymasterService | undefined;

  for (const name of Object.keys(capabilityMap)) {
    const capability = captureJsonObject(
      captureRecord(
        capabilityMap[name],
        "wallet_sendCalls capability",
        context,
        invalidProviderParams,
      ),
      context,
    );
    const optional = capability.optional;
    if (Object.hasOwn(capability, "optional") && typeof optional !== "boolean") {
      return invalidProviderParams();
    }
    values[name] = capability;
    if (!isHandledWalletCapability(name, method, scope)) {
      ignored.push(name);
      if (optional !== true) budget.hasUnsupportedRequiredCapability = true;
    } else if (name === "paymasterService") {
      paymasterService = capturePaymasterServiceCapability(capability);
    }
  }

  const capturedValues = Object.freeze(values);
  budget.capabilityJsonBytes += jsonByteLength(capturedValues);
  if (budget.capabilityJsonBytes > EIP5792_CAPTURE_LIMITS.capabilityJsonBytes) {
    return rpcFail(5740);
  }
  const captured = {
    values: capturedValues,
    ignored: Object.freeze(ignored),
    ...(paymasterService === undefined ? {} : { paymasterService }),
  };
  Object.setPrototypeOf(captured, null);
  return Object.freeze(captured);
}

function capturedId(value: unknown, oversizedBundle: boolean): string {
  const id = value;
  if (typeof id !== "string" || id.length === 0) return invalidProviderParams();
  if (
    id.length > EIP5792_CAPTURE_LIMITS.idUtf8Bytes ||
    utf8Bytes(id) > EIP5792_CAPTURE_LIMITS.idUtf8Bytes
  ) {
    return oversizedBundle ? rpcFail(5740) : invalidProviderParams();
  }
  return id;
}

function optionalId(record: ExactRecord): string | undefined {
  if (!Object.hasOwn(record, "id")) return undefined;
  return capturedId(record.id, true);
}

function optionalFrom(record: ExactRecord): CapturedAddress | undefined {
  if (!Object.hasOwn(record, "from")) return undefined;
  return canonicalAddress(record.from);
}

function capturePreparedCallsKey(
  value: unknown,
  context: CaptureContext,
): CapturedWalletPreparedCallsKey {
  const record = captureRecord(value, "wallet prepared calls key", context, invalidProviderParams);
  acceptOnly(record, PREPARED_CALLS_KEY_KEYS);
  requireFields(record, PREPARED_CALLS_KEY_KEYS);
  const type = record.type;
  if (type !== "secp256k1" && type !== "webauthn-p256") {
    return invalidProviderParams();
  }
  if (record.prehash !== false) return invalidProviderParams();

  let publicKey: CapturedHex;
  if (type === "secp256k1") {
    if (
      typeof record.publicKey !== "string" ||
      !UNCOMPRESSED_SECP256K1_PUBLIC_KEY.test(record.publicKey)
    ) {
      return invalidProviderParams();
    }
    publicKey = record.publicKey as CapturedHex;
  } else {
    publicKey = exactLowercaseBytes(
      record.publicKey,
      1,
      ERC7836_CAPTURE_LIMITS.webauthnPublicKeyBytes,
    );
  }

  const captured = {
    type,
    publicKey,
    prehash: false,
  } as const;
  Object.setPrototypeOf(captured, null);
  return Object.freeze(captured);
}

function capturePreparedCallsContext(
  value: unknown,
  context: CaptureContext,
): CapturedWalletPreparedCallsContext {
  const record = captureRecord(
    value,
    "wallet prepared calls context",
    context,
    invalidProviderParams,
  );
  acceptOnly(record, PREPARED_CALLS_CONTEXT_KEYS);
  requireFields(record, PREPARED_CALLS_CONTEXT_KEYS);
  if (record.version !== OAATH_PREPARED_CALL_CONTEXT_TOKEN_VERSION) {
    return invalidProviderParams();
  }
  if (typeof record.id !== "string" || !HASH.test(record.id)) return invalidProviderParams();
  const id = record.id as Hash;

  const captured = {
    version: OAATH_PREPARED_CALL_CONTEXT_TOKEN_VERSION,
    id,
  };
  Object.setPrototypeOf(captured, null);
  return Object.freeze(captured);
}

function captureCall(
  value: unknown,
  method: WalletCapabilityMethod,
  context: CaptureContext,
  budget: CaptureBudget,
): CapturedWalletCallDraft {
  const record = captureRecord(value, "wallet_sendCalls call", context, invalidProviderParams);
  acceptOnly(record, CALL_KEYS);

  const to = Object.hasOwn(record, "to") ? canonicalAddress(record.to) : null;

  let data: CapturedHex | undefined;
  if (Object.hasOwn(record, "data")) {
    if (!isHexBytes(record.data)) return invalidProviderParams();
    budget.calldataBytes += (record.data.length - 2) / 2;
    if (budget.calldataBytes > EIP5792_CAPTURE_LIMITS.calldataBytes) {
      return rpcFail(5740);
    }
    data = canonicalBytes(record.data);
  }

  let valueQuantity: CapturedHex | undefined;
  if (Object.hasOwn(record, "value")) {
    if (!isCanonicalQuantity(record.value)) return invalidProviderParams();
    valueQuantity = record.value;
  }

  const capabilities = Object.hasOwn(record, "capabilities")
    ? captureCapabilities(record.capabilities, "call", method, context, budget)
    : undefined;

  const wire: Record<string, CapturedJsonValue> = Object.create(null);
  if (to !== null) wire.to = to;
  if (data !== undefined) wire.data = data;
  if (valueQuantity !== undefined) wire.value = valueQuantity;
  if (capabilities !== undefined) wire.capabilities = capabilities.values;

  const draft = {
    to,
    ...(data === undefined ? {} : { data }),
    ...(valueQuantity === undefined ? {} : { value: valueQuantity }),
    ...(capabilities === undefined ? {} : { capabilities }),
    wire: Object.freeze(wire),
  };
  Object.setPrototypeOf(draft, null);
  return Object.freeze(draft);
}

function completeCall(draft: CapturedWalletCallDraft): CapturedWalletCall {
  if (draft.to === null) return refuseProviderExecution();
  const call = {
    to: draft.to,
    ...(draft.data === undefined ? {} : { data: draft.data }),
    ...(draft.value === undefined ? {} : { value: draft.value }),
    ...(draft.capabilities === undefined ? {} : { capabilities: draft.capabilities }),
  };
  Object.setPrototypeOf(call, null);
  return Object.freeze(call);
}

function configuredChain(chainId: number): CapturedHex {
  if (!Number.isSafeInteger(chainId) || chainId < 1) return rpcFail(-32603);
  const value = `0x${chainId.toString(16)}`;
  if (!isCanonicalChainId(value)) return rpcFail(-32603);
  return value;
}

/**
 * Captures exactly one Final EIP-5792 `wallet_sendCalls` bundle for the
 * configured provider chain. This function does not generate a missing ID and
 * performs no account authorization or execution effects.
 */
export function captureWalletSendCallsParams(
  params: unknown,
  configuredChainId: number,
): CapturedWalletSendCallsParams {
  const expectedChainId = configuredChain(configuredChainId);
  const context: CaptureContext = new WeakSet();
  const entries = captureDenseArray(
    params,
    "wallet_sendCalls params",
    context,
    invalidProviderParams,
  );
  if (entries.length !== 1) return invalidProviderParams();

  const bundle = captureRecord(
    entries[0],
    "wallet_sendCalls bundle",
    context,
    invalidProviderParams,
  );
  acceptOnly(bundle, BUNDLE_KEYS);
  requireFields(bundle, REQUIRED_BUNDLE_KEYS);
  if (bundle.version !== "2.0.0") return invalidProviderParams();

  const id = optionalId(bundle);
  const from = optionalFrom(bundle);
  const chainId = canonicalChainId(bundle.chainId);
  if (chainId !== expectedChainId) return rpcFail(5710);
  const atomic = captureAtomicCapability(bundle.atomicRequired);
  const atomicRequired = atomic.atomicRequired;

  const budget: CaptureBudget = {
    calldataBytes: 0,
    capabilityJsonBytes: 0,
    hasUnsupportedRequiredCapability: false,
  };
  const callEntries = captureDenseArray(
    bundle.calls,
    "wallet_sendCalls calls",
    context,
    invalidProviderParams,
  );
  if (callEntries.length === 0) return invalidProviderParams();
  if (callEntries.length > EIP5792_CAPTURE_LIMITS.calls) return rpcFail(5740);

  const drafts: CapturedWalletCallDraft[] = [];
  const wireCalls: CapturedJsonValue[] = [];
  for (const entry of callEntries) {
    const draft = captureCall(entry, "wallet_sendCalls", context, budget);
    drafts.push(draft);
    wireCalls.push(draft.wire);
  }
  const capabilities = Object.hasOwn(bundle, "capabilities")
    ? captureCapabilities(bundle.capabilities, "bundle", "wallet_sendCalls", context, budget)
    : undefined;

  const wire: Record<string, CapturedJsonValue> = Object.create(null);
  wire.version = "2.0.0";
  if (id !== undefined) wire.id = id;
  if (from !== undefined) wire.from = from;
  wire.chainId = chainId;
  wire.atomicRequired = atomicRequired;
  wire.calls = Object.freeze(wireCalls);
  if (capabilities !== undefined) wire.capabilities = capabilities.values;

  // Count each decoded calldata byte once rather than counting both of its hex
  // nibbles. Calldata has its own 128 KiB budget; this keeps that exact boundary
  // reachable while the aggregate budget still covers every captured payload.
  const bundleBytes = jsonByteLength(Object.freeze(wire)) - budget.calldataBytes;
  if (bundleBytes > EIP5792_CAPTURE_LIMITS.bundleBytes) return rpcFail(5740);
  if (budget.hasUnsupportedRequiredCapability) return rpcFail(5700);

  const calls: CapturedWalletCall[] = [];
  for (const draft of drafts) calls.push(completeCall(draft));

  const version: "2.0.0" = "2.0.0";
  const captured = {
    version,
    ...(id === undefined ? {} : { id }),
    ...(from === undefined ? {} : { from }),
    chainId,
    atomicRequired,
    calls: Object.freeze(calls),
    ...(capabilities === undefined ? {} : { capabilities }),
  };
  Object.setPrototypeOf(captured, null);
  return Object.freeze(captured);
}

/**
 * Captures OAAth's exact experimental ERC-7836 `wallet_prepareCalls` profile.
 * A missing chain resolves to the configured provider chain; preparation and
 * every authority, persistence, signing, and submission effect remain outside
 * this hostile-input boundary.
 */
export function captureWalletPrepareCallsParams(
  params: unknown,
  configuredChainId: number,
): CapturedWalletPrepareCallsParams {
  const expectedChainId = configuredChain(configuredChainId);
  const context: CaptureContext = new WeakSet();
  const entries = captureDenseArray(
    params,
    "wallet_prepareCalls params",
    context,
    invalidProviderParams,
  );
  if (entries.length !== 1) return invalidProviderParams();

  const bundle = captureRecord(
    entries[0],
    "wallet_prepareCalls bundle",
    context,
    invalidProviderParams,
  );
  acceptOnly(bundle, PREPARE_CALLS_KEYS);
  requireFields(bundle, REQUIRED_PREPARE_CALLS_KEYS);
  if (bundle.version !== "1") return invalidProviderParams();

  let chainId = expectedChainId;
  if (Object.hasOwn(bundle, "chainId")) {
    chainId = canonicalChainId(bundle.chainId);
    if (chainId !== expectedChainId) return rpcFail(5710);
  }
  const from = optionalFrom(bundle);
  const key = capturePreparedCallsKey(bundle.key, context);

  const budget: CaptureBudget = {
    calldataBytes: 0,
    capabilityJsonBytes: 0,
    hasUnsupportedRequiredCapability: false,
  };
  const callEntries = captureDenseArray(
    bundle.calls,
    "wallet_prepareCalls calls",
    context,
    invalidProviderParams,
  );
  if (callEntries.length === 0) return invalidProviderParams();
  if (callEntries.length > EIP5792_CAPTURE_LIMITS.calls) return rpcFail(5740);

  const drafts: CapturedWalletCallDraft[] = [];
  const wireCalls: CapturedJsonValue[] = [];
  for (const entry of callEntries) {
    const draft = captureCall(entry, "wallet_prepareCalls", context, budget);
    drafts.push(draft);
    wireCalls.push(draft.wire);
  }
  const capabilities = Object.hasOwn(bundle, "capabilities")
    ? captureCapabilities(bundle.capabilities, "bundle", "wallet_prepareCalls", context, budget)
    : undefined;

  const wireKey: CapturedJsonObject = Object.freeze({
    type: key.type,
    publicKey: key.publicKey,
    prehash: key.prehash,
  });
  const wire: Record<string, CapturedJsonValue> = Object.create(null);
  wire.version = "1";
  wire.chainId = chainId;
  if (from !== undefined) wire.from = from;
  wire.calls = Object.freeze(wireCalls);
  if (capabilities !== undefined) wire.capabilities = capabilities.values;
  wire.key = wireKey;

  const bundleBytes = jsonByteLength(Object.freeze(wire)) - budget.calldataBytes;
  if (bundleBytes > EIP5792_CAPTURE_LIMITS.bundleBytes) return rpcFail(5740);
  if (budget.hasUnsupportedRequiredCapability) return rpcFail(5700);

  const calls: CapturedWalletCall[] = [];
  for (const draft of drafts) calls.push(completeCall(draft));

  const version: "1" = "1";
  const captured = {
    version,
    chainId,
    ...(from === undefined ? {} : { from }),
    calls: Object.freeze(calls),
    ...(capabilities === undefined ? {} : { capabilities }),
    key,
  };
  Object.setPrototypeOf(captured, null);
  return Object.freeze(captured);
}

/** Exact capture of one echoed experimental ERC-7836 prepared-call request. */
export function captureWalletSendPreparedCallsParams(
  params: unknown,
  configuredChainId: number,
): CapturedWalletSendPreparedCallsParams {
  const expectedChainId = configuredChain(configuredChainId);
  const context: CaptureContext = new WeakSet();
  const entries = captureDenseArray(
    params,
    "wallet_sendPreparedCalls params",
    context,
    invalidProviderParams,
  );
  if (entries.length !== 1) return invalidProviderParams();

  const request = captureRecord(
    entries[0],
    "wallet_sendPreparedCalls request",
    context,
    invalidProviderParams,
  );
  acceptOnly(request, SEND_PREPARED_CALLS_KEYS);
  requireFields(request, SEND_PREPARED_CALLS_KEYS);
  if (request.version !== "1") return invalidProviderParams();
  const chainId = canonicalChainId(request.chainId);
  if (chainId !== expectedChainId) return rpcFail(5710);

  const budget: CaptureBudget = {
    calldataBytes: 0,
    capabilityJsonBytes: 0,
    hasUnsupportedRequiredCapability: false,
  };
  const capabilities = captureCapabilities(
    request.capabilities,
    "bundle",
    "wallet_sendPreparedCalls",
    context,
    budget,
  );
  const preparedContext = capturePreparedCallsContext(request.context, context);
  const key = capturePreparedCallsKey(request.key, context);
  const signature = exactLowercaseBytes(
    request.signature,
    1,
    ERC7836_CAPTURE_LIMITS.signatureBytes,
  );

  const wire: CapturedJsonObject = Object.freeze({
    version: "1",
    chainId,
    capabilities: capabilities.values,
    context: Object.freeze({
      version: preparedContext.version,
      id: preparedContext.id,
    }),
    key: Object.freeze({
      type: key.type,
      publicKey: key.publicKey,
      prehash: key.prehash,
    }),
    signature,
  });
  if (jsonByteLength(wire) > EIP5792_CAPTURE_LIMITS.bundleBytes) return rpcFail(5740);
  if (budget.hasUnsupportedRequiredCapability) return rpcFail(5700);

  const version: "1" = "1";
  const captured = {
    version,
    chainId,
    capabilities,
    context: preparedContext,
    key,
    signature,
  };
  Object.setPrototypeOf(captured, null);
  return Object.freeze(captured);
}

/** Exact shared params capture for `wallet_getCallsStatus` and `wallet_showCallsStatus`. */
export function captureWalletCallsStatusParams(params: unknown): string {
  const entries = captureDenseArray(
    params,
    "wallet calls status params",
    new WeakSet(),
    invalidProviderParams,
  );
  if (entries.length !== 1) return invalidProviderParams();
  return capturedId(entries[0], false);
}

/** Exact Final EIP-5792 `[address, chainIds?]` capability-query capture. */
export function captureWalletGetCapabilitiesParams(
  params: unknown,
): CapturedWalletGetCapabilitiesParams {
  const context: CaptureContext = new WeakSet();
  const entries = captureDenseArray(
    params,
    "wallet_getCapabilities params",
    context,
    invalidProviderParams,
  );
  if (entries.length !== 1 && entries.length !== 2) return invalidProviderParams();

  const address = canonicalAddress(entries[0]);
  let chainIds: readonly CapturedHex[] | undefined;
  if (entries.length === 2) {
    const requested = captureDenseArray(
      entries[1],
      "wallet_getCapabilities chain ids",
      context,
      invalidProviderParams,
    );
    chainIds = Object.freeze(
      requested.map((chainId) => {
        return canonicalChainId(chainId);
      }),
    );
  }

  const captured = {
    address,
    ...(chainIds === undefined ? {} : { chainIds }),
  };
  Object.setPrototypeOf(captured, null);
  return Object.freeze(captured);
}
