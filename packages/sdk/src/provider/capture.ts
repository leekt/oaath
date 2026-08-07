/**
 * Exact hostile-input capture for Final EIP-5792 `wallet_sendCalls` params.
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
  isHandledWalletCapability,
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
const CANONICAL_CHAIN_ID = /^0x[1-9a-fA-F][0-9a-fA-F]*$/u;
const CANONICAL_QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/u;
const HASH = /^0x[0-9a-f]{64}$/u;

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

export const EIP5792_CAPTURE_LIMITS = Object.freeze({
  idUtf8Bytes: 4_096,
  calls: 64,
  calldataBytes: 128 * 1_024,
  capabilityJsonBytes: 64 * 1_024,
  bundleBytes: 256 * 1_024,
});

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

/**
 * Capability input and its explicit disposition. No named handlers exist in
 * this slice, so every accepted capability name appears in `ignored` and has no
 * execution effect. The exact JSON-compatible values remain in `values`.
 */
export interface CapturedWalletCapabilities {
  readonly values: Readonly<Record<string, CapturedJsonObject>>;
  readonly ignored: readonly string[];
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
    if (!isHandledWalletCapability(name, scope)) {
      ignored.push(name);
      if (optional !== true) budget.hasUnsupportedRequiredCapability = true;
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

function captureCall(
  value: unknown,
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
    ? captureCapabilities(record.capabilities, "call", context, budget)
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
    const draft = captureCall(entry, context, budget);
    drafts.push(draft);
    wireCalls.push(draft.wire);
  }
  const capabilities = Object.hasOwn(bundle, "capabilities")
    ? captureCapabilities(bundle.capabilities, "bundle", context, budget)
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
