import { encodeAbiParameters, type Hex, keccak256 } from "viem";
import {
  type CaptureContext,
  captureDenseArray,
  captureRecord,
  exactCapturedRecord,
  exactRecord,
} from "./internal/exact-record.js";

export const OAATH_GRANT_POLICY_VERSION = "oaath.grant-policy/v1" as const;
export const OAATH_GRANT_POLICY_USAGE_VERSION = "oaath.grant-policy-usage/v1" as const;
export const OAATH_GRANT_POLICY_HASH_DOMAIN = "@oaath/protocol:grant-policy" as const;
export const OAATH_GRANT_POLICY_CALLS_HASH_DOMAIN = "@oaath/protocol:grant-policy-calls" as const;

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const SELECTOR = /^0x[0-9a-f]{8}$/u;
const WORD = /^0x[0-9a-f]{64}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const ZERO_SELECTOR = "0x00000000";
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_UINT48 = 2 ** 48 - 1;
const MAX_ARGUMENT_INDEX = Math.floor(Number.MAX_SAFE_INTEGER / 32);
const MAX_GRANT_ID_LENGTH = 256;

export type GrantPolicyErrorCode =
  | "grant_policy_invalid"
  | "grant_policy_attenuation_input_invalid"
  | "grant_policy_coverage_input_invalid";

export class OaathGrantPolicyError extends Error {
  readonly code: GrantPolicyErrorCode;

  constructor(code: GrantPolicyErrorCode, message: string) {
    super(message);
    this.name = "OaathGrantPolicyError";
    this.code = code;
  }
}

export interface GrantPolicyArgumentEquality {
  /** Zero-based 32-byte ABI word after the selector. */
  readonly index: number;
  readonly value: `0x${string}`;
}

export interface GrantPolicyCall {
  readonly target: `0x${string}`;
  readonly selector: `0x${string}`;
  /** Canonical decimal uint256 string, scoped to this call within a batch. */
  readonly valueLimit: string;
  /** The sole argument rule: equality on fixed 32-byte ABI words. */
  readonly argumentEquals: readonly Readonly<GrantPolicyArgumentEquality>[];
}

export interface GrantPolicy {
  readonly version: typeof OAATH_GRANT_POLICY_VERSION;
  readonly calls: readonly Readonly<GrantPolicyCall>[];
  /** Inclusive Unix timestamp, encoded as uint48. */
  readonly validAfter: number;
  /** Inclusive Unix timestamp, or null as the only indefinite representation. */
  readonly validUntil: number | null;
  /** Each covered UserOperation consumes one use on its concrete chain. */
  readonly perChainOperationLimit: number;
}

export interface GrantPolicyUsageCheckpoint {
  readonly blockNumber: string;
  readonly blockHash: `0x${string}`;
  readonly observedAt: number;
}

export interface CompleteGrantPolicyUsageEvidence {
  readonly version: typeof OAATH_GRANT_POLICY_USAGE_VERSION;
  readonly status: "complete";
  readonly grantId: string;
  readonly chainId: number;
  /**
   * Complete count of finalized included executions on this chain. Both successful and reverted
   * executions consume first-party rate-limit allowance.
   */
  readonly finalizedOperationCount: string;
  readonly through: Readonly<GrantPolicyUsageCheckpoint>;
}

export interface UnavailableGrantPolicyUsageEvidence {
  readonly version: typeof OAATH_GRANT_POLICY_USAGE_VERSION;
  readonly status: "unavailable";
  readonly reason: "unreadable" | "non_finalized" | "canonicality_unproven";
}

export type GrantPolicyUsageEvidence =
  | CompleteGrantPolicyUsageEvidence
  | UnavailableGrantPolicyUsageEvidence;

export interface GrantPolicyCoverageCall {
  readonly target: `0x${string}`;
  readonly data: `0x${string}`;
  readonly value: string;
}

export interface GrantPolicyCoverageInput {
  readonly policy: GrantPolicy;
  readonly grantId: string;
  readonly chainId: number;
  readonly evaluatedAt: number;
  readonly calls: readonly Readonly<GrantPolicyCoverageCall>[];
  /** Null explicitly means that complete usage evidence is missing. */
  readonly usage: Readonly<GrantPolicyUsageEvidence> | null;
}

export type GrantPolicyCoverageDeniedReason =
  | "empty_calls"
  | "outside_time_window"
  | "call_not_permitted"
  | "argument_not_permitted"
  | "value_limit_exceeded"
  | "operation_limit_exhausted";

export type GrantPolicyCoverageInconclusiveReason =
  | "usage_missing"
  | "usage_unreadable"
  | "usage_non_finalized"
  | "usage_canonicality_unproven"
  | "usage_identity_mismatch";

export type GrantPolicyCoverageResult =
  | Readonly<{
      status: "covered";
      policyHash: `0x${string}`;
      chainId: number;
      finalizedOperationCount: string;
      uses: 1;
    }>
  | Readonly<{
      status: "denied";
      policyHash: `0x${string}`;
      chainId: number;
      reason: GrantPolicyCoverageDeniedReason;
      callIndex: number | null;
    }>
  | Readonly<{
      status: "inconclusive";
      policyHash: `0x${string}`;
      chainId: number;
      reason: GrantPolicyCoverageInconclusiveReason;
    }>;

function invalid(code: GrantPolicyErrorCode, message: string): never {
  throw new OaathGrantPolicyError(code, message);
}

function failFor(code: GrantPolicyErrorCode): (message: string) => never {
  return (message) => invalid(code, message);
}

function captureFailure<Value>(code: GrantPolicyErrorCode, action: () => Value): Value {
  try {
    return action();
  } catch (error) {
    if (error instanceof OaathGrantPolicyError) throw error;
    return invalid(code, "grant policy input could not be captured safely");
  }
}

function safeInteger(
  value: unknown,
  label: string,
  code: GrantPolicyErrorCode,
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    (value as number) < minimum ||
    (value as number) > maximum
  ) {
    return invalid(code, `${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value as number;
}

function uint256(value: unknown, label: string, code: GrantPolicyErrorCode): string {
  if (typeof value !== "string" || !DECIMAL_UINT.test(value) || BigInt(value) > MAX_UINT256) {
    return invalid(code, `${label} must be a canonical decimal uint256 string`);
  }
  return value;
}

function address(value: unknown, label: string, code: GrantPolicyErrorCode): `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value) || value === ZERO_ADDRESS) {
    return invalid(code, `${label} must be a nonzero lowercase address`);
  }
  return value as `0x${string}`;
}

function selector(value: unknown, label: string, code: GrantPolicyErrorCode): `0x${string}` {
  if (typeof value !== "string" || !SELECTOR.test(value) || value === ZERO_SELECTOR) {
    return invalid(code, `${label} must be a nonzero lowercase 4-byte selector`);
  }
  return value as `0x${string}`;
}

function word(value: unknown, label: string, code: GrantPolicyErrorCode): `0x${string}` {
  if (typeof value !== "string" || !WORD.test(value)) {
    return invalid(code, `${label} must be a lowercase 32-byte word`);
  }
  return value as `0x${string}`;
}

function hash(value: unknown, label: string, code: GrantPolicyErrorCode): `0x${string}` {
  if (typeof value !== "string" || !HASH.test(value)) {
    return invalid(code, `${label} must be a lowercase 32-byte hash`);
  }
  return value as `0x${string}`;
}

function canonicalGrantId(value: unknown, code: GrantPolicyErrorCode): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_GRANT_ID_LENGTH ||
    value !== value.trim()
  ) {
    return invalid(code, "grantId must be a bounded canonical string");
  }
  return value;
}

function parseArgumentEquality(
  value: unknown,
  code: GrantPolicyErrorCode,
  context: CaptureContext,
  callIndex: number,
  argumentIndex: number,
): Readonly<GrantPolicyArgumentEquality> {
  const record = exactRecord(
    value,
    ["index", "value"],
    `grant policy call ${callIndex} argument equality ${argumentIndex}`,
    context,
    failFor(code),
  );
  return Object.freeze({
    index: safeInteger(
      record.index,
      `grant policy call ${callIndex} argument equality index`,
      code,
      0,
      MAX_ARGUMENT_INDEX,
    ),
    value: word(record.value, `grant policy call ${callIndex} argument equality value`, code),
  });
}

function parseCall(
  value: unknown,
  code: GrantPolicyErrorCode,
  context: CaptureContext,
  index: number,
): Readonly<GrantPolicyCall> {
  const record = exactRecord(
    value,
    ["target", "selector", "valueLimit", "argumentEquals"],
    `grant policy call ${index}`,
    context,
    failFor(code),
  );
  const equalityInputs = captureDenseArray(
    record.argumentEquals,
    `grant policy call ${index} argumentEquals`,
    context,
    failFor(code),
  );
  const argumentEquals = equalityInputs.map((entry, argumentIndex) =>
    parseArgumentEquality(entry, code, context, index, argumentIndex),
  );
  for (let argumentIndex = 1; argumentIndex < argumentEquals.length; argumentIndex += 1) {
    const previous = argumentEquals[argumentIndex - 1];
    const current = argumentEquals[argumentIndex];
    if (!previous || !current || previous.index >= current.index) {
      return invalid(code, `grant policy call ${index} argumentEquals must be unique and sorted`);
    }
  }
  return Object.freeze({
    target: address(record.target, `grant policy call ${index} target`, code),
    selector: selector(record.selector, `grant policy call ${index} selector`, code),
    valueLimit: uint256(record.valueLimit, `grant policy call ${index} valueLimit`, code),
    argumentEquals: Object.freeze(argumentEquals),
  });
}

function callKey(call: GrantPolicyCall): string {
  return `${call.target}:${call.selector}`;
}

function capturePolicy(
  value: unknown,
  code: GrantPolicyErrorCode,
  context: CaptureContext,
): Readonly<GrantPolicy> {
  const record = exactRecord(
    value,
    ["version", "calls", "validAfter", "validUntil", "perChainOperationLimit"],
    "grant policy",
    context,
    failFor(code),
  );
  if (record.version !== OAATH_GRANT_POLICY_VERSION) {
    return invalid(code, "grant policy version is unsupported");
  }
  const callInputs = captureDenseArray(record.calls, "grant policy calls", context, failFor(code));
  if (callInputs.length === 0) return invalid(code, "grant policy calls must not be empty");
  const calls = callInputs.map((entry, index) => parseCall(entry, code, context, index));
  for (let index = 1; index < calls.length; index += 1) {
    const previous = calls[index - 1];
    const current = calls[index];
    if (!previous || !current || callKey(previous) >= callKey(current)) {
      return invalid(code, "grant policy calls must have unique, sorted target-selector keys");
    }
  }
  const validAfter = safeInteger(record.validAfter, "grant policy validAfter", code, 0, MAX_UINT48);
  const validUntil =
    record.validUntil === null
      ? null
      : safeInteger(record.validUntil, "grant policy validUntil", code, 1, MAX_UINT48);
  if (validUntil !== null && validAfter > validUntil) {
    return invalid(code, "grant policy time window is inverted");
  }
  return Object.freeze({
    version: OAATH_GRANT_POLICY_VERSION,
    calls: Object.freeze(calls),
    validAfter,
    validUntil,
    perChainOperationLimit: safeInteger(
      record.perChainOperationLimit,
      "grant policy perChainOperationLimit",
      code,
      1,
      MAX_UINT48,
    ),
  });
}

export function parseGrantPolicy(value: unknown): Readonly<GrantPolicy> {
  return captureFailure("grant_policy_invalid", () =>
    capturePolicy(value, "grant_policy_invalid", new WeakSet()),
  );
}

function encodeCapturedGrantPolicy(policy: GrantPolicy): Hex {
  return encodeAbiParameters(
    [
      { type: "string", name: "domain" },
      { type: "string", name: "version" },
      {
        type: "tuple[]",
        name: "calls",
        components: [
          { type: "address", name: "target" },
          { type: "bytes4", name: "selector" },
          { type: "uint256", name: "valueLimit" },
          {
            type: "tuple[]",
            name: "argumentEquals",
            components: [
              { type: "uint64", name: "index" },
              { type: "bytes32", name: "value" },
            ],
          },
        ],
      },
      { type: "uint48", name: "validAfter" },
      { type: "bool", name: "hasValidUntil" },
      { type: "uint48", name: "validUntil" },
      { type: "uint48", name: "perChainOperationLimit" },
    ],
    [
      OAATH_GRANT_POLICY_HASH_DOMAIN,
      policy.version,
      policy.calls.map((call) => ({
        target: call.target,
        selector: call.selector,
        valueLimit: BigInt(call.valueLimit),
        argumentEquals: call.argumentEquals.map((argument) => ({
          index: BigInt(argument.index),
          value: argument.value,
        })),
      })),
      policy.validAfter,
      policy.validUntil !== null,
      policy.validUntil ?? 0,
      policy.perChainOperationLimit,
    ],
  );
}

export function encodeGrantPolicy(value: unknown): Hex {
  return encodeCapturedGrantPolicy(parseGrantPolicy(value));
}

export function hashGrantPolicy(value: unknown): `0x${string}` {
  return keccak256(encodeGrantPolicy(value));
}

/**
 * Digest of one exact call set alone, independent of the policy's time window
 * and rate limit. An adopter that reviewed a call set pins this digest; the
 * verifying side recomputes it from the calls the Grant's policy permits, so
 * equality states "the reviewed calls are exactly the permitted calls" without
 * shipping the policy itself. Input calls must already be in canonical policy
 * order (unique, sorted target-selector keys).
 */
export function hashGrantPolicyCalls(value: unknown): `0x${string}` {
  return captureFailure("grant_policy_invalid", () => {
    const code = "grant_policy_invalid" as const;
    const context: CaptureContext = new WeakSet();
    const callInputs = captureDenseArray(value, "grant policy calls", context, failFor(code));
    if (callInputs.length === 0) return invalid(code, "grant policy calls must not be empty");
    const calls = callInputs.map((entry, index) => parseCall(entry, code, context, index));
    for (let index = 1; index < calls.length; index += 1) {
      const previous = calls[index - 1];
      const current = calls[index];
      if (!previous || !current || callKey(previous) >= callKey(current)) {
        return invalid(code, "grant policy calls must have unique, sorted target-selector keys");
      }
    }
    return keccak256(
      encodeAbiParameters(
        [
          { type: "string", name: "domain" },
          { type: "string", name: "version" },
          {
            type: "tuple[]",
            name: "calls",
            components: [
              { type: "address", name: "target" },
              { type: "bytes4", name: "selector" },
              { type: "uint256", name: "valueLimit" },
              {
                type: "tuple[]",
                name: "argumentEquals",
                components: [
                  { type: "uint64", name: "index" },
                  { type: "bytes32", name: "value" },
                ],
              },
            ],
          },
        ],
        [
          OAATH_GRANT_POLICY_CALLS_HASH_DOMAIN,
          OAATH_GRANT_POLICY_VERSION,
          calls.map((call) => ({
            target: call.target,
            selector: call.selector,
            valueLimit: BigInt(call.valueLimit),
            argumentEquals: call.argumentEquals.map((argument) => ({
              index: BigInt(argument.index),
              value: argument.value,
            })),
          })),
        ],
      ),
    );
  });
}

function argumentMap(call: GrantPolicyCall): ReadonlyMap<number, `0x${string}`> {
  return new Map(call.argumentEquals.map((argument) => [argument.index, argument.value]));
}

function callAttenuates(requested: GrantPolicyCall, approved: GrantPolicyCall): boolean {
  if (
    requested.target !== approved.target ||
    requested.selector !== approved.selector ||
    BigInt(approved.valueLimit) > BigInt(requested.valueLimit)
  ) {
    return false;
  }
  const approvedArguments = argumentMap(approved);
  return requested.argumentEquals.every(
    (argument) => approvedArguments.get(argument.index) === argument.value,
  );
}

export function isGrantPolicyAttenuation(requested: unknown, approved: unknown): boolean {
  return captureFailure("grant_policy_attenuation_input_invalid", () => {
    const requestedPolicy = capturePolicy(
      requested,
      "grant_policy_attenuation_input_invalid",
      new WeakSet(),
    );
    const approvedPolicy = capturePolicy(
      approved,
      "grant_policy_attenuation_input_invalid",
      new WeakSet(),
    );
    if (
      approvedPolicy.validAfter < requestedPolicy.validAfter ||
      (requestedPolicy.validUntil !== null &&
        (approvedPolicy.validUntil === null ||
          approvedPolicy.validUntil > requestedPolicy.validUntil)) ||
      approvedPolicy.perChainOperationLimit > requestedPolicy.perChainOperationLimit
    ) {
      return false;
    }
    const requestedCalls = new Map(
      requestedPolicy.calls.map((call) => [callKey(call), call] as const),
    );
    return approvedPolicy.calls.every((call) => {
      const requestedCall = requestedCalls.get(callKey(call));
      return requestedCall !== undefined && callAttenuates(requestedCall, call);
    });
  });
}

function parseCoverageCall(
  value: unknown,
  code: GrantPolicyErrorCode,
  context: CaptureContext,
  index: number,
): Readonly<GrantPolicyCoverageCall> {
  const record = exactRecord(
    value,
    ["target", "data", "value"],
    `grant policy coverage call ${index}`,
    context,
    failFor(code),
  );
  if (
    typeof record.data !== "string" ||
    !BYTES.test(record.data) ||
    record.data.length < 10 ||
    (record.data.length - 10) % 64 !== 0
  ) {
    return invalid(code, `grant policy coverage call ${index} data must be canonical ABI calldata`);
  }
  return Object.freeze({
    target: address(record.target, `grant policy coverage call ${index} target`, code),
    data: record.data as `0x${string}`,
    value: uint256(record.value, `grant policy coverage call ${index} value`, code),
  });
}

function parseCheckpoint(
  value: unknown,
  code: GrantPolicyErrorCode,
  context: CaptureContext,
): Readonly<GrantPolicyUsageCheckpoint> {
  const record = exactRecord(
    value,
    ["blockNumber", "blockHash", "observedAt"],
    "grant policy usage checkpoint",
    context,
    failFor(code),
  );
  return Object.freeze({
    blockNumber: uint256(record.blockNumber, "grant policy usage checkpoint blockNumber", code),
    blockHash: hash(record.blockHash, "grant policy usage checkpoint blockHash", code),
    observedAt: safeInteger(record.observedAt, "grant policy usage checkpoint observedAt", code, 0),
  });
}

function parseUsageEvidence(
  value: unknown,
  code: GrantPolicyErrorCode,
  context: CaptureContext,
): Readonly<GrantPolicyUsageEvidence> | null {
  if (value === null) return null;
  const captured = captureRecord(value, "grant policy usage evidence", context, failFor(code));
  if (captured.status === "complete") {
    const record = exactCapturedRecord(
      captured,
      ["version", "status", "grantId", "chainId", "finalizedOperationCount", "through"],
      "complete grant policy usage evidence",
      failFor(code),
    );
    if (record.version !== OAATH_GRANT_POLICY_USAGE_VERSION) {
      return invalid(code, "grant policy usage evidence version is unsupported");
    }
    return Object.freeze({
      version: OAATH_GRANT_POLICY_USAGE_VERSION,
      status: "complete",
      grantId: canonicalGrantId(record.grantId, code),
      chainId: safeInteger(record.chainId, "grant policy usage chainId", code, 1),
      finalizedOperationCount: uint256(
        record.finalizedOperationCount,
        "grant policy usage finalizedOperationCount",
        code,
      ),
      through: parseCheckpoint(record.through, code, context),
    });
  }
  const record = exactCapturedRecord(
    captured,
    ["version", "status", "reason"],
    "unavailable grant policy usage evidence",
    failFor(code),
  );
  if (record.version !== OAATH_GRANT_POLICY_USAGE_VERSION || record.status !== "unavailable") {
    return invalid(code, "grant policy usage evidence status or version is unsupported");
  }
  if (
    record.reason !== "unreadable" &&
    record.reason !== "non_finalized" &&
    record.reason !== "canonicality_unproven"
  ) {
    return invalid(code, "grant policy usage evidence reason is unsupported");
  }
  return Object.freeze({
    version: OAATH_GRANT_POLICY_USAGE_VERSION,
    status: "unavailable",
    reason: record.reason,
  });
}

interface CapturedCoverageInput {
  readonly policy: Readonly<GrantPolicy>;
  readonly grantId: string;
  readonly chainId: number;
  readonly evaluatedAt: number;
  readonly calls: readonly Readonly<GrantPolicyCoverageCall>[];
  readonly usage: Readonly<GrantPolicyUsageEvidence> | null;
}

function captureCoverageInput(value: unknown): CapturedCoverageInput {
  const code = "grant_policy_coverage_input_invalid";
  const context: CaptureContext = new WeakSet();
  const record = exactRecord(
    value,
    ["policy", "grantId", "chainId", "evaluatedAt", "calls", "usage"],
    "grant policy coverage input",
    context,
    failFor(code),
  );
  const callInputs = captureDenseArray(
    record.calls,
    "grant policy coverage calls",
    context,
    failFor(code),
  );
  return Object.freeze({
    policy: capturePolicy(record.policy, code, context),
    grantId: canonicalGrantId(record.grantId, code),
    chainId: safeInteger(record.chainId, "grant policy coverage chainId", code, 1),
    evaluatedAt: safeInteger(
      record.evaluatedAt,
      "grant policy coverage evaluatedAt",
      code,
      0,
      MAX_UINT48,
    ),
    calls: Object.freeze(
      callInputs.map((call, index) => parseCoverageCall(call, code, context, index)),
    ),
    usage: parseUsageEvidence(record.usage, code, context),
  });
}

function denied(
  policyHash: `0x${string}`,
  chainId: number,
  reason: GrantPolicyCoverageDeniedReason,
  callIndex: number | null = null,
): GrantPolicyCoverageResult {
  return Object.freeze({ status: "denied", policyHash, chainId, reason, callIndex });
}

function callDenialReason(
  permitted: GrantPolicyCall,
  candidate: GrantPolicyCoverageCall,
): "argument_not_permitted" | "value_limit_exceeded" | null {
  if (BigInt(candidate.value) > BigInt(permitted.valueLimit)) return "value_limit_exceeded";
  for (const equality of permitted.argumentEquals) {
    const byteEnd = BigInt(equality.index + 1) * 32n;
    const argumentByteLength = BigInt((candidate.data.length - 10) / 2);
    if (byteEnd > argumentByteLength) return "argument_not_permitted";
    const start = 10 + equality.index * 64;
    if (`0x${candidate.data.slice(start, start + 64)}` !== equality.value) {
      return "argument_not_permitted";
    }
  }
  return null;
}

export function evaluateGrantPolicyCoverage(value: unknown): GrantPolicyCoverageResult {
  return captureFailure("grant_policy_coverage_input_invalid", () => {
    const input = captureCoverageInput(value);
    const policyHash = keccak256(encodeCapturedGrantPolicy(input.policy));
    if (input.calls.length === 0) return denied(policyHash, input.chainId, "empty_calls");
    if (
      input.evaluatedAt < input.policy.validAfter ||
      (input.policy.validUntil !== null && input.evaluatedAt > input.policy.validUntil)
    ) {
      return denied(policyHash, input.chainId, "outside_time_window");
    }
    const permittedCalls = new Map(
      input.policy.calls.map((call) => [callKey(call), call] as const),
    );
    for (let index = 0; index < input.calls.length; index += 1) {
      const candidate = input.calls[index];
      if (!candidate) return invalid("grant_policy_coverage_input_invalid", "call is missing");
      const candidateSelector = candidate.data.slice(0, 10);
      const permitted = permittedCalls.get(`${candidate.target}:${candidateSelector}`);
      if (!permitted) return denied(policyHash, input.chainId, "call_not_permitted", index);
      const reason = callDenialReason(permitted, candidate);
      if (reason) return denied(policyHash, input.chainId, reason, index);
    }
    if (input.usage === null) {
      return Object.freeze({
        status: "inconclusive",
        policyHash,
        chainId: input.chainId,
        reason: "usage_missing",
      });
    }
    if (input.usage.status === "unavailable") {
      return Object.freeze({
        status: "inconclusive",
        policyHash,
        chainId: input.chainId,
        reason: `usage_${input.usage.reason}` as GrantPolicyCoverageInconclusiveReason,
      });
    }
    if (input.usage.grantId !== input.grantId || input.usage.chainId !== input.chainId) {
      return Object.freeze({
        status: "inconclusive",
        policyHash,
        chainId: input.chainId,
        reason: "usage_identity_mismatch",
      });
    }
    if (
      BigInt(input.usage.finalizedOperationCount) >= BigInt(input.policy.perChainOperationLimit)
    ) {
      return denied(policyHash, input.chainId, "operation_limit_exhausted");
    }
    return Object.freeze({
      status: "covered",
      policyHash,
      chainId: input.chainId,
      finalizedOperationCount: input.usage.finalizedOperationCount,
      uses: 1,
    });
  });
}
