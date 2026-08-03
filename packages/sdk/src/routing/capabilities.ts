/**
 * Per-chain routing facts. This module performs no probing, no chain read, and
 * no network call: facts arrive as caller-supplied evidence and are captured
 * exactly once here, the same way the Kernel adapter captures chain reads. It
 * owns every routing fact validator, so no other routing module re-implements
 * one.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { CaptureContext } from "@oaath/protocol";
import { getAddress } from "viem";
import {
  capabilityInvalid,
  exactRoutingRecord,
  type OaathFeePayerDescriptor,
  OaathRoutingError,
  routingFail,
} from "./types.js";

const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const MAX_UINT256 = (1n << 256n) - 1n;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;

/**
 * The routing fact for one chain's bundler, in the repository's closed capability
 * vocabulary (`kernel/capabilities.ts` diagnoses Kernel axes with the same four
 * statuses; this owner is the evidence-derived per-chain half of it).
 *
 * - `available`: a bundler is configured, healthy, and compatible with the
 *   prepared operation's chain and EntryPoint.
 * - `absent`: no bundler is configured for the chain, or a configured bundler
 *   conclusively reported that it is not accepting operations.
 * - `unsupported`: a reachable bundler conclusively cannot or will not accept
 *   this operation (wrong chain, unsupported EntryPoint, or a conclusive
 *   pre-acceptance rejection).
 * - `unreadable`: the bundler's state is unknown. Timeouts, disconnects,
 *   ambiguous responses, and malformed evidence land here and never authorize a
 *   fallback route.
 */
export type OaathBundlerCapability = "available" | "absent" | "unsupported" | "unreadable";

/**
 * Whether a valid session credential covers the prepared calls. `uncovered`
 * includes root work no session policy permits; `unreadable` includes every
 * inconclusive coverage evaluation (`@oaath/protocol` returns `covered`,
 * `denied`, and `inconclusive`, which map to `covered`, `uncovered`, and
 * `unreadable` respectively). Neither ever selects a session signer.
 */
export type OaathSessionCoverage = "covered" | "uncovered" | "unreadable";

/**
 * The exact routing facts for one chain. `feePayer` is the configured EOA
 * descriptor, or `null` when no fee payer is configured.
 */
export interface OaathRoutingCapabilities {
  readonly chainId: number;
  readonly bundler: OaathBundlerCapability;
  readonly sessionCoverage: OaathSessionCoverage;
  readonly feePayer: Readonly<OaathFeePayerDescriptor> | null;
}

export function routingChainId(value: unknown, fail: (message: string) => never): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    return fail("routing chainId must be a positive safe integer");
  }
  return value;
}

export function routingAddress(
  value: unknown,
  label: string,
  fail: (message: string) => never,
): `0x${string}` {
  if (typeof value !== "string") return fail(`${label} must be an address`);
  try {
    const canonical = getAddress(value).toLowerCase() as `0x${string}`;
    if (canonical === ZERO_ADDRESS) return fail(`${label} must be a nonzero address`);
    return canonical;
  } catch {
    return fail(`${label} must be an address`);
  }
}

/** Canonical lowercase nonempty byte string, as a signature or calldata field. */
export function routingBytes(
  value: unknown,
  label: string,
  fail: (message: string) => never,
): `0x${string}` {
  if (typeof value !== "string" || !BYTES.test(value) || value === "0x") {
    return fail(`${label} must be canonical nonempty bytes`);
  }
  return value as `0x${string}`;
}

export function routingUint(
  value: unknown,
  label: string,
  fail: (message: string) => never,
): string {
  if (typeof value !== "string" || !DECIMAL_UINT.test(value) || BigInt(value) > MAX_UINT256) {
    return fail(`${label} must be a canonical bounded decimal integer`);
  }
  return value;
}

export function bundlerCapability(
  value: unknown,
  fail: (message: string) => never,
): OaathBundlerCapability {
  if (
    value !== "available" &&
    value !== "absent" &&
    value !== "unsupported" &&
    value !== "unreadable"
  ) {
    return fail("routing bundler capability is unsupported");
  }
  return value;
}

export function sessionCoverage(
  value: unknown,
  fail: (message: string) => never,
): OaathSessionCoverage {
  if (value !== "covered" && value !== "uncovered" && value !== "unreadable") {
    return fail("routing session coverage is unsupported");
  }
  return value;
}

export function feePayerDescriptor(
  value: unknown,
  context: CaptureContext,
  fail: (message: string) => never,
): Readonly<OaathFeePayerDescriptor> | null {
  if (value === null) return null;
  const record = exactRoutingRecord(
    value,
    ["address", "balance"],
    "routing fee payer",
    context,
    fail,
  );
  return Object.freeze({
    address: routingAddress(record.address, "routing fee payer address", fail),
    balance: routingUint(record.balance, "routing fee payer balance", fail),
  });
}

/**
 * Captures one chain's routing facts exactly. The caller supplies already
 * classified evidence: `bundler` comes from `routing/bundler.ts`, or is `absent`
 * when the chain has no configured bundler at all.
 */
export function captureRoutingCapabilities(
  value: OaathRoutingCapabilities,
): Readonly<OaathRoutingCapabilities> {
  const fail = capabilityInvalid;
  try {
    const context: CaptureContext = new WeakSet();
    const record = exactRoutingRecord(
      value,
      ["chainId", "bundler", "sessionCoverage", "feePayer"],
      "routing capabilities",
      context,
      fail,
    );
    return Object.freeze({
      chainId: routingChainId(record.chainId, fail),
      bundler: bundlerCapability(record.bundler, fail),
      sessionCoverage: sessionCoverage(record.sessionCoverage, fail),
      feePayer: feePayerDescriptor(record.feePayer, context, fail),
    });
  } catch (error) {
    if (error instanceof OaathRoutingError) throw error;
    return routingFail("routing_capability_invalid", "routing capabilities are invalid");
  }
}
