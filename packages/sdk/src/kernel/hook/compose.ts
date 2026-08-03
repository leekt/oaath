/**
 * Combines orthogonal policy hook profiles into one Kernel module
 * configuration. Owns policy meaning and encoding only: it never branches on
 * credential kind or operator authority.
 *
 * Unlimited sentinels in `moduleData`: absent value limit encodes uint256 max,
 * an absent validity window encodes validAfter 0 and validUntil 0, and an
 * absent operation limit encodes 0.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { CaptureContext } from "@oaath/protocol";
import { encodeAbiParameters } from "viem";
import {
  captureInput,
  denseInput,
  exactCaptured,
  exactInput,
  inputAddress,
  inputInvalid,
  inputSelector,
  inputUint,
} from "../internal.js";
import type {
  ComposedKernelHookPolicy,
  KernelCallHookProfile,
  KernelHookProfile,
} from "../types.js";

const MAX_UINT32 = (1n << 32n) - 1n;
const MAX_UINT48 = (1n << 48n) - 1n;
const MAX_UINT256 = (1n << 256n) - 1n;

const POLICY_PARAMETERS = [
  {
    name: "calls",
    type: "tuple[]",
    components: [
      { name: "target", type: "address" },
      { name: "selectors", type: "bytes4[]" },
    ],
  },
  { name: "maximumValue", type: "uint256" },
  { name: "validAfter", type: "uint48" },
  { name: "validUntil", type: "uint48" },
  { name: "maximumOperations", type: "uint32" },
] as const;

function captureCalls(value: unknown, context: CaptureContext): KernelCallHookProfile["calls"] {
  const entries = denseInput(value, "Kernel call hook calls", context);
  if (entries.length < 1 || entries.length > 256) {
    return inputInvalid("Kernel call hook call count is invalid");
  }
  const targets = new Set<string>();
  return Object.freeze(
    entries.map((entry, index) => {
      const record = exactInput(
        entry,
        ["target", "selectors"],
        `Kernel call hook call ${index}`,
        context,
      );
      const target = inputAddress(record.target, "Kernel call hook target");
      if (targets.has(target)) return inputInvalid("Kernel call hook targets contain a duplicate");
      targets.add(target);
      const values = denseInput(record.selectors, "Kernel call hook selectors", context);
      if (values.length > 256) return inputInvalid("Kernel call hook selector count is invalid");
      const seen = new Set<string>();
      return Object.freeze({
        target,
        selectors: Object.freeze(
          values.map((selectorValue) => {
            const selector = inputSelector(selectorValue, "Kernel call hook selector");
            if (seen.has(selector)) {
              return inputInvalid("Kernel call hook selectors contain a duplicate");
            }
            seen.add(selector);
            return selector;
          }),
        ),
      });
    }),
  );
}

/**
 * Captures one hook profile set and combines it into the exact policy
 * configuration a Kernel policy/hook module receives. Materializing it against a
 * chain is owned by resolveHookModule, which fails closed while no reviewed
 * module deployment is bound.
 */
export function composeKernelHooks(
  profiles: readonly KernelHookProfile[],
): Readonly<ComposedKernelHookPolicy> {
  const context: CaptureContext = new WeakSet();
  return composeCapturedKernelHooks(denseInput(profiles, "Kernel hook profiles", context), context);
}

/** Composes hook profiles already captured from a dense array by their owner. */
export function composeCapturedKernelHooks(
  entries: readonly unknown[],
  context: CaptureContext,
): Readonly<ComposedKernelHookPolicy> {
  if (entries.length < 1 || entries.length > 4) {
    return inputInvalid("Kernel hook profile count is invalid");
  }
  let calls: KernelCallHookProfile["calls"] | null = null;
  let maximumValue: string | null = null;
  let validAfter: string | null = null;
  let validUntil: string | null = null;
  let maximumOperations: string | null = null;

  for (const entry of entries) {
    const captured = captureInput(entry, "Kernel hook profile", context);
    const kind = captured.kind;
    if (kind === "call") {
      if (calls) return inputInvalid("Kernel hook profiles contain a duplicate kind");
      calls = captureCalls(
        exactCaptured(captured, ["kind", "calls"], "Kernel call hook profile").calls,
        context,
      );
      continue;
    }
    if (kind === "value") {
      if (maximumValue) return inputInvalid("Kernel hook profiles contain a duplicate kind");
      const record = exactCaptured(captured, ["kind", "maximumValue"], "Kernel value hook profile");
      maximumValue = inputUint(
        record.maximumValue,
        MAX_UINT256,
        "Kernel value hook maximum value",
      ).toString(10);
      continue;
    }
    if (kind === "expiry") {
      if (validUntil) return inputInvalid("Kernel hook profiles contain a duplicate kind");
      const record = exactCaptured(
        captured,
        ["kind", "validAfter", "validUntil"],
        "Kernel expiry hook profile",
      );
      const after = inputUint(record.validAfter, MAX_UINT48, "Kernel expiry hook validAfter");
      const until = inputUint(record.validUntil, MAX_UINT48, "Kernel expiry hook validUntil");
      if (until === 0n || until <= after) {
        return inputInvalid("Kernel expiry hook validity window is invalid");
      }
      validAfter = after.toString(10);
      validUntil = until.toString(10);
      continue;
    }
    if (kind === "operation-limit") {
      if (maximumOperations) return inputInvalid("Kernel hook profiles contain a duplicate kind");
      const record = exactCaptured(
        captured,
        ["kind", "maximumOperations"],
        "Kernel operation limit hook profile",
      );
      const limit = inputUint(
        record.maximumOperations,
        MAX_UINT32,
        "Kernel operation limit hook maximum",
      );
      if (limit === 0n) return inputInvalid("Kernel operation limit hook maximum is invalid");
      maximumOperations = limit.toString(10);
      continue;
    }
    return inputInvalid("Kernel hook profile kind is unsupported");
  }

  return Object.freeze({
    calls,
    maximumValue,
    validAfter,
    validUntil,
    maximumOperations,
    moduleData: encodeAbiParameters(POLICY_PARAMETERS, [
      (calls ?? []).map((call) => ({ target: call.target, selectors: call.selectors })),
      maximumValue === null ? MAX_UINT256 : BigInt(maximumValue),
      validAfter === null ? 0 : Number(validAfter),
      validUntil === null ? 0 : Number(validUntil),
      maximumOperations === null ? 0 : Number(maximumOperations),
    ]),
  });
}
