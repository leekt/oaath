/**
 * Compiles orthogonal policy profiles into the exact configuration ZeroDev's
 * CallPolicy module receives. Owns policy meaning and encoding only: it never
 * branches on credential kind or operator authority.
 *
 * The compiled package is total and fail-closed. Every permitted call is one
 * (callType, target, selector) triple carrying the native value ceiling that
 * applies to it, so a call the profile never named has no entry and CallPolicy
 * rejects it. An absent value profile compiles to a zero ceiling rather than an
 * unlimited sentinel: a session that never declared a spend may not move value.
 *
 * Each axis resolves to its own reviewed module: calls and value to CallPolicy,
 * the validity window to TimestampPolicy, the per-chain operation count to
 * RateLimitPolicy. Expiry is therefore enforced on-chain through the ERC-4337
 * validationData time range that Kernel intersects across policies, not by
 * client-side refusal. An axis with no pinned module fails closed with
 * kernel_runtime_policy_unavailable rather than being dropped, because a caller
 * that asked for a bound and received none would believe in a scope the chain
 * does not enforce.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { CaptureContext } from "@oaath/protocol";
import { concat, encodeAbiParameters, toHex } from "viem";
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
import { resolvePolicyModule } from "../modules.js";
import type {
  CompiledKernelPermissionPolicy,
  CompiledKernelPolicyPackage,
  KernelCallPolicyProfile,
} from "../types.js";

const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_UINT32 = (1n << 32n) - 1n;
const MAX_UINT48 = (1n << 48n) - 1n;
/** CallPolicy keys every permission by Kernel's CALLTYPE_SINGLE for single and batched calls. */
const CALLTYPE_SINGLE = "0x00" as const;

/**
 * CallPolicy's `Permission[]` install payload. `rules` stays empty: argument
 * conditions are a CallPolicy feature no OAAth scope profile expresses yet.
 */
const PERMISSION_PARAMETERS = [
  {
    name: "permissions",
    type: "tuple[]",
    components: [
      { name: "callType", type: "bytes1" },
      { name: "target", type: "address" },
      { name: "selector", type: "bytes4" },
      { name: "valueLimit", type: "uint256" },
      {
        name: "rules",
        type: "tuple[]",
        components: [
          { name: "condition", type: "uint8" },
          { name: "offset", type: "uint64" },
          { name: "params", type: "bytes32[]" },
        ],
      },
    ],
  },
] as const;

function captureCalls(value: unknown, context: CaptureContext): KernelCallPolicyProfile["calls"] {
  const entries = denseInput(value, "Kernel call policy calls", context);
  if (entries.length < 1 || entries.length > 256) {
    return inputInvalid("Kernel call policy call count is invalid");
  }
  const targets = new Set<string>();
  return Object.freeze(
    entries.map((entry, index) => {
      const record = exactInput(
        entry,
        ["target", "selectors"],
        `Kernel call policy call ${index}`,
        context,
      );
      const target = inputAddress(record.target, "Kernel call policy target");
      if (targets.has(target)) {
        return inputInvalid("Kernel call policy targets contain a duplicate");
      }
      targets.add(target);
      const values = denseInput(record.selectors, "Kernel call policy selectors", context);
      // CallPolicy keys each permission by an exact selector, so a target with no
      // selector would permit nothing: reject it instead of installing a scope
      // that can never authorize a call. A plain value transfer is selector
      // 0x00000000, which CallPolicy derives from empty calldata.
      if (values.length < 1 || values.length > 256) {
        return inputInvalid("Kernel call policy selector count is invalid");
      }
      const seen = new Set<string>();
      return Object.freeze({
        target,
        selectors: Object.freeze(
          values.map((selectorValue) => {
            const selector = inputSelector(selectorValue, "Kernel call policy selector");
            if (seen.has(selector)) {
              return inputInvalid("Kernel call policy selectors contain a duplicate");
            }
            seen.add(selector);
            return selector;
          }),
        ),
      });
    }),
  );
}

/** Compiles one policy profile set into the packages its modules receive. */
export function compileKernelPermissionPolicy(
  profiles: readonly unknown[],
): Readonly<CompiledKernelPermissionPolicy> {
  const context: CaptureContext = new WeakSet();
  return compileCapturedKernelPermissionPolicy(
    denseInput(profiles, "Kernel policy profiles", context),
    context,
  );
}

/** Compiles policy profiles already captured from a dense array by their owner. */
export function compileCapturedKernelPermissionPolicy(
  entries: readonly unknown[],
  context: CaptureContext,
): Readonly<CompiledKernelPermissionPolicy> {
  if (entries.length < 1 || entries.length > 4) {
    return inputInvalid("Kernel policy profile count is invalid");
  }
  let calls: KernelCallPolicyProfile["calls"] | null = null;
  let maximumValue: string | null = null;
  let validAfter: string | null = null;
  let validUntil: string | null = null;
  let maximumOperations: string | null = null;

  for (const entry of entries) {
    const captured = captureInput(entry, "Kernel policy profile", context);
    const kind = captured.kind;
    if (kind === "call") {
      if (calls) return inputInvalid("Kernel policy profiles contain a duplicate kind");
      calls = captureCalls(
        exactCaptured(captured, ["kind", "calls"], "Kernel call policy profile").calls,
        context,
      );
      continue;
    }
    if (kind === "value") {
      if (maximumValue) return inputInvalid("Kernel policy profiles contain a duplicate kind");
      const record = exactCaptured(
        captured,
        ["kind", "maximumValue"],
        "Kernel value policy profile",
      );
      maximumValue = inputUint(
        record.maximumValue,
        MAX_UINT256,
        "Kernel value policy maximum value",
      ).toString(10);
      continue;
    }
    if (kind === "expiry") {
      if (validUntil) return inputInvalid("Kernel policy profiles contain a duplicate kind");
      const record = exactCaptured(
        captured,
        ["kind", "validAfter", "validUntil"],
        "Kernel expiry policy profile",
      );
      const after = inputUint(record.validAfter, MAX_UINT48, "Kernel expiry policy validAfter");
      const until = inputUint(record.validUntil, MAX_UINT48, "Kernel expiry policy validUntil");
      // An unbounded or inverted window is not a scope: TimestampPolicy reads
      // validUntil 0 as no expiry at all, which is what expiry exists to prevent.
      if (until === 0n || until <= after) {
        return inputInvalid("Kernel expiry policy validity window is invalid");
      }
      validAfter = after.toString(10);
      validUntil = until.toString(10);
      continue;
    }
    if (kind === "operation-limit") {
      if (maximumOperations) return inputInvalid("Kernel policy profiles contain a duplicate kind");
      const record = exactCaptured(
        captured,
        ["kind", "maximumOperations"],
        "Kernel operation limit policy profile",
      );
      const limit = inputUint(
        record.maximumOperations,
        MAX_UINT32,
        "Kernel operation limit policy maximum",
      );
      if (limit === 0n) return inputInvalid("Kernel operation limit policy maximum is invalid");
      maximumOperations = limit.toString(10);
      continue;
    }
    return inputInvalid("Kernel policy profile kind is unsupported");
  }

  // Without permitted calls there is no scope to enforce: CallPolicy would reject
  // every operation, so an installation like that is never expressible.
  if (!calls) return inputInvalid("Kernel policy profiles must bound the calls a session may make");
  const valueLimit = maximumValue === null ? "0" : maximumValue;

  // Packages are emitted in one fixed order, independent of the order the
  // profiles arrived in, so one scope always compiles to one permission ID and
  // one signature slice layout.
  const packages: Readonly<CompiledKernelPolicyPackage>[] = [
    Object.freeze({
      module: resolvePolicyModule("call"),
      policyData: encodeAbiParameters(PERMISSION_PARAMETERS, [
        calls.flatMap((call) =>
          call.selectors.map((selector) => ({
            callType: CALLTYPE_SINGLE,
            target: call.target,
            selector,
            valueLimit: BigInt(valueLimit),
            rules: [],
          })),
        ),
      ]),
    }),
  ];
  if (validUntil !== null) {
    packages.push(
      Object.freeze({
        module: resolvePolicyModule("expiry"),
        policyData: encodeAbiParameters(
          [
            { name: "validAfter", type: "uint48" },
            { name: "validUntil", type: "uint48" },
          ],
          [Number(validAfter ?? "0"), Number(validUntil)],
        ),
      }),
    );
  }
  if (maximumOperations !== null) {
    packages.push(
      Object.freeze({
        module: resolvePolicyModule("operation-limit"),
        // RateLimitPolicy install data is packed interval ‖ count ‖ startAt, each
        // uint48. A zero interval and start make it a pure per-chain count cap:
        // every operation decrements the count and adds no time bound.
        policyData: concat([
          toHex(0, { size: 6 }),
          toHex(BigInt(maximumOperations), { size: 6 }),
          toHex(0, { size: 6 }),
        ]),
      }),
    );
  }

  return Object.freeze({
    packages: Object.freeze(packages),
    calls,
    maximumValue: valueLimit,
    validAfter,
    validUntil,
    maximumOperations,
  });
}
