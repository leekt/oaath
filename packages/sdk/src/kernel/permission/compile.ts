/**
 * Compiles orthogonal policy profiles into the exact configuration ZeroDev's
 * CallPolicy module receives. Owns policy meaning and encoding only: it never
 * branches on credential kind or operator authority.
 *
 * The compiled package is total and fail-closed. Every permitted call is one
 * (callType, target, selector) entry carrying the exact native value ceiling
 * reviewed for that call alone — value is not a policy axis of its own, so no
 * global maximum can widen another call's allowance — and a call the profile
 * never named has no entry, so CallPolicy rejects it. A call with no declared
 * spend carries a zero ceiling rather than an unlimited sentinel.
 *
 * Each axis resolves to its own reviewed module: calls to CallPolicy, the
 * validity window to OaathKernelV4ValidityPolicy, the per-chain operation count to
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
import { concat, decodeAbiParameters, encodeAbiParameters, toHex } from "viem";
import type { KernelCall } from "../../kernel-v4.js";
import {
  captureInput,
  denseInput,
  exactCaptured,
  exactInput,
  inputAddress,
  inputInvalid,
  inputSelector,
  inputUint,
  runtimeFail,
} from "../internal.js";
import { resolvePolicyModule } from "../modules.js";
import type {
  CompiledKernelPermissionPolicy,
  CompiledKernelPolicyPackage,
  KernelCallPolicyProfile,
  KernelRateLimitPolicyProfile,
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

function capturePermissions(
  value: unknown,
  context: CaptureContext,
): KernelCallPolicyProfile["permissions"] {
  const entries = denseInput(value, "Kernel call policy permissions", context);
  if (entries.length < 1 || entries.length > 256) {
    return inputInvalid("Kernel call policy permission count is invalid");
  }
  const seen = new Set<string>();
  return Object.freeze(
    entries.map((entry, index) => {
      const record = exactInput(
        entry,
        ["target", "selector", "valueLimit"],
        `Kernel call policy permission ${index}`,
        context,
      );
      const target = inputAddress(record.target, "Kernel call policy target");
      // CallPolicy keys each permission by an exact (target, selector) pair. A
      // plain value transfer is selector 0x00000000, which CallPolicy derives
      // from empty calldata. A duplicate pair could carry two different value
      // limits, so it is rejected instead of letting one shadow the other.
      const selector = inputSelector(record.selector, "Kernel call policy selector");
      if (seen.has(`${target}${selector}`)) {
        return inputInvalid("Kernel call policy permissions contain a duplicate call");
      }
      seen.add(`${target}${selector}`);
      return Object.freeze({
        target,
        selector,
        // Each permission carries the exact reviewed ceiling for this call
        // alone; no other permission's allowance can widen it.
        valueLimit: inputUint(
          record.valueLimit,
          MAX_UINT256,
          "Kernel call policy value limit",
        ).toString(10),
      });
    }),
  );
}

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

/**
 * Decodes an installed CallPolicy payload into the exact check its
 * checkUserOpPolicy performs, so a session refuses a forbidden call before any
 * key is asked to sign. It mirrors zerodev-kernel-call-policy 0.0.4 for the
 * single and batched calls Kernel executes: every call is looked up under
 * CALLTYPE_SINGLE by (target, selector), where empty calldata is selector
 * 0x00000000 and one to three bytes revert the selector slice; a miss retries
 * the zero-address "any target" entry; the call's native value must not exceed
 * that entry's valueLimit. No OAAth scope profile expresses argument rules, so
 * a payload carrying them is refused here rather than checked differently from
 * the chain.
 */
export function kernelCallPolicyCheck(
  policyData: `0x${string}`,
): (calls: readonly Readonly<KernelCall>[]) => void {
  let permissions: ReturnType<typeof decodeAbiParameters<typeof PERMISSION_PARAMETERS>>[0];
  try {
    [permissions] = decodeAbiParameters(PERMISSION_PARAMETERS, policyData);
  } catch {
    return inputInvalid("Kernel call policy payload is invalid");
  }
  if (permissions.some((permission) => permission.rules.length > 0)) {
    return inputInvalid("Kernel call policy argument rules are unsupported");
  }
  const limits = new Map<string, bigint>();
  for (const permission of permissions) {
    if (permission.callType !== CALLTYPE_SINGLE) continue;
    const key = `${permission.target.toLowerCase()}${permission.selector.toLowerCase()}`;
    // CallPolicy's onInstall rejects a duplicate permission hash, so the first
    // entry is the only one the chain can hold.
    if (!limits.has(key)) limits.set(key, permission.valueLimit);
  }
  return (calls) => {
    for (const call of calls) {
      const data = call.data.toLowerCase();
      if (data.length > 2 && data.length < 10) {
        return runtimeFail("kernel_runtime_call_forbidden", "Kernel call has no whole selector");
      }
      const selector = data === "0x" ? "0x00000000" : data.slice(0, 10);
      const limit =
        limits.get(`${call.target.toLowerCase()}${selector}`) ??
        limits.get(`${ZERO_ADDRESS}${selector}`);
      if (limit === undefined) {
        return runtimeFail(
          "kernel_runtime_call_forbidden",
          "Kernel call is not permitted by the session call policy",
        );
      }
      if (BigInt(call.value) > limit) {
        return runtimeFail(
          "kernel_runtime_call_forbidden",
          "Kernel call value exceeds the session call policy limit",
        );
      }
    }
  };
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
  let permissions: KernelCallPolicyProfile["permissions"] | null = null;
  let validAfter: string | null = null;
  let validUntil: string | null = null;
  let maximumOperations: string | null = null;
  let rateLimit: Readonly<Omit<KernelRateLimitPolicyProfile, "kind">> | null = null;

  for (const entry of entries) {
    const captured = captureInput(entry, "Kernel policy profile", context);
    const kind = captured.kind;
    if (kind === "call") {
      if (permissions) return inputInvalid("Kernel policy profiles contain a duplicate kind");
      permissions = capturePermissions(
        exactCaptured(captured, ["kind", "permissions"], "Kernel call policy profile").permissions,
        context,
      );
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
      // An unbounded or inverted window is not a scope: the OAAth validity
      // policy requires one finite increasing immutable ceiling.
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
    if (kind === "rate-limit") {
      if (rateLimit) return inputInvalid("Kernel policy profiles contain a duplicate kind");
      const record = exactCaptured(
        captured,
        ["kind", "intervalSeconds", "maximumOperations"],
        "Kernel rate limit policy profile",
      );
      const interval = inputUint(record.intervalSeconds, MAX_UINT48, "Kernel rate limit interval");
      const count = inputUint(record.maximumOperations, MAX_UINT32, "Kernel rate limit count");
      if (interval === 0n || count === 0n)
        return inputInvalid("Kernel rate limit must have a positive interval and count");
      rateLimit = Object.freeze({
        intervalSeconds: interval.toString(10),
        maximumOperations: count.toString(10),
      });
      continue;
    }
    return inputInvalid("Kernel policy profile kind is unsupported");
  }

  // Without permitted calls there is no scope to enforce: CallPolicy would reject
  // every operation, so an installation like that is never expressible.
  if (!permissions) {
    return inputInvalid("Kernel policy profiles must bound the calls a session may make");
  }

  // Packages are emitted in one fixed order, independent of the order the
  // profiles arrived in, so one scope always compiles to one permission ID and
  // one signature slice layout. Each permission's value limit is part of the
  // encoded payload, so changing any single limit changes the permission ID.
  const packages: Readonly<CompiledKernelPolicyPackage>[] = [
    Object.freeze({
      module: resolvePolicyModule("call"),
      policyData: encodeAbiParameters(PERMISSION_PARAMETERS, [
        permissions.map((permission) => ({
          callType: CALLTYPE_SINGLE,
          target: permission.target,
          selector: permission.selector,
          valueLimit: BigInt(permission.valueLimit),
          rules: [],
        })),
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

  if (rateLimit !== null) {
    packages.push(
      Object.freeze({
        module: resolvePolicyModule("rate-limit"),
        policyData: concat([
          toHex(BigInt(rateLimit.intervalSeconds), { size: 6 }),
          toHex(BigInt(rateLimit.maximumOperations), { size: 6 }),
        ]),
      }),
    );
  }

  return Object.freeze({
    packages: Object.freeze(packages),
    permissions,
    validAfter,
    validUntil,
    maximumOperations,
    rateLimit,
  });
}
