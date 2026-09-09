import type { GrantPolicy } from "@oaath/protocol";
import { runtimeFail } from "../internal.js";
import type { KernelPolicyProfile } from "../types.js";

/**
 * Maps the approved Grant policy onto Kernel policy hook profiles. This is the
 * one place the two vocabularies meet, and it is deliberately total: an approved
 * constraint with no reviewed hook profile fails closed instead of installing a
 * session that enforces less than the owner approved.
 */
export function deriveSessionPolicyProfiles(
  policy: Readonly<GrantPolicy>,
): readonly KernelPolicyProfile[] {
  // Every approved call maps to exactly one CallPolicy permission carrying that
  // call's own value limit, in the Grant policy's canonical order. No aggregate
  // is computed: a global maximum would install an on-chain allowance on one
  // call that only another call's approval justified.
  const permissions = policy.calls.map((call) => {
    if (call.argumentEquals.length > 0) {
      runtimeFail(
        "kernel_runtime_policy_unavailable",
        "argument constraints have no Kernel policy profile",
      );
    }
    return Object.freeze({
      target: call.target,
      selector: call.selector,
      valueLimit: call.valueLimit,
    });
  });
  if (permissions.length === 0)
    runtimeFail("kernel_runtime_policy_unavailable", "policy has no calls");
  if (policy.validUntil === null)
    runtimeFail("kernel_runtime_policy_unavailable", "policy expiry is unbounded");
  return Object.freeze([
    Object.freeze({ kind: "call" as const, permissions: Object.freeze(permissions) }),
    Object.freeze({
      kind: "expiry" as const,
      validAfter: policy.validAfter.toString(10),
      validUntil: policy.validUntil.toString(10),
    }),
    Object.freeze({
      kind: "operation-limit" as const,
      maximumOperations: policy.perChainOperationLimit.toString(10),
    }),
  ]);
}
