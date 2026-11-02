/**
 * Unbounded grants: a GrantPolicy without an expiry and/or an operation limit
 * compiles to exactly the profiles Orchestra's `operatorGrantPolicyProfiles`
 * builds (the call policy, plus `expiry` only when set and `rate-limit` only
 * when set), so the portal's permission ID equals the one Orchestra verifies.
 */
import { describe, expect, it } from "vitest";
import { credentialKey } from "../src/kernel/key/credential.js";
import { sessionOperator } from "../src/kernel/operator/session.js";
import type { KernelPolicyProfile } from "../src/kernel/types.js";
import { grantPermissionPackages } from "../src/kernel.js";
import { kernelV4Deployment } from "../src/kernel-v4.js";
import { portalRoot } from "./support/portal-roots.js";

const passkey = portalRoot("webauthn", "operator");
const SIGNER = { ...passkey.credential, version: "oaath.operator-credential-profile/v1" } as never;
const TARGET = `0x${"aa".repeat(20)}` as const;
const SELECTOR = "0x00000000" as const;
const EXPIRES_AT = 4_000_000_000;
const DAILY = 25;

/** Orchestra's compilation, as `operatorGrantPolicyProfiles` builds it. */
function orchestraProfiles(expiresAt?: number, daily?: number): KernelPolicyProfile[] {
  const profiles: KernelPolicyProfile[] = [
    { kind: "call", permissions: [{ target: TARGET, selector: SELECTOR, valueLimit: "0" }] },
  ];
  if (expiresAt !== undefined)
    profiles.push({ kind: "expiry", validAfter: "0", validUntil: String(expiresAt) });
  if (daily !== undefined)
    profiles.push({
      kind: "rate-limit",
      intervalSeconds: "86400",
      maximumOperations: String(daily),
    });
  return profiles;
}

function orchestraPermission(expiresAt?: number, daily?: number) {
  const deployment = kernelV4Deployment(1);
  const operator = sessionOperator({
    key: credentialKey({ credential: SIGNER, validator: null }),
    policies: orchestraProfiles(expiresAt, daily),
  });
  const validation = operator.resolveValidation(deployment);
  return {
    permissionId: validation.kind === "permission" ? validation.permissionId : null,
    packages: operator.resolvePackages(deployment),
  };
}

function policy(expiresAt?: number, daily?: number) {
  return {
    version: "oaath.grant-policy/v1",
    calls: [{ target: TARGET, selector: SELECTOR, valueLimit: "0", argumentEquals: [] }],
    validAfter: 0,
    validUntil: expiresAt ?? null,
    perChainOperationLimit: daily === undefined ? null : { count: daily, intervalSeconds: 86_400 },
  } as never;
}

describe("unbounded grants", () => {
  it("compile to Orchestra's own profiles for every combination of expiry and limit", () => {
    for (const [expiresAt, daily] of [
      [undefined, undefined],
      [EXPIRES_AT, undefined],
      [undefined, DAILY],
      [EXPIRES_AT, DAILY],
    ] as const) {
      const derived = grantPermissionPackages({ signer: SIGNER, policy: policy(expiresAt, daily) });
      const orchestra = orchestraPermission(expiresAt, daily);
      expect(derived.permissionId).toBe(orchestra.permissionId);
      expect(derived.packages).toEqual(orchestra.packages);
    }
    // An unbounded grant installs only the call policy and the signer.
    expect(grantPermissionPackages({ signer: SIGNER, policy: policy() }).packages).toHaveLength(2);
  });
});
