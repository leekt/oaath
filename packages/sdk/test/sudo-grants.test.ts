/**
 * Sudo grants: a GrantPolicy with no calls installs exactly one policy, the
 * validity window, so the session may make any call for at most 600 seconds.
 */
import { describe, expect, it } from "vitest";
import { capturePermissionInput } from "../src/client/connection.js";
import { OAATH_KERNEL_V4_VALIDITY_POLICY } from "../src/kernel/modules.js";
import { compileKernelPermissionPolicy } from "../src/kernel/permission/compile.js";
import { deriveSessionPolicyProfiles } from "../src/kernel/permission/profiles.js";
import { grantPermissionPackages } from "../src/kernel.js";
import { portalRoot } from "./support/portal-roots.js";

const SIGNER = {
  ...portalRoot("webauthn", "operator").credential,
  version: "oaath.operator-credential-profile/v1",
} as never;
const SUDO = {
  version: "oaath.grant-policy/v1",
  calls: [],
  validAfter: 1_000,
  validUntil: 1_599,
  perChainOperationLimit: null,
} as const;

describe("sudo grants", () => {
  it("derive only the validity policy and the signer", () => {
    expect(deriveSessionPolicyProfiles(SUDO)).toEqual([
      { kind: "expiry", validAfter: "1000", validUntil: "1599" },
    ]);
    const { packages } = grantPermissionPackages({ signer: SIGNER, policy: SUDO as never });
    expect(packages.map((install) => [install.moduleType, install.module])).toEqual([
      [5, OAATH_KERNEL_V4_VALIDITY_POLICY],
      [6, expect.any(String)],
    ]);
  });

  it("compile no call-free scope beyond one window of at most 600 inclusive seconds", () => {
    expect(
      compileKernelPermissionPolicy([{ kind: "expiry", validAfter: "1000", validUntil: "1599" }])
        .permissions,
    ).toBeNull();
    for (const profiles of [
      [{ kind: "expiry", validAfter: "1000", validUntil: "1600" }],
      [{ kind: "operation-limit", maximumOperations: "1" }],
      [
        { kind: "expiry", validAfter: "1000", validUntil: "1599" },
        { kind: "operation-limit", maximumOperations: "1" },
      ],
    ]) {
      expect(() => compileKernelPermissionPolicy(profiles)).toThrow(/expire within 600 seconds/u);
    }
  });

  it("are requested with an empty call list and a lifetime of at most 600 seconds", () => {
    const input = (expiresIn: number) => ({
      chainScope: "all",
      permissions: [{ calls: [] }],
      expiresIn,
      perChainOperationLimit: null,
    });
    expect(capturePermissionInput(input(600), 1_000).policy).toMatchObject(SUDO);
    expect(() => capturePermissionInput(input(601), 1_000)).toThrow();
  });
});
