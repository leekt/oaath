/**
 * Session authority: Kernel v4 permission validation. Accepts any KeyProfile,
 * compiles the requested scope into a policy package, and owns authority
 * semantics only.
 *
 * A session is a permission, never whole-key authority: the packages it installs
 * are one moduleType 5 policy per requested scope axis — calls and value, the
 * validity window, the per-chain operation count — followed by one moduleType 6
 * signer carrying the key's public material. Policies are required, so an
 * unscoped session cannot be expressed at all.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { CaptureContext } from "@oaath/protocol";
import { concat, keccak256, pad } from "viem";
import {
  encodeKernelV4PermissionSignature,
  encodeKernelV4PolicyData,
  encodeKernelV4SignerData,
  KERNEL_V4_EXECUTE_SELECTOR,
  type KernelV4Deployment,
} from "../../kernel-v4.js";
import { captureKeyProfile, denseInput, exactInput, inputInvalid } from "../internal.js";
import { exactKernelDeployment, resolvePinnedSigner } from "../modules.js";
import { compileCapturedKernelPermissionPolicy } from "../permission/compile.js";
import type { KernelPolicyProfile, KeyProfile, OperatorProfile } from "../types.js";

export interface SessionOperatorInput {
  readonly key: Readonly<KeyProfile>;
  /** Policy profiles bounding this session. At least one is required. */
  readonly policies: readonly KernelPolicyProfile[];
}

/**
 * Every input that defines this authority feeds the permission ID, so one session
 * derives one ID on every chain and two different scopes never share an ID.
 * Kernel stores the validation under this ID and rejects a second install on an
 * occupied ID, so even a 4-byte collision fails closed on-chain instead of
 * silently widening an installed scope.
 */
function derivePermissionId(
  policies: readonly Readonly<{ module: `0x${string}`; policyData: `0x${string}` }>[],
  signerModule: `0x${string}`,
  kind: string,
  publicMaterial: `0x${string}`,
): `0x${string}` {
  const digest = keccak256(
    concat([
      ...policies.flatMap((policy) => [policy.module, keccak256(policy.policyData)]),
      signerModule,
      keccak256(new TextEncoder().encode(kind)),
      keccak256(publicMaterial),
    ]),
  );
  return digest.slice(0, 10) as `0x${string}`;
}

/**
 * Permission validation installed with no hook allow-lists Kernel v4's
 * execute(bytes32,bytes) selector and takes Kernel's fast path, so its operations
 * carry plain execute calldata. Kernel enforces the same selector allow-list on
 * that path as on the executeUserOp-wrapped one, and the policy module needs the
 * unwrapped calldata to decode the calls it bounds.
 */
export function sessionOperator(value: SessionOperatorInput): Readonly<OperatorProfile> {
  const context: CaptureContext = new WeakSet();
  const record = exactInput(value, ["key", "policies"], "Kernel session operator", context);
  const key = captureKeyProfile(record.key);
  const profiles = denseInput(record.policies, "Kernel session operator policies", context);
  // An unscoped session is not expressible: with no policy the signer would hold
  // whole-key authority, which is exactly what a permission replaces.
  if (profiles.length === 0) {
    return inputInvalid("Kernel session operator requires at least one policy profile");
  }
  // Compile and resolve eagerly so the scope is captured once, at the authority
  // boundary, and an unavailable module fails before any permission ID exists.
  const policy = compileCapturedKernelPermissionPolicy(profiles, context);
  const signer = resolvePinnedSigner(key.kind);
  const permissionId = derivePermissionId(policy.packages, signer, key.kind, key.publicMaterial);
  const paddedPermissionId = pad(permissionId, { size: 32, dir: "right" });

  return Object.freeze({
    authority: "session" as const,
    key,
    policy,
    resolveAuthorityModule: (deployment: Readonly<KernelV4Deployment>) => {
      exactKernelDeployment(deployment);
      return signer;
    },
    // Kernel's _validateUserOpPermission requires exactly one slice per installed
    // policy package plus one for the signer, or it reverts InvalidSignature
    // before any policy runs. The slices are derived from the same captured
    // compiled policy resolvePackages installs from, so the envelope can never
    // describe a different package count than the permission holds. No reviewed
    // policy module reads a signature of its own, so every policy slice is empty
    // and the signer slice, which Kernel requires last, carries the key signature.
    encodeSignature: (signature: `0x${string}`) =>
      encodeKernelV4PermissionSignature([...policy.packages.map(() => "0x" as const), signature]),
    resolveValidation: (deployment: Readonly<KernelV4Deployment>) => {
      exactKernelDeployment(deployment);
      return Object.freeze({ kind: "permission" as const, permissionId });
    },
    resolvePackages: (deployment: Readonly<KernelV4Deployment>) => {
      exactKernelDeployment(deployment);
      return Object.freeze([
        ...policy.packages.map((entry) =>
          Object.freeze({
            moduleType: 5 as const,
            module: entry.module,
            moduleData: concat([paddedPermissionId, entry.policyData]),
            internalData: encodeKernelV4PolicyData(permissionId),
          }),
        ),
        Object.freeze({
          moduleType: 6 as const,
          module: signer,
          moduleData: concat([paddedPermissionId, key.publicMaterial]),
          internalData: encodeKernelV4SignerData({
            permissionId,
            hook: "none",
            selectors: [KERNEL_V4_EXECUTE_SELECTOR],
          }),
        }),
      ]);
    },
  });
}
