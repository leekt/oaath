import {
  type GrantPolicy,
  type OperatorCredentialProfile,
  parseGrantPolicy,
  parseOperatorCredentialProfile,
} from "@oaath/protocol";
import { kernelV4Deployment } from "../../kernel-v4.js";
import { credentialKey } from "../key/credential.js";
import { sessionOperator } from "../operator/session.js";
import type { KernelInstall } from "../types.js";
import { deriveSessionPolicyProfiles } from "./profiles.js";

export interface GrantPermissionPackages {
  readonly permissionId: `0x${string}`;
  /** Policies in install order, then the signer: what the root's enable installs. */
  readonly packages: readonly Readonly<KernelInstall>[];
  /** The signer package's module and the credential's public material. */
  readonly sessionKey: Readonly<{ module: `0x${string}`; publicMaterial: `0x${string}` }>;
}

/**
 * The permission one Grant installs for `signer` under `policy`, exactly as
 * the OAAth relay derives it for the root to approve. Pure: no chain, clock
 * or signer. Session modules are pinned, so every Kernel deployment derives
 * the same packages and permission ID. A constraint with no reviewed Kernel
 * profile fails with `kernel_runtime_policy_unavailable`.
 */
export function grantPermissionPackages(value: {
  readonly signer: Readonly<OperatorCredentialProfile>;
  readonly policy: Readonly<GrantPolicy>;
}): Readonly<GrantPermissionPackages> {
  const signer = parseOperatorCredentialProfile(value?.signer);
  const policy = parseGrantPolicy(value?.policy);
  const deployment = kernelV4Deployment(1);
  const key = credentialKey({ credential: signer, validator: null });
  const operator = sessionOperator({ key, policies: deriveSessionPolicyProfiles(policy) });
  const validation = operator.resolveValidation(deployment);
  if (validation.kind !== "permission") throw new Error("a session operator resolves a permission");
  return Object.freeze({
    permissionId: validation.permissionId,
    packages: operator.resolvePackages(deployment),
    sessionKey: Object.freeze({
      module: operator.resolveAuthorityModule(deployment),
      publicMaterial: key.publicMaterial,
    }),
  });
}
