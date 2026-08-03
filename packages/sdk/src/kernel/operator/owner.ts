/**
 * Owner authority: root Kernel validation. Accepts any KeyProfile and owns
 * authority semantics only — never credential internals, policy, or routing.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { CaptureContext } from "@oaath/protocol";
import { encodeKernelV4ValidatorData, type KernelV4Deployment } from "../../kernel-v4.js";
import { captureKeyProfile, exactInput } from "../internal.js";
import { exactKernelDeployment } from "../modules.js";
import type { KeyProfile, OperatorProfile } from "../types.js";

export interface OwnerOperatorInput {
  readonly key: Readonly<KeyProfile>;
}

/**
 * Root validation needs no selector allow-list: Kernel v4 validates root
 * operations against the account's own calldata without executeUserOp wrapping.
 */
export function ownerOperator(value: OwnerOperatorInput): Readonly<OperatorProfile> {
  const context: CaptureContext = new WeakSet();
  const key = captureKeyProfile(exactInput(value, ["key"], "Kernel owner operator", context).key);

  return Object.freeze({
    authority: "owner" as const,
    key,
    policy: null,
    resolveAuthorityModule: (deployment: Readonly<KernelV4Deployment>) =>
      key.resolveValidator(exactKernelDeployment(deployment)),
    // Root validation carries no envelope: Kernel hands the signature straight to
    // the validator module.
    encodeSignature: (signature: `0x${string}`) => signature,
    resolveValidation: (deployment: Readonly<KernelV4Deployment>) => {
      exactKernelDeployment(deployment);
      return Object.freeze({ kind: "root" as const });
    },
    resolvePackages: (deployment: Readonly<KernelV4Deployment>) =>
      Object.freeze([
        Object.freeze({
          moduleType: 1 as const,
          module: key.resolveValidator(exactKernelDeployment(deployment)),
          moduleData: key.publicMaterial,
          internalData: encodeKernelV4ValidatorData({ hook: "none", selectors: [] }),
        }),
      ]),
  });
}
