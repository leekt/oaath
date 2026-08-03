/**
 * Session authority: non-root Kernel validation. Accepts any KeyProfile and any
 * composed policy hooks, and owns authority semantics only.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { CaptureContext } from "@oaath/protocol";
import {
  encodeKernelV4ValidatorData,
  KERNEL_V4_EXECUTE_SELECTOR,
  type KernelV4Deployment,
} from "../../kernel-v4.js";
import { composeCapturedKernelHooks } from "../hook/compose.js";
import { captureKeyProfile, denseInput, exactInput } from "../internal.js";
import { exactKernelDeployment, resolveHookModule } from "../modules.js";
import type { KernelHookProfile, KeyProfile, OperatorProfile } from "../types.js";

export interface SessionOperatorInput {
  readonly key: Readonly<KeyProfile>;
  /** Policy hook profiles; an empty set installs an unconditional session validator. */
  readonly hooks: readonly KernelHookProfile[];
}

/**
 * Every non-root validation must allow-list Kernel v4's execute(bytes32,bytes)
 * selector, or the executeUserOp-wrapped operation reverts with
 * UnauthorizedCallData. Wrapping itself is owned by prepareKernelV4UserOperation.
 */
export function sessionOperator(value: SessionOperatorInput): Readonly<OperatorProfile> {
  const context: CaptureContext = new WeakSet();
  const record = exactInput(value, ["key", "hooks"], "Kernel session operator", context);
  const key = captureKeyProfile(record.key);
  const profiles = denseInput(record.hooks, "Kernel session operator hooks", context);
  // Compose eagerly so the policy configuration is captured once, at the
  // authority boundary, instead of at every materialization.
  const policy = profiles.length === 0 ? null : composeCapturedKernelHooks(profiles, context);

  return Object.freeze({
    authority: "session" as const,
    key,
    policy,
    resolveValidation: (deployment: Readonly<KernelV4Deployment>) =>
      Object.freeze({
        kind: "validator" as const,
        validator: key.resolveValidator(exactKernelDeployment(deployment)),
      }),
    resolvePackages: (deploymentValue: Readonly<KernelV4Deployment>) => {
      const deployment = exactKernelDeployment(deploymentValue);
      const validator = key.resolveValidator(deployment);
      const hook = policy ? resolveHookModule(deployment) : "none";
      return Object.freeze([
        Object.freeze({
          moduleType: 1 as const,
          module: validator,
          moduleData: key.publicMaterial,
          internalData: encodeKernelV4ValidatorData({
            hook,
            selectors: [KERNEL_V4_EXECUTE_SELECTOR],
          }),
        }),
      ]);
    },
  });
}
