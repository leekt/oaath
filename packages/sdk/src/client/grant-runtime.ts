/** Adapts the Grant's semantic enable mode to its captured Kernel account version. */
import { isKernelExistingAccountProfile, type KernelAccountProfile } from "@oaath/protocol";
import { createKernelRuntime } from "../kernel/create-kernel-runtime.js";
import type { KernelAccountDescriptor } from "../kernel/deployment/account.js";
import {
  type KernelV33AccountDescriptor,
  type KernelV33Reads,
  kernelV33Deployment,
} from "../kernel/deployment/v33.js";
import type { KernelGasPolicy } from "../kernel/gas-policy.js";
import { ownerOperator } from "../kernel/operator/owner.js";
import type { KernelGrantApproval } from "../kernel/permission/approval.js";
import { bindKernelPermissionApproval } from "../kernel/permission/materialize.js";
import {
  bindKernelV33PermissionApproval,
  OAATH_KERNEL_V33_APPROVAL_VERSION,
} from "../kernel/permission/v33.js";
import type {
  KernelRuntime,
  KernelRuntimePrepareInput,
  KernelV33Runtime,
  KeyProfile,
  OperatorProfile,
} from "../kernel/types.js";
import {
  type KernelV4AccountDescriptor,
  type KernelV4AccountReadCapability,
  kernelV4Deployment,
} from "../kernel-v4.js";
import type { PreparedUserOperation } from "../prepared-user-operation.js";
import { clientFail } from "./errors.js";

export type GrantKernelAccount = KernelAccountDescriptor;
export type GrantKernelPrepareInput = KernelRuntimePrepareInput<GrantKernelAccount>;
export interface GrantKernelExecution {
  readonly gasPolicy: Readonly<KernelGasPolicy>;
  readonly dummySignature: `0x${string}`;
  readonly prepareOperation: (input: GrantKernelPrepareInput) => PreparedUserOperation;
  readonly signOperation: (prepared: Readonly<PreparedUserOperation>) => Promise<`0x${string}`>;
  readonly encodeVerifiedSignature: (
    prepared: Readonly<PreparedUserOperation>,
    signature: `0x${string}`,
  ) => Promise<`0x${string}`>;
}
export interface GrantKernelRuntime extends GrantKernelExecution {
  readonly validation: KernelRuntime["validation"];
  readonly deployment: KernelRuntime["deployment"] | KernelV33Runtime["deployment"];
  readonly bindAccount: () => Promise<Readonly<GrantKernelAccount>>;
  readonly bindApproval: (
    approval: Readonly<KernelGrantApproval>,
    account: `0x${string}`,
  ) => GrantKernelExecution;
}

function mismatch(): never {
  return clientFail(
    "oaath_client_state_conflict",
    "the Grant runtime and account version disagree",
  );
}

export function createGrantKernelRuntime(
  input: Readonly<{
    account: Readonly<KernelAccountProfile>;
    ownerKey: Readonly<KeyProfile>;
    operator: Readonly<OperatorProfile>;
    reads: KernelV33Reads & KernelV4AccountReadCapability;
    gas?: Readonly<KernelGasPolicy>;
    chainId: number;
  }>,
): Readonly<GrantKernelRuntime> {
  const { account } = input;
  if (account.kernelVersion === "0.3.3") {
    const options = {
      deployment: kernelV33Deployment(input.chainId),
      reads: input.reads,
      ...(input.gas === undefined ? {} : { gas: input.gas }),
    };
    const runtime = createKernelRuntime({ ...options, operator: input.operator });
    const owner =
      runtime.authority === "owner"
        ? runtime
        : createKernelRuntime({
            ...options,
            operator: ownerOperator({ key: input.ownerKey }),
          });
    function adapt(
      execution: Pick<KernelV33Runtime, "prepareOperation" | "dummySignature" | "gasPolicy"> &
        Pick<GrantKernelExecution, "signOperation" | "encodeVerifiedSignature">,
    ): GrantKernelExecution {
      return Object.freeze({
        ...execution,
        prepareOperation(value: GrantKernelPrepareInput) {
          if (value.account.profile !== "kernel-v3.3-entrypoint-v0.7") return mismatch();
          if (value.validityTimeRange !== undefined)
            return clientFail(
              "oaath_client_input_invalid",
              "Kernel v3.3 request-time validity is unsupported",
            );
          const { validityTimeRange: _range, mode, ...fields } = value;
          return execution.prepareOperation({
            ...fields,
            account: value.account,
            ...(mode === undefined
              ? {}
              : { mode: mode === "enable-replayable" ? "enable" : "standard" }),
          });
        },
      });
    }
    return Object.freeze({
      ...adapt(runtime),
      validation: runtime.validation,
      deployment: runtime.deployment,
      async bindAccount() {
        const bound = await owner.bindAccount({ address: account.address });
        return runtime.authority === "owner"
          ? bound
          : runtime.bindAccount({ address: account.address });
      },
      bindApproval(approval, address) {
        if (approval.version !== OAATH_KERNEL_V33_APPROVAL_VERSION) return mismatch();
        return adapt(bindKernelV33PermissionApproval({ runtime, approval, account: address }));
      },
    } satisfies GrantKernelRuntime);
  }
  const options = {
    deployment: kernelV4Deployment(input.chainId),
    reads: input.reads,
    ...(input.gas === undefined ? {} : { gas: input.gas }),
  };
  const runtime = createKernelRuntime({ ...options, operator: input.operator });
  const owner = createKernelRuntime({
    ...options,
    operator: ownerOperator({ key: input.ownerKey }),
  });
  function adapt(
    execution: Pick<KernelRuntime, "prepareOperation" | "dummySignature" | "gasPolicy"> &
      Pick<GrantKernelExecution, "signOperation" | "encodeVerifiedSignature">,
  ): GrantKernelExecution {
    return Object.freeze({
      ...execution,
      prepareOperation(value: GrantKernelPrepareInput) {
        if (value.account.profile !== "kernel-v4-uups-entrypoint-v0.7") return mismatch();
        return execution.prepareOperation({ ...value, account: value.account });
      },
    });
  }
  return Object.freeze({
    ...adapt(runtime),
    validation: runtime.validation,
    deployment: runtime.deployment,
    async bindAccount() {
      if (!isKernelExistingAccountProfile(account))
        return runtime.bindAccount({
          accountIndex: account.accountIndex,
          initialPackages: [...owner.packages],
        });
      // An existing account proves its root owner before the operator binds.
      await owner.bindAccount({ address: account.address });
      return runtime.bindAccount({ address: account.address });
    },
    bindApproval(approval, address) {
      if (approval.version === OAATH_KERNEL_V33_APPROVAL_VERSION) return mismatch();
      return adapt(bindKernelPermissionApproval({ runtime, approval, account: address }));
    },
  } satisfies GrantKernelRuntime);
}
