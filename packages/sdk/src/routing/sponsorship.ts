/**
 * Pre-sign sponsorship finalization. A concrete bundler/paymaster adapter may
 * supply only gas and EntryPoint paymaster fields; the composed Kernel runtime
 * re-prepares every other field from the original input before authority signs.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { CaptureContext } from "@oaath/protocol";
import { captureAddress } from "@oaath/protocol";
import type { KernelAccountDescriptor } from "../kernel/deployment/account.js";
import {
  captureKernelGasPolicy,
  enableVerificationFloorForNonce,
  type KernelGasPolicy,
} from "../kernel/gas-policy.js";
import type { KernelRuntimePrepareInput, KernelV33RuntimePrepareInput } from "../kernel/types.js";
import type { KernelUserOperationGas } from "../kernel-v4.js";
import type { PreparedPaymaster, PreparedUserOperation } from "../prepared-user-operation.js";
import { capabilityInvalid, exactRoutingRecord, routingFail } from "./types.js";

const BYTES = /^0x(?:[0-9a-fA-F]{2})*$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;

type SponsorableOperation =
  | KernelRuntimePrepareInput<KernelAccountDescriptor>
  | KernelV33RuntimePrepareInput;

export interface OaathKernelSponsorshipRuntime<
  Operation extends SponsorableOperation = KernelRuntimePrepareInput,
> {
  readonly gasPolicy?: Readonly<KernelGasPolicy>;
  readonly dummySignature: `0x${string}`;
  readonly prepareOperation: (input: Operation) => PreparedUserOperation;
}

export interface OaathKernelSponsorshipRequest {
  /** Captured runtime floor, applied by the adapter before final paymaster authorization. */
  readonly verificationGasFloor?: string;
  readonly prepared: Readonly<PreparedUserOperation>;
  readonly simulationSignature: `0x${string}`;
}

export interface OaathKernelSponsorshipCapability {
  readonly sponsor: (request: Readonly<OaathKernelSponsorshipRequest>) => Promise<unknown>;
}

export interface OaathKernelSponsorshipResult {
  readonly gas: Readonly<KernelUserOperationGas>;
  readonly paymaster: Readonly<PreparedPaymaster>;
}

export interface PrepareSponsoredKernelOperationInput<
  Operation extends SponsorableOperation = KernelRuntimePrepareInput,
> {
  readonly runtime: Readonly<OaathKernelSponsorshipRuntime<Operation>>;
  readonly operation: Operation;
  /** Validation-shaped bytes used only by the paymaster's pre-sign simulation. */
  readonly simulationSignature: `0x${string}`;
  readonly sponsorship: OaathKernelSponsorshipCapability;
}

const invalidEvidence: (message: string) => never = (message) =>
  routingFail("routing_sponsorship_invalid", message);

function decimal(value: unknown, label: string): string {
  if (typeof value !== "string" || !DECIMAL_UINT.test(value))
    return invalidEvidence(`${label} is invalid`);
  return value;
}

function address(value: unknown): `0x${string}` {
  return captureAddress(value, "sponsorship paymaster address", invalidEvidence, true);
}

function bytes(value: unknown): `0x${string}` {
  if (typeof value !== "string" || !BYTES.test(value))
    return invalidEvidence("sponsorship paymaster data is invalid");
  return `0x${value.slice(2).toLowerCase()}`;
}

function captureResult(value: unknown): Readonly<OaathKernelSponsorshipResult> {
  const context: CaptureContext = new WeakSet();
  const result = exactRoutingRecord(
    value,
    ["gas", "paymaster"],
    "sponsorship result",
    context,
    invalidEvidence,
  );
  const gas = exactRoutingRecord(
    result.gas,
    [
      "callGasLimit",
      "verificationGasLimit",
      "preVerificationGas",
      "maxFeePerGas",
      "maxPriorityFeePerGas",
    ],
    "sponsorship gas",
    context,
    invalidEvidence,
  );
  const paymaster = exactRoutingRecord(
    result.paymaster,
    ["address", "verificationGasLimit", "postOpGasLimit", "data"],
    "sponsorship paymaster",
    context,
    invalidEvidence,
  );
  return Object.freeze({
    gas: Object.freeze({
      callGasLimit: decimal(gas.callGasLimit, "sponsorship call gas"),
      verificationGasLimit: decimal(gas.verificationGasLimit, "sponsorship verification gas"),
      preVerificationGas: decimal(gas.preVerificationGas, "sponsorship pre-verification gas"),
      maxFeePerGas: decimal(gas.maxFeePerGas, "sponsorship maximum fee"),
      maxPriorityFeePerGas: decimal(gas.maxPriorityFeePerGas, "sponsorship priority fee"),
    }),
    paymaster: Object.freeze({
      address: address(paymaster.address),
      verificationGasLimit: decimal(
        paymaster.verificationGasLimit,
        "sponsorship paymaster verification gas",
      ),
      postOpGasLimit: decimal(paymaster.postOpGasLimit, "sponsorship paymaster post-op gas"),
      data: bytes(paymaster.data),
    }),
  });
}

/**
 * Returns the one final sponsored operation that authority may sign. The
 * sponsorship capability receives no signer and cannot provide replacement
 * operation fields beyond exact gas and paymaster evidence.
 */
export async function prepareSponsoredKernelOperation<Operation extends SponsorableOperation>(
  input: PrepareSponsoredKernelOperationInput<Operation>,
): Promise<PreparedUserOperation> {
  const context: CaptureContext = new WeakSet();
  const record = exactRoutingRecord(
    input,
    ["runtime", "operation", "simulationSignature", "sponsorship"],
    "sponsorship preparation input",
    context,
    capabilityInvalid,
  );
  const runtime = record.runtime as Readonly<OaathKernelSponsorshipRuntime<Operation>>;
  if (
    !runtime ||
    typeof runtime !== "object" ||
    typeof runtime.prepareOperation !== "function" ||
    typeof runtime.dummySignature !== "string" ||
    !BYTES.test(runtime.dummySignature) ||
    runtime.dummySignature === "0x"
  )
    return capabilityInvalid("sponsorship Kernel runtime is invalid");
  const capabilityRecord = exactRoutingRecord(
    record.sponsorship,
    ["sponsor"],
    "sponsorship capability",
    context,
    capabilityInvalid,
  );
  if (typeof capabilityRecord.sponsor !== "function")
    return capabilityInvalid("sponsorship capability is invalid");
  const sponsor = capabilityRecord.sponsor as OaathKernelSponsorshipCapability["sponsor"];
  const operation = record.operation as Operation;
  const simulationSignature = record.simulationSignature;
  if (
    typeof simulationSignature !== "string" ||
    !BYTES.test(simulationSignature) ||
    simulationSignature === "0x"
  )
    return routingFail("routing_sponsorship_invalid", "simulation signature is invalid");

  const prepared = runtime.prepareOperation(operation);
  const verificationGasFloor = enableVerificationFloorForNonce(
    prepared.userOperation.nonce,
    captureKernelGasPolicy(prepared.chainId, runtime.gasPolicy),
  ).toString(10);
  const result = captureResult(
    await Reflect.apply(sponsor, undefined, [
      Object.freeze({
        prepared,
        simulationSignature,
        verificationGasFloor,
      }),
    ]),
  );
  const final = runtime.prepareOperation({
    kind: operation.kind,
    grantId: operation.grantId,
    account: operation.account,
    nonceKey: operation.nonceKey,
    sequence: operation.sequence,
    calls: operation.calls,
    gas: result.gas,
    ...(operation.mode === undefined ? {} : { mode: operation.mode }),
    ...(!("validityTimeRange" in operation) || operation.validityTimeRange === undefined
      ? {}
      : { validityTimeRange: operation.validityTimeRange }),
    paymaster: result.paymaster,
  } as Operation);
  if (final.userOperation.verificationGasLimit !== result.gas.verificationGasLimit) {
    return invalidEvidence("Sponsorship verification gas is below the configured floor");
  }
  return final;
}
