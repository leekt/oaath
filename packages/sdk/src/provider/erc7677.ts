/**
 * Review ERC-7677 translation into OAAth's existing pre-sign sponsorship owner.
 *
 * This adapter never fetches the application-provided URL. A deployment gives
 * it one registered service capability, and the requested URL is only an exact
 * assertion against that registration. The adapter performs no signing,
 * publication, persistence, submission, retry, or fallback selection.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type CaptureContext,
  captureDenseArray,
  captureRecord,
  OAATH_ISSUER_VERSION,
  parseIssuerIdentity,
} from "@oaath/protocol";
import type { KernelV4UserOperationGas } from "../kernel-v4.js";
import {
  type PreparedPaymaster,
  type PreparedUserOperation,
  parsePreparedUserOperation,
} from "../prepared-user-operation.js";
import type { OaathKernelSponsorshipCapability } from "../routing/sponsorship.js";
import { capabilityInvalid, exactRoutingRecord, routingFail } from "../routing/types.js";
import {
  captureErc7677SponsorDisplayMetadata,
  type OaathErc7677SponsorDisplayMetadata,
  type OaathWalletCallResultCapabilities,
  walletCallSponsorResultCapabilities,
} from "./result-capabilities.js";

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const NONEMPTY_BYTES = /^0x(?:[0-9a-f]{2})+$/u;
const CANONICAL_QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const MAX_UINT120 = (1n << 120n) - 1n;

const LIMITS = Object.freeze({
  contextBytes: 64 * 1_024,
  contextDepth: 32,
  contextNodes: 4_096,
  paymasterDataBytes: 64 * 1_024,
});

interface SponsorshipResultState {
  started: boolean;
  resultCapabilities: Readonly<OaathWalletCallResultCapabilities> | null | undefined;
}

const sponsorshipResultStates = new WeakMap<object, SponsorshipResultState>();

export type Erc7677JsonValue =
  | null
  | boolean
  | number
  | string
  | Erc7677JsonObject
  | readonly Erc7677JsonValue[];

export interface Erc7677JsonObject {
  readonly [key: string]: Erc7677JsonValue;
}

/** Exact EntryPoint 0.7 unsigned wire shape used by ERC-7677. */
export interface Erc7677UnsignedUserOperationV07 {
  readonly sender: `0x${string}`;
  readonly nonce: `0x${string}`;
  readonly factory?: `0x${string}`;
  readonly factoryData?: `0x${string}`;
  readonly callData: `0x${string}`;
  readonly callGasLimit: `0x${string}`;
  readonly verificationGasLimit: `0x${string}`;
  readonly preVerificationGas: `0x${string}`;
  readonly maxFeePerGas: `0x${string}`;
  readonly maxPriorityFeePerGas: `0x${string}`;
  readonly paymaster?: `0x${string}`;
  readonly paymasterVerificationGasLimit?: `0x${string}`;
  readonly paymasterPostOpGasLimit?: `0x${string}`;
  readonly paymasterData?: `0x${string}`;
}

export interface Erc7677EstimationUserOperationV07 extends Erc7677UnsignedUserOperationV07 {
  /** Validation-shaped bytes used only by the injected bundler estimator. */
  readonly signature: `0x${string}`;
}

export type Erc7677PaymasterMethod = "pm_getPaymasterStubData" | "pm_getPaymasterData";

export interface Erc7677PaymasterServiceRequest {
  readonly method: Erc7677PaymasterMethod;
  readonly params: readonly [
    Readonly<Erc7677UnsignedUserOperationV07>,
    `0x${string}`,
    `0x${string}`,
    Readonly<Erc7677JsonObject>,
  ];
}

export interface Erc7677RegisteredPaymasterService {
  /** Canonical deployment-registered URL. The adapter never dereferences it. */
  readonly url: string;
  readonly request: (request: Readonly<Erc7677PaymasterServiceRequest>) => Promise<unknown>;
}

export interface Erc7677GasEstimationRequest {
  /** The exact owner-produced candidate; it is never replaced by estimator output. */
  readonly prepared: Readonly<PreparedUserOperation>;
  readonly userOperation: Readonly<Erc7677EstimationUserOperationV07>;
}

export interface Erc7677GasEstimator {
  readonly estimate: (request: Readonly<Erc7677GasEstimationRequest>) => Promise<unknown>;
}

export interface CreateErc7677SponsorshipCapabilityInput {
  readonly requested: Readonly<{ url: string; context: unknown }>;
  readonly service: Readonly<Erc7677RegisteredPaymasterService>;
  readonly estimator: Readonly<Erc7677GasEstimator>;
}

function invalidConfiguration(message: string): never {
  return capabilityInvalid(message);
}

function invalidEvidence(message: string): never {
  return routingFail("routing_sponsorship_invalid", message);
}

function canonicalUrl(value: unknown): string {
  try {
    return parseIssuerIdentity({ version: OAATH_ISSUER_VERSION, url: value }).url;
  } catch {
    return invalidConfiguration("ERC-7677 paymaster service URL is invalid");
  }
}

interface JsonBudget {
  nodes: number;
}

function jsonValue(
  value: unknown,
  context: CaptureContext,
  budget: JsonBudget,
  depth: number,
): Erc7677JsonValue {
  budget.nodes += 1;
  if (budget.nodes > LIMITS.contextNodes || depth > LIMITS.contextDepth) {
    return invalidConfiguration("ERC-7677 context is too large");
  }
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return invalidConfiguration("ERC-7677 context is not JSON");
    return Object.is(value, -0) ? 0 : value;
  }
  if (!value || typeof value !== "object") {
    return invalidConfiguration("ERC-7677 context is not JSON");
  }

  let array: boolean;
  try {
    array = Array.isArray(value);
  } catch {
    return invalidConfiguration("ERC-7677 context is invalid");
  }
  if (array) {
    const entries = captureDenseArray(
      value,
      "ERC-7677 context array",
      context,
      invalidConfiguration,
    );
    return Object.freeze(entries.map((entry) => jsonValue(entry, context, budget, depth + 1)));
  }

  const record = captureRecord(value, "ERC-7677 context object", context, invalidConfiguration);
  const captured: Record<string, Erc7677JsonValue> = Object.create(null);
  for (const key of Object.keys(record)) {
    captured[key] = jsonValue(record[key], context, budget, depth + 1);
  }
  return Object.freeze(captured);
}

function capturedContext(value: unknown, context: CaptureContext): Readonly<Erc7677JsonObject> {
  const captured = jsonValue(value, context, { nodes: 0 }, 0);
  if (captured === null || typeof captured !== "object" || Array.isArray(captured)) {
    return invalidConfiguration("ERC-7677 context must be an object");
  }
  const encoded = JSON.stringify(captured);
  if (new TextEncoder().encode(encoded).byteLength > LIMITS.contextBytes) {
    return invalidConfiguration("ERC-7677 context is too large");
  }
  return captured as Readonly<Erc7677JsonObject>;
}

function allowedRecord(
  value: unknown,
  allowed: readonly string[],
  required: readonly string[],
  label: string,
  context: CaptureContext,
): Record<string, unknown> {
  const record = captureRecord(value, label, context, invalidEvidence);
  for (const key of Object.keys(record)) {
    if (!allowed.includes(key)) return invalidEvidence(`${label} contains an unknown field`);
  }
  for (const key of required) {
    if (!Object.hasOwn(record, key)) return invalidEvidence(`${label} is missing a field`);
  }
  return record;
}

function canonicalAddress(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string") return invalidEvidence(`${label} is invalid`);
  const canonical = value.toLowerCase();
  if (!ADDRESS.test(canonical) || canonical === ZERO_ADDRESS) {
    return invalidEvidence(`${label} is invalid`);
  }
  return canonical as `0x${string}`;
}

function canonicalBytes(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string") return invalidEvidence(`${label} is invalid`);
  const canonical = value.toLowerCase();
  if (!BYTES.test(canonical) || (canonical.length - 2) / 2 > LIMITS.paymasterDataBytes) {
    return invalidEvidence(`${label} is invalid`);
  }
  return canonical as `0x${string}`;
}

function quantity(value: unknown, label: string): string {
  if (typeof value !== "string" || !CANONICAL_QUANTITY.test(value)) {
    return invalidEvidence(`${label} is invalid`);
  }
  const parsed = BigInt(value);
  if (parsed > MAX_UINT120) return invalidEvidence(`${label} is out of bounds`);
  return parsed.toString(10);
}

function decimal(value: unknown, label: string): string {
  if (typeof value !== "string" || !DECIMAL_UINT.test(value) || BigInt(value) > MAX_UINT120) {
    return invalidEvidence(`${label} is invalid`);
  }
  return value;
}

function decimalQuantity(value: string): `0x${string}` {
  return `0x${BigInt(value).toString(16)}`;
}

interface CapturedStub {
  readonly address: `0x${string}`;
  readonly data: `0x${string}`;
  readonly verificationGasLimit: string | null;
  readonly postOpGasLimit: string;
  readonly isFinal: boolean;
  readonly sponsor: Readonly<OaathErc7677SponsorDisplayMetadata> | null;
}

function captureStub(value: unknown): Readonly<CapturedStub> {
  const context: CaptureContext = new WeakSet();
  const record = allowedRecord(
    value,
    [
      "sponsor",
      "paymaster",
      "paymasterData",
      "paymasterVerificationGasLimit",
      "paymasterPostOpGasLimit",
      "isFinal",
    ],
    ["paymaster", "paymasterData", "paymasterPostOpGasLimit"],
    "ERC-7677 stub result",
    context,
  );
  const sponsor = Object.hasOwn(record, "sponsor")
    ? captureErc7677SponsorDisplayMetadata(record.sponsor, context, invalidEvidence)
    : null;
  let isFinal = false;
  if (Object.hasOwn(record, "isFinal")) {
    if (typeof record.isFinal !== "boolean") {
      return invalidEvidence("ERC-7677 stub finality is invalid");
    }
    isFinal = record.isFinal;
  }
  return Object.freeze({
    address: canonicalAddress(record.paymaster, "ERC-7677 stub paymaster"),
    data: canonicalBytes(record.paymasterData, "ERC-7677 stub paymaster data"),
    verificationGasLimit: Object.hasOwn(record, "paymasterVerificationGasLimit")
      ? quantity(record.paymasterVerificationGasLimit, "ERC-7677 stub paymaster verification gas")
      : null,
    postOpGasLimit: quantity(record.paymasterPostOpGasLimit, "ERC-7677 stub paymaster post-op gas"),
    isFinal,
    sponsor,
  });
}

interface CapturedFinalData {
  readonly address: `0x${string}`;
  readonly data: `0x${string}`;
}

function captureFinalData(value: unknown): Readonly<CapturedFinalData> {
  const record = allowedRecord(
    value,
    ["paymaster", "paymasterData"],
    ["paymaster", "paymasterData"],
    "ERC-7677 final result",
    new WeakSet(),
  );
  return Object.freeze({
    address: canonicalAddress(record.paymaster, "ERC-7677 final paymaster"),
    data: canonicalBytes(record.paymasterData, "ERC-7677 final paymaster data"),
  });
}

interface CapturedEstimate {
  readonly callGasLimit: string;
  readonly verificationGasLimit: string;
  readonly preVerificationGas: string;
  readonly paymasterVerificationGasLimit: string | null;
}

function captureEstimate(value: unknown): Readonly<CapturedEstimate> {
  const record = allowedRecord(
    value,
    ["callGasLimit", "verificationGasLimit", "preVerificationGas", "paymasterVerificationGasLimit"],
    ["callGasLimit", "verificationGasLimit", "preVerificationGas"],
    "ERC-7677 gas estimate",
    new WeakSet(),
  );
  return Object.freeze({
    callGasLimit: decimal(record.callGasLimit, "ERC-7677 call gas estimate"),
    verificationGasLimit: decimal(
      record.verificationGasLimit,
      "ERC-7677 verification gas estimate",
    ),
    preVerificationGas: decimal(
      record.preVerificationGas,
      "ERC-7677 pre-verification gas estimate",
    ),
    paymasterVerificationGasLimit: Object.hasOwn(record, "paymasterVerificationGasLimit")
      ? decimal(
          record.paymasterVerificationGasLimit,
          "ERC-7677 paymaster verification gas estimate",
        )
      : null,
  });
}

function unsignedWire(
  prepared: Readonly<PreparedUserOperation>,
  gas?: Readonly<CapturedEstimate>,
  paymaster?: Readonly<CapturedStub>,
): Readonly<Erc7677UnsignedUserOperationV07> {
  const operation = prepared.userOperation;
  const paymasterVerificationGasLimit =
    paymaster?.verificationGasLimit ?? gas?.paymasterVerificationGasLimit ?? null;
  return Object.freeze({
    sender: operation.sender,
    nonce: decimalQuantity(operation.nonce),
    ...(operation.factory === null
      ? {}
      : { factory: operation.factory.address, factoryData: operation.factory.data }),
    callData: operation.callData,
    callGasLimit: decimalQuantity(gas?.callGasLimit ?? operation.callGasLimit),
    verificationGasLimit: decimalQuantity(
      gas?.verificationGasLimit ?? operation.verificationGasLimit,
    ),
    preVerificationGas: decimalQuantity(gas?.preVerificationGas ?? operation.preVerificationGas),
    maxFeePerGas: decimalQuantity(operation.maxFeePerGas),
    maxPriorityFeePerGas: decimalQuantity(operation.maxPriorityFeePerGas),
    ...(paymaster === undefined
      ? {}
      : {
          paymaster: paymaster.address,
          ...(paymasterVerificationGasLimit === null
            ? {}
            : {
                paymasterVerificationGasLimit: decimalQuantity(paymasterVerificationGasLimit),
              }),
          paymasterPostOpGasLimit: decimalQuantity(paymaster.postOpGasLimit),
          paymasterData: paymaster.data,
        }),
  });
}

function byteZeroCount(value: `0x${string}`): number {
  let count = 0;
  for (let index = 2; index < value.length; index += 2) {
    if (value.slice(index, index + 2) === "00") count += 1;
  }
  return count;
}

function assertFinalMatchesStub(
  stub: Readonly<CapturedStub>,
  finalData: Readonly<CapturedFinalData>,
): void {
  if (finalData.address !== stub.address) {
    invalidEvidence("ERC-7677 final paymaster differs from the stub");
  }
  if (
    finalData.data.length !== stub.data.length ||
    byteZeroCount(stub.data) > byteZeroCount(finalData.data)
  ) {
    invalidEvidence("ERC-7677 final paymaster data contradicts the stub");
  }
}

function paymasterRequest(
  method: Erc7677PaymasterMethod,
  userOperation: Readonly<Erc7677UnsignedUserOperationV07>,
  prepared: Readonly<PreparedUserOperation>,
  context: Readonly<Erc7677JsonObject>,
): Readonly<Erc7677PaymasterServiceRequest> {
  return Object.freeze({
    method,
    params: Object.freeze([
      userOperation,
      prepared.entryPoint.address,
      `0x${prepared.chainId.toString(16)}`,
      context,
    ]) as Erc7677PaymasterServiceRequest["params"],
  });
}

async function invokeService(
  request: Erc7677RegisteredPaymasterService["request"],
  value: Readonly<Erc7677PaymasterServiceRequest>,
): Promise<unknown> {
  try {
    return await Reflect.apply(request, undefined, [value]);
  } catch {
    return invalidEvidence("ERC-7677 paymaster service did not answer");
  }
}

async function invokeEstimator(
  estimate: Erc7677GasEstimator["estimate"],
  value: Readonly<Erc7677GasEstimationRequest>,
): Promise<unknown> {
  try {
    return await Reflect.apply(estimate, undefined, [value]);
  } catch {
    return invalidEvidence("ERC-7677 gas estimator did not answer");
  }
}

/** Reads display-only facts after this exact adapter capability completed. */
export function readCompletedErc7677ResultCapabilities(
  capability: Readonly<OaathKernelSponsorshipCapability>,
): Readonly<OaathWalletCallResultCapabilities> | null {
  const state = sponsorshipResultStates.get(capability);
  if (state === undefined || state.resultCapabilities === undefined) {
    return invalidConfiguration("ERC-7677 sponsorship result metadata is unavailable");
  }
  return state.resultCapabilities;
}

/**
 * Creates the one ERC-7677 translation accepted by
 * `prepareSponsoredKernelOperation`. URL authorization and context capture
 * happen immediately, before the returned capability can prepare an operation
 * or invoke either external capability.
 */
export function createErc7677SponsorshipCapability(
  input: Readonly<CreateErc7677SponsorshipCapabilityInput>,
): Readonly<OaathKernelSponsorshipCapability> {
  const context: CaptureContext = new WeakSet();
  const record = exactRoutingRecord(
    input,
    ["requested", "service", "estimator"],
    "ERC-7677 adapter input",
    context,
    invalidConfiguration,
  );
  const requested = exactRoutingRecord(
    record.requested,
    ["url", "context"],
    "ERC-7677 requested service",
    context,
    invalidConfiguration,
  );
  const service = exactRoutingRecord(
    record.service,
    ["url", "request"],
    "ERC-7677 registered service",
    context,
    invalidConfiguration,
  );
  const estimator = exactRoutingRecord(
    record.estimator,
    ["estimate"],
    "ERC-7677 estimator",
    context,
    invalidConfiguration,
  );
  const requestedUrl = canonicalUrl(requested.url);
  const registeredUrl = canonicalUrl(service.url);
  if (requestedUrl !== registeredUrl) {
    return invalidConfiguration("ERC-7677 paymaster service is not registered");
  }
  if (typeof service.request !== "function" || typeof estimator.estimate !== "function") {
    return invalidConfiguration("ERC-7677 capabilities are invalid");
  }
  const paymasterContext = capturedContext(requested.context, context);
  const serviceRequest = service.request as Erc7677RegisteredPaymasterService["request"];
  const estimateGas = estimator.estimate as Erc7677GasEstimator["estimate"];
  const state: SponsorshipResultState = { started: false, resultCapabilities: undefined };
  const capability: Readonly<OaathKernelSponsorshipCapability> = Object.freeze({
    async sponsor(value: unknown) {
      if (state.started) return invalidEvidence("ERC-7677 sponsorship capability was already used");
      state.started = true;
      state.resultCapabilities = undefined;
      const sponsorInput = exactRoutingRecord(
        value,
        ["prepared", "simulationSignature"],
        "ERC-7677 sponsorship request",
        new WeakSet(),
        invalidEvidence,
      );
      let prepared: Readonly<PreparedUserOperation>;
      try {
        prepared = parsePreparedUserOperation(sponsorInput.prepared);
      } catch {
        return invalidEvidence("ERC-7677 prepared operation is invalid");
      }
      if (prepared.userOperation.paymaster !== null) {
        return invalidEvidence("ERC-7677 candidate already has a paymaster");
      }
      const simulationSignature = sponsorInput.simulationSignature;
      if (typeof simulationSignature !== "string" || !NONEMPTY_BYTES.test(simulationSignature)) {
        return invalidEvidence("ERC-7677 simulation signature is invalid");
      }
      const initialWire = unsignedWire(prepared);
      const stub = captureStub(
        await invokeService(
          serviceRequest,
          paymasterRequest("pm_getPaymasterStubData", initialWire, prepared, paymasterContext),
        ),
      );
      const estimate = captureEstimate(
        await invokeEstimator(
          estimateGas,
          Object.freeze({
            prepared,
            userOperation: Object.freeze({
              ...unsignedWire(prepared, undefined, stub),
              signature: simulationSignature as `0x${string}`,
            }),
          }),
        ),
      );
      const paymasterVerificationGasLimit =
        stub.verificationGasLimit ?? estimate.paymasterVerificationGasLimit;
      if (paymasterVerificationGasLimit === null) {
        return invalidEvidence("ERC-7677 paymaster verification gas is absent");
      }

      let finalData: Readonly<CapturedFinalData> = Object.freeze({
        address: stub.address,
        data: stub.data,
      });
      if (!stub.isFinal) {
        finalData = captureFinalData(
          await invokeService(
            serviceRequest,
            paymasterRequest(
              "pm_getPaymasterData",
              unsignedWire(prepared, estimate, stub),
              prepared,
              paymasterContext,
            ),
          ),
        );
        assertFinalMatchesStub(stub, finalData);
      }

      const gas: Readonly<KernelV4UserOperationGas> = Object.freeze({
        callGasLimit: estimate.callGasLimit,
        verificationGasLimit: estimate.verificationGasLimit,
        preVerificationGas: estimate.preVerificationGas,
        maxFeePerGas: prepared.userOperation.maxFeePerGas,
        maxPriorityFeePerGas: prepared.userOperation.maxPriorityFeePerGas,
      });
      const paymaster: Readonly<PreparedPaymaster> = Object.freeze({
        address: finalData.address,
        verificationGasLimit: paymasterVerificationGasLimit,
        postOpGasLimit: stub.postOpGasLimit,
        data: finalData.data,
      });
      state.resultCapabilities =
        stub.sponsor === null ? null : walletCallSponsorResultCapabilities(stub.sponsor);
      return Object.freeze({ gas, paymaster });
    },
  });
  sponsorshipResultStates.set(capability, state);
  return capability;
}
