import {
  concat,
  decodeAbiParameters,
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  type Hex,
  hexToBigInt,
  keccak256,
  pad,
  toHex,
} from "viem";
import {
  type CaptureContext,
  captureDenseArray,
  captureRecord,
  type ExactRecord,
  exactCapturedRecord,
} from "./internal/exact-record.js";
import { type PreparedUserOperation, prepareUserOperation } from "./prepared-user-operation.js";

const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const BYTES4 = /^0x[0-9a-f]{8}$/u;
const BYTES32 = /^0x[0-9a-f]{64}$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const NO_HOOK = `0x${"00".repeat(19)}01` as const;
const EXECUTE_USER_OP_SELECTOR = "0x8dd7712f" as const;
const MAX_UINT16 = (1n << 16n) - 1n;
const MAX_UINT64 = (1n << 64n) - 1n;
const MAX_UINT256 = (1n << 256n) - 1n;
const BOUND_ACCOUNTS = new WeakSet<object>();

export const KERNEL_V4_ENTRY_POINT_V07 = "0x0000000071727de22e5e9d8baf0edac6f37da032" as const;
export const KERNEL_V4_UUPS_IMPLEMENTATION_V07 =
  "0x3c504000d05c1e28687f70fca40a76f7ddda9952" as const;
export const KERNEL_V4_FACTORY_V07 = "0xe65c6a17bdb14070977b4ab70f1e7d9cdf441d53" as const;
export const KERNEL_V4_CREATE2_DEPLOYER = "0x4e59b44847b379578588920ca78fbf26c0b4956c" as const;
export const KERNEL_V4_ENTRY_POINT_V07_CODE_HASH =
  "0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58" as const;
export const KERNEL_V4_FACTORY_V07_CODE_HASH =
  "0xac398027b5068558aaf4fb5c986a6ae397e891d0c6e8d8181881385648ff629f" as const;
/** ERC-1967 implementation storage slot read by kernel_account_implementation. */
export const KERNEL_V4_IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" as const;
/**
 * Kernel v4 execute(bytes32,bytes) selector. A validator or signer installed
 * for non-root validation must allow-list this selector in its internalData,
 * or every prepared non-root operation reverts on-chain with
 * UnauthorizedCallData (AA23).
 */
export const KERNEL_V4_EXECUTE_SELECTOR = "0xe9ae5c53" as const;

export type KernelV4SupportedChainId = 46_630 | 421_614 | 11_155_111;
export type KernelV4ModuleType = 1 | 2 | 3 | 4 | 5 | 6;
export type KernelV4ValidationMode =
  | "standard"
  | "enable"
  | "enable-replayable"
  | "replayable"
  | "enable-user-operation-replayable"
  | "enable-all-replayable";

export type KernelV4ErrorCode =
  | "kernel_v4_input_invalid"
  | "kernel_v4_chain_unsupported"
  | "kernel_v4_read_unavailable"
  | "kernel_v4_evidence_invalid";

export class OaathKernelV4Error extends Error {
  readonly code: KernelV4ErrorCode;

  constructor(code: KernelV4ErrorCode, message: string) {
    super(message);
    this.name = "OaathKernelV4Error";
    this.code = code;
  }
}

export interface KernelV4Deployment {
  readonly profile: "kernel-v4-uups-entrypoint-v0.7";
  readonly kernelVersion: "0.4.0";
  readonly accountType: "uups";
  readonly chainId: KernelV4SupportedChainId;
  readonly chain: "arbitrum-sepolia" | "ethereum-sepolia" | "robinhood-sepolia";
  readonly entryPoint: Readonly<{
    version: "0.7";
    address: typeof KERNEL_V4_ENTRY_POINT_V07;
  }>;
  readonly implementation: typeof KERNEL_V4_UUPS_IMPLEMENTATION_V07;
  readonly factory: typeof KERNEL_V4_FACTORY_V07;
  readonly implementationDeployment: Readonly<{
    deployer: typeof KERNEL_V4_CREATE2_DEPLOYER;
    transactionHash: `0x${string}`;
    runtimeCodeHash: `0x${string}`;
  }>;
}

export interface KernelV4Install {
  readonly moduleType: KernelV4ModuleType;
  readonly module: `0x${string}`;
  readonly moduleData: `0x${string}`;
  readonly internalData: `0x${string}`;
}

export interface KernelV4Call {
  readonly target: `0x${string}`;
  readonly value: string;
  readonly data: `0x${string}`;
}

export interface KernelV4UserOperationGas {
  readonly callGasLimit: string;
  readonly verificationGasLimit: string;
  readonly preVerificationGas: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
}

export type KernelV4Validation =
  | Readonly<{ kind: "root" }>
  | Readonly<{ kind: "validator"; validator: `0x${string}` }>
  | Readonly<{ kind: "permission"; permissionId: `0x${string}` }>;

export interface KernelV4ModuleDataInput {
  readonly hook: "none" | `0x${string}`;
  readonly selectors: readonly `0x${string}`[];
}

export interface KernelV4SignerDataInput extends KernelV4ModuleDataInput {
  readonly permissionId: `0x${string}`;
}

export interface KernelV4AccountInput {
  readonly initialPackages: readonly KernelV4Install[];
  readonly accountIndex: string;
}

export interface KernelV4NonceKeyInput {
  readonly mode: KernelV4ValidationMode;
  readonly validation: KernelV4Validation;
  readonly nonceKey: string;
}

export interface KernelV4NonceInput {
  readonly key: string;
  readonly sequence: string;
}

export interface KernelV4NonceReadInput {
  readonly account: `0x${string}`;
  readonly key: string;
}

export interface KernelV4UserOperationNonceInput extends KernelV4NonceKeyInput {
  readonly sequence: string;
}

export interface KernelV4UserOperationInput {
  readonly kind: "execution" | "revocation";
  readonly grantId: string;
  readonly account: KernelV4AccountDescriptor;
  readonly nonce: KernelV4UserOperationNonceInput;
  readonly calls: readonly KernelV4Call[];
  readonly gas: KernelV4UserOperationGas;
}

export interface KernelV4EnableSignatureInput {
  readonly nonce: string;
  readonly packages: readonly KernelV4Install[];
  readonly enableSignature: `0x${string}`;
  readonly userOperationSignature: `0x${string}`;
}

export interface KernelV4ExecutionInput {
  readonly calls: readonly KernelV4Call[];
}

export type KernelV4AccountReadRequest =
  | Readonly<{ type: "chain_id"; chainId: KernelV4SupportedChainId }>
  | Readonly<{
      type: "code";
      chainId: KernelV4SupportedChainId;
      address: `0x${string}`;
    }>
  | Readonly<{
      type: "runtime_code_hash";
      chainId: KernelV4SupportedChainId;
      address: `0x${string}`;
    }>
  | Readonly<{
      type: "kernel_factory_implementation";
      chainId: KernelV4SupportedChainId;
      factory: `0x${string}`;
      calldata: `0x${string}`;
    }>
  | Readonly<{
      type: "kernel_factory_account";
      chainId: KernelV4SupportedChainId;
      factory: `0x${string}`;
      calldata: `0x${string}`;
    }>
  | Readonly<{
      type: "kernel_account_implementation";
      chainId: KernelV4SupportedChainId;
      account: `0x${string}`;
    }>;

export interface KernelV4AccountReadCapability {
  readonly read: (request: KernelV4AccountReadRequest) => Promise<unknown>;
}

export interface KernelV4BindAccountInput extends KernelV4AccountInput {
  readonly chainId: number;
  readonly reads: KernelV4AccountReadCapability;
}

/**
 * Minimal viem-PublicClient-shaped surface consumed by createKernelV4Reads.
 * Any client whose getChainId/getCode/getStorageAt/call match structurally
 * satisfies it.
 */
export interface KernelV4ReadClient {
  readonly getChainId: () => Promise<number>;
  readonly getCode: (args: { address: `0x${string}` }) => Promise<`0x${string}` | undefined>;
  readonly getStorageAt: (args: {
    address: `0x${string}`;
    slot: `0x${string}`;
  }) => Promise<`0x${string}` | null | undefined>;
  readonly call: (args: {
    to: `0x${string}`;
    data: `0x${string}`;
  }) => Promise<{ data?: `0x${string}` | undefined }>;
}

export interface KernelV4AccountDescriptor {
  readonly profile: "kernel-v4-uups-entrypoint-v0.7";
  readonly state: "counterfactual" | "deployed";
  readonly chainId: KernelV4SupportedChainId;
  readonly entryPoint: typeof KERNEL_V4_ENTRY_POINT_V07;
  readonly implementation: typeof KERNEL_V4_UUPS_IMPLEMENTATION_V07;
  readonly factory: typeof KERNEL_V4_FACTORY_V07;
  readonly account: `0x${string}`;
  readonly accountIndex: string;
  readonly initialPackages: readonly Readonly<KernelV4Install>[];
  readonly factoryAddressCalldata: `0x${string}`;
  readonly factoryDeployCalldata: `0x${string}`;
}

const ENTRY_POINT = Object.freeze({
  version: "0.7" as const,
  address: KERNEL_V4_ENTRY_POINT_V07,
});

const implementationDeployment = (transactionHash: `0x${string}`, runtimeCodeHash: `0x${string}`) =>
  Object.freeze({ deployer: KERNEL_V4_CREATE2_DEPLOYER, transactionHash, runtimeCodeHash });

const DEPLOYMENTS: Readonly<Record<KernelV4SupportedChainId, KernelV4Deployment>> = Object.freeze({
  46_630: Object.freeze({
    profile: "kernel-v4-uups-entrypoint-v0.7",
    kernelVersion: "0.4.0",
    accountType: "uups",
    chainId: 46_630,
    chain: "robinhood-sepolia",
    entryPoint: ENTRY_POINT,
    implementation: KERNEL_V4_UUPS_IMPLEMENTATION_V07,
    factory: KERNEL_V4_FACTORY_V07,
    implementationDeployment: implementationDeployment(
      "0xf662be20e4e8d3b0fcfb7bd08845ea89b45977d82aa315cb78530f013f4f2782",
      "0xaef18d8059fa2474272125891050e2e755f45db00c2668b45b7062b2a9579be0",
    ),
  }),
  421_614: Object.freeze({
    profile: "kernel-v4-uups-entrypoint-v0.7",
    kernelVersion: "0.4.0",
    accountType: "uups",
    chainId: 421_614,
    chain: "arbitrum-sepolia",
    entryPoint: ENTRY_POINT,
    implementation: KERNEL_V4_UUPS_IMPLEMENTATION_V07,
    factory: KERNEL_V4_FACTORY_V07,
    implementationDeployment: implementationDeployment(
      "0xa63c36c76b536b1c11d75c68ac5ca15d4ce2c09a40e90ab29ff6601b4bdb0d33",
      "0xd0c42b1ed1738560c1b243fd9e5fc04b2eb5aa1be9962ac7f1f61696f9e6902b",
    ),
  }),
  11_155_111: Object.freeze({
    profile: "kernel-v4-uups-entrypoint-v0.7",
    kernelVersion: "0.4.0",
    accountType: "uups",
    chainId: 11_155_111,
    chain: "ethereum-sepolia",
    entryPoint: ENTRY_POINT,
    implementation: KERNEL_V4_UUPS_IMPLEMENTATION_V07,
    factory: KERNEL_V4_FACTORY_V07,
    implementationDeployment: implementationDeployment(
      "0x54528619ceafbcc656a7d0f7b637213f38d2fbe013a0e2909cfa3fef6dca7cc0",
      "0xb1f85627093213ec87a1484b6af7192651f4dbd6c5f9e9c0aff22e332c5ddb01",
    ),
  }),
});

const INSTALL_COMPONENTS = [
  { name: "moduleType", type: "uint256" },
  { name: "module", type: "address" },
  { name: "moduleData", type: "bytes" },
  { name: "internalData", type: "bytes" },
] as const;

const INSTALL_ARRAY_PARAMETER = {
  name: "packages",
  type: "tuple[]",
  components: INSTALL_COMPONENTS,
} as const;

const ENTRY_POINT_GET_NONCE_ABI = [
  {
    type: "function",
    name: "getNonce",
    stateMutability: "view",
    inputs: [
      { name: "sender", type: "address" },
      { name: "key", type: "uint192" },
    ],
    outputs: [{ name: "nonce", type: "uint256" }],
  },
] as const;

const FACTORY_ABI = [
  {
    type: "function",
    name: "UUPS",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "getAddress",
    stateMutability: "view",
    inputs: [INSTALL_ARRAY_PARAMETER, { name: "nonce", type: "uint256" }],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "deploy",
    stateMutability: "payable",
    inputs: [INSTALL_ARRAY_PARAMETER, { name: "nonce", type: "uint256" }],
    outputs: [{ name: "", type: "address" }],
  },
] as const;

const KERNEL_ABI = [
  {
    type: "function",
    name: "initialize",
    stateMutability: "payable",
    inputs: [INSTALL_ARRAY_PARAMETER],
    outputs: [],
  },
  {
    type: "function",
    name: "installModule",
    stateMutability: "payable",
    inputs: [INSTALL_ARRAY_PARAMETER],
    outputs: [],
  },
  {
    type: "function",
    name: "execute",
    stateMutability: "payable",
    inputs: [
      { name: "mode", type: "bytes32" },
      { name: "executionData", type: "bytes" },
    ],
    outputs: [],
  },
] as const;

function kernelError(code: KernelV4ErrorCode, message: string): never {
  throw new OaathKernelV4Error(code, message);
}

function fail(message: string): never {
  return kernelError("kernel_v4_input_invalid", message);
}

function exact(
  value: unknown,
  keys: readonly string[],
  label: string,
  context: CaptureContext,
): ExactRecord {
  return exactCapturedRecord(captureRecord(value, label, context, fail), keys, label, fail);
}

function address(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string") return fail(`${label} is invalid`);
  try {
    const canonical = getAddress(value).toLowerCase() as `0x${string}`;
    if (canonical === ZERO_ADDRESS) return fail(`${label} is invalid`);
    return canonical;
  } catch {
    return fail(`${label} is invalid`);
  }
}

function bytes(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string" || !BYTES.test(value)) return fail(`${label} is invalid`);
  return value as `0x${string}`;
}

function bytes4(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string" || !BYTES4.test(value)) return fail(`${label} is invalid`);
  return value as `0x${string}`;
}

function uint(value: unknown, maximum: bigint, label: string): bigint {
  if (typeof value !== "string" || !DECIMAL_UINT.test(value)) return fail(`${label} is invalid`);
  const parsed = BigInt(value);
  if (parsed > maximum) return fail(`${label} is invalid`);
  return parsed;
}

function callable(value: unknown, label: string): KernelV4AccountReadCapability["read"] {
  if (typeof value !== "function") return fail(`${label} is invalid`);
  return value as KernelV4AccountReadCapability["read"];
}

function evidenceInvalid(message: string): never {
  return kernelError("kernel_v4_evidence_invalid", message);
}

function evidenceAddress(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string") return evidenceInvalid(`${label} is invalid`);
  try {
    const canonical = getAddress(value).toLowerCase() as `0x${string}`;
    if (canonical === ZERO_ADDRESS) return evidenceInvalid(`${label} is invalid`);
    return canonical;
  } catch {
    return evidenceInvalid(`${label} is invalid`);
  }
}

function evidenceCode(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string" || !BYTES.test(value) || value === "0x") {
    return evidenceInvalid(`${label} is invalid`);
  }
  return value as `0x${string}`;
}

function evidenceCodeHash(value: unknown, expected: Hex, label: string): void {
  if (typeof value !== "string" || !BYTES32.test(value) || value !== expected) {
    evidenceInvalid(`${label} does not match the deployment profile`);
  }
}

async function readEvidence(
  read: KernelV4AccountReadCapability["read"],
  request: KernelV4AccountReadRequest,
): Promise<unknown> {
  try {
    return await read(request);
  } catch {
    return kernelError("kernel_v4_read_unavailable", "Kernel v4 account evidence is unavailable");
  }
}

function moduleType(value: unknown): KernelV4ModuleType {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > 6) {
    return fail("Kernel module type is invalid");
  }
  return value as KernelV4ModuleType;
}

function captureInstall(
  value: unknown,
  context: CaptureContext,
  index: number,
): Readonly<KernelV4Install> {
  const record = exact(
    value,
    ["moduleType", "module", "moduleData", "internalData"],
    `Kernel install package ${index}`,
    context,
  );
  return Object.freeze({
    moduleType: moduleType(record.moduleType),
    module: address(record.module, "Kernel install module"),
    moduleData: bytes(record.moduleData, "Kernel install module data"),
    internalData: bytes(record.internalData, "Kernel install internal data"),
  });
}

function captureInstalls(
  value: unknown,
  context: CaptureContext,
  label: string,
): readonly Readonly<KernelV4Install>[] {
  const values = captureDenseArray(value, label, context, fail);
  if (values.length < 1 || values.length > 256) {
    return fail("Kernel install package count is invalid");
  }
  const packages = values.map((entry, index) => captureInstall(entry, context, index));
  let pendingPermission: string | undefined;
  for (const pkg of packages) {
    if (pkg.moduleType !== 5 && pkg.moduleType !== 6) continue;
    if (pkg.internalData.length < 10) return fail("Kernel permission package is invalid");
    const permission = pkg.internalData.slice(0, 10);
    if (pendingPermission && pendingPermission !== permission) {
      return fail("Kernel permission package sequence is invalid");
    }
    if (pkg.moduleType === 6 && !pendingPermission) {
      return fail("Kernel permission package sequence is invalid");
    }
    pendingPermission = pkg.moduleType === 5 ? permission : undefined;
  }
  if (pendingPermission) return fail("Kernel permission package sequence is incomplete");
  return Object.freeze(packages);
}

function captureInitialPackages(
  value: unknown,
  context: CaptureContext,
): readonly Readonly<KernelV4Install>[] {
  const packages = captureInstalls(value, context, "Kernel initial packages");
  const root = packages[0];
  if (!root || (root.moduleType !== 1 && root.moduleType !== 5 && root.moduleType !== 6)) {
    return fail("Kernel initial root package is invalid");
  }
  return packages;
}

function captureSelectors(value: unknown, context: CaptureContext): readonly `0x${string}`[] {
  const values = captureDenseArray(value, "Kernel selectors", context, fail);
  if (values.length > 256) return fail("Kernel selector count is invalid");
  const seen = new Set<string>();
  return Object.freeze(
    values.map((entry) => {
      const selector = bytes4(entry, "Kernel selector");
      if (seen.has(selector)) return fail("Kernel selectors contain a duplicate");
      seen.add(selector);
      return selector;
    }),
  );
}

function installTuples(installs: readonly Readonly<KernelV4Install>[]): readonly Readonly<{
  moduleType: bigint;
  module: `0x${string}`;
  moduleData: `0x${string}`;
  internalData: `0x${string}`;
}>[] {
  return Object.freeze(
    installs.map((install) =>
      Object.freeze({
        moduleType: BigInt(install.moduleType),
        module: install.module,
        moduleData: install.moduleData,
        internalData: install.internalData,
      }),
    ),
  );
}

export function kernelV4Deployment(chainId: unknown): Readonly<KernelV4Deployment> {
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId)) {
    return kernelError("kernel_v4_chain_unsupported", "Kernel v4 chain is unsupported");
  }
  const deployment = DEPLOYMENTS[chainId as KernelV4SupportedChainId];
  if (!deployment) {
    return kernelError("kernel_v4_chain_unsupported", "Kernel v4 chain is unsupported");
  }
  return deployment;
}

/** Encodes Kernel v4 validator internalData: hook followed by allowed selectors. */
export function encodeKernelV4ValidatorData(value: KernelV4ModuleDataInput): Hex {
  const context: CaptureContext = new WeakSet();
  const record = exact(value, ["hook", "selectors"], "Kernel validator data", context);
  const hook = record.hook === "none" ? NO_HOOK : address(record.hook, "Kernel validator hook");
  return concat([hook, ...captureSelectors(record.selectors, context)]);
}

/** Encodes Kernel v4 policy internalData. */
export function encodeKernelV4PolicyData(permissionId: `0x${string}`): Hex {
  return bytes4(permissionId, "Kernel permission ID");
}

/** Encodes Kernel v4 signer internalData: permission ID, hook, then allowed selectors. */
export function encodeKernelV4SignerData(value: KernelV4SignerDataInput): Hex {
  const context: CaptureContext = new WeakSet();
  const record = exact(value, ["permissionId", "hook", "selectors"], "Kernel signer data", context);
  const hook = record.hook === "none" ? NO_HOOK : address(record.hook, "Kernel signer hook");
  return concat([
    bytes4(record.permissionId, "Kernel permission ID"),
    hook,
    ...captureSelectors(record.selectors, context),
  ]);
}

export function encodeKernelV4Initialize(installs: readonly KernelV4Install[]): Hex {
  const context: CaptureContext = new WeakSet();
  const packages = captureInitialPackages(installs, context);
  return encodeFunctionData({
    abi: KERNEL_ABI,
    functionName: "initialize",
    args: [installTuples(packages)],
  });
}

export function encodeKernelV4InstallModules(installs: readonly KernelV4Install[]): Hex {
  const context: CaptureContext = new WeakSet();
  const packages = captureInstalls(installs, context, "Kernel install packages");
  return encodeFunctionData({
    abi: KERNEL_ABI,
    functionName: "installModule",
    args: [installTuples(packages)],
  });
}

export function encodeKernelV4FactoryImplementationRead(): Hex {
  return encodeFunctionData({ abi: FACTORY_ABI, functionName: "UUPS" });
}

export function encodeKernelV4FactoryAddressRead(value: KernelV4AccountInput): Hex {
  const context: CaptureContext = new WeakSet();
  const record = exact(value, ["initialPackages", "accountIndex"], "Kernel account", context);
  const packages = captureInitialPackages(record.initialPackages, context);
  return encodeFunctionData({
    abi: FACTORY_ABI,
    functionName: "getAddress",
    args: [installTuples(packages), uint(record.accountIndex, MAX_UINT256, "Kernel account index")],
  });
}

export function encodeKernelV4FactoryDeploy(value: KernelV4AccountInput): Hex {
  const context: CaptureContext = new WeakSet();
  const record = exact(value, ["initialPackages", "accountIndex"], "Kernel account", context);
  const packages = captureInitialPackages(record.initialPackages, context);
  return encodeFunctionData({
    abi: FACTORY_ABI,
    functionName: "deploy",
    args: [installTuples(packages), uint(record.accountIndex, MAX_UINT256, "Kernel account index")],
  });
}

/**
 * Adapts one viem-style public client into the exact account read capability
 * consumed by bindKernelV4Account, covering all six read request types.
 */
export function createKernelV4Reads(client: KernelV4ReadClient): KernelV4AccountReadCapability {
  return Object.freeze({
    async read(request: KernelV4AccountReadRequest): Promise<unknown> {
      if (request.type === "chain_id") return client.getChainId();
      if (request.type === "code") {
        return (await client.getCode({ address: request.address })) ?? "0x";
      }
      if (request.type === "runtime_code_hash") {
        const code = await client.getCode({ address: request.address });
        return code && code !== "0x" ? keccak256(code) : undefined;
      }
      if (
        request.type === "kernel_factory_implementation" ||
        request.type === "kernel_factory_account"
      ) {
        const result = await client.call({ to: request.factory, data: request.calldata });
        if (!result.data) return undefined;
        return decodeAbiParameters([{ type: "address" }] as const, result.data)[0].toLowerCase();
      }
      const value = await client.getStorageAt({
        address: request.account,
        slot: KERNEL_V4_IMPLEMENTATION_SLOT,
      });
      return value ? `0x${value.slice(-40)}`.toLowerCase() : undefined;
    },
  });
}

/**
 * Resolves one counterfactual or deployed Kernel account after proving that the
 * registered factory is bound to the supported v4 UUPS implementation.
 */
export async function bindKernelV4Account(
  value: KernelV4BindAccountInput,
): Promise<Readonly<KernelV4AccountDescriptor>> {
  const context: CaptureContext = new WeakSet();
  const record = exact(
    value,
    ["chainId", "initialPackages", "accountIndex", "reads"],
    "Kernel account binding",
    context,
  );
  const deployment = kernelV4Deployment(record.chainId);
  const factory = deployment.factory;
  const initialPackages = captureInitialPackages(record.initialPackages, context);
  const accountIndex = uint(record.accountIndex, MAX_UINT256, "Kernel account index").toString(10);
  const readsRecord = exact(record.reads, ["read"], "Kernel account reads", context);
  const read = callable(readsRecord.read, "Kernel account read capability");
  const accountInput = Object.freeze({ initialPackages, accountIndex });
  const factoryAddressCalldata = encodeKernelV4FactoryAddressRead(accountInput);
  const factoryDeployCalldata = encodeKernelV4FactoryDeploy(accountInput);

  const observedChainId = await readEvidence(read, {
    type: "chain_id",
    chainId: deployment.chainId,
  });
  if (observedChainId !== deployment.chainId) {
    return evidenceInvalid("Kernel v4 chain evidence does not match the deployment profile");
  }

  evidenceCodeHash(
    await readEvidence(read, {
      type: "runtime_code_hash",
      chainId: deployment.chainId,
      address: deployment.entryPoint.address,
    }),
    KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
    "Kernel v4 EntryPoint runtime code",
  );
  evidenceCodeHash(
    await readEvidence(read, {
      type: "runtime_code_hash",
      chainId: deployment.chainId,
      address: deployment.implementation,
    }),
    deployment.implementationDeployment.runtimeCodeHash,
    "Kernel v4 implementation runtime code",
  );
  evidenceCodeHash(
    await readEvidence(read, {
      type: "runtime_code_hash",
      chainId: deployment.chainId,
      address: factory,
    }),
    KERNEL_V4_FACTORY_V07_CODE_HASH,
    "Kernel v4 factory runtime code",
  );
  for (const module of new Set(initialPackages.map((install) => install.module))) {
    evidenceCode(
      await readEvidence(read, { type: "code", chainId: deployment.chainId, address: module }),
      "Kernel v4 initial module code",
    );
  }

  const factoryImplementation = evidenceAddress(
    await readEvidence(read, {
      type: "kernel_factory_implementation",
      chainId: deployment.chainId,
      factory,
      calldata: encodeKernelV4FactoryImplementationRead(),
    }),
    "Kernel factory implementation",
  );
  if (factoryImplementation !== deployment.implementation) {
    return evidenceInvalid("Kernel factory implementation does not match the deployment profile");
  }

  const account = evidenceAddress(
    await readEvidence(read, {
      type: "kernel_factory_account",
      chainId: deployment.chainId,
      factory,
      calldata: factoryAddressCalldata,
    }),
    "Kernel account",
  );
  const accountCode = await readEvidence(read, {
    type: "code",
    chainId: deployment.chainId,
    address: account,
  });
  if (typeof accountCode !== "string" || !BYTES.test(accountCode)) {
    return evidenceInvalid("Kernel account code is invalid");
  }
  const state = accountCode === "0x" ? "counterfactual" : "deployed";
  if (state === "deployed") {
    const accountImplementation = evidenceAddress(
      await readEvidence(read, {
        type: "kernel_account_implementation",
        chainId: deployment.chainId,
        account,
      }),
      "Kernel account implementation",
    );
    if (accountImplementation !== deployment.implementation) {
      return evidenceInvalid("Kernel account implementation does not match the deployment profile");
    }
  }

  const descriptor = Object.freeze({
    profile: deployment.profile,
    state,
    chainId: deployment.chainId,
    entryPoint: deployment.entryPoint.address,
    implementation: deployment.implementation,
    factory,
    account,
    accountIndex,
    initialPackages,
    factoryAddressCalldata,
    factoryDeployCalldata,
  });
  BOUND_ACCOUNTS.add(descriptor);
  return descriptor;
}

function captureAccountDescriptor(
  value: unknown,
  context: CaptureContext,
): Readonly<KernelV4AccountDescriptor> {
  if (!value || typeof value !== "object" || !BOUND_ACCOUNTS.has(value)) {
    return fail("Kernel account descriptor has not been proven by this SDK instance");
  }
  const record = exact(
    value,
    [
      "profile",
      "state",
      "chainId",
      "entryPoint",
      "implementation",
      "factory",
      "account",
      "accountIndex",
      "initialPackages",
      "factoryAddressCalldata",
      "factoryDeployCalldata",
    ],
    "Kernel account descriptor",
    context,
  );
  const deployment = kernelV4Deployment(record.chainId);
  if (
    record.profile !== deployment.profile ||
    (record.state !== "counterfactual" && record.state !== "deployed") ||
    record.entryPoint !== deployment.entryPoint.address ||
    record.implementation !== deployment.implementation
  ) {
    return fail("Kernel account descriptor profile is invalid");
  }
  if (address(record.factory, "Kernel factory") !== deployment.factory) {
    return fail("Kernel account descriptor factory is invalid");
  }
  const factory = deployment.factory;
  const account = address(record.account, "Kernel account");
  const accountIndex = uint(record.accountIndex, MAX_UINT256, "Kernel account index").toString(10);
  const initialPackages = captureInitialPackages(record.initialPackages, context);
  const accountInput = Object.freeze({ initialPackages, accountIndex });
  const factoryAddressCalldata = bytes(
    record.factoryAddressCalldata,
    "Kernel factory address calldata",
  );
  const factoryDeployCalldata = bytes(
    record.factoryDeployCalldata,
    "Kernel factory deploy calldata",
  );
  if (
    factoryAddressCalldata !== encodeKernelV4FactoryAddressRead(accountInput) ||
    factoryDeployCalldata !== encodeKernelV4FactoryDeploy(accountInput)
  ) {
    return fail("Kernel account descriptor calldata is contradictory");
  }
  return Object.freeze({
    profile: deployment.profile,
    state: record.state,
    chainId: deployment.chainId,
    entryPoint: deployment.entryPoint.address,
    implementation: deployment.implementation,
    factory,
    account,
    accountIndex,
    initialPackages,
    factoryAddressCalldata,
    factoryDeployCalldata,
  });
}

/**
 * Builds and hashes one immutable EntryPoint 0.7 UserOperation from a proven
 * Kernel v4 account descriptor and the native v4 nonce/execution codecs.
 */
export function prepareKernelV4UserOperation(
  value: KernelV4UserOperationInput,
): PreparedUserOperation {
  const context: CaptureContext = new WeakSet();
  const record = exact(
    value,
    ["kind", "grantId", "account", "nonce", "calls", "gas"],
    "Kernel UserOperation",
    context,
  );
  if (record.kind !== "execution" && record.kind !== "revocation") {
    return fail("Kernel UserOperation kind is invalid");
  }
  if (
    typeof record.grantId !== "string" ||
    record.grantId.length < 1 ||
    record.grantId.length > 256 ||
    record.grantId !== record.grantId.trim()
  ) {
    return fail("Kernel UserOperation grant ID is invalid");
  }
  const account = captureAccountDescriptor(record.account, context);
  const nonceRecord = exact(
    record.nonce,
    ["mode", "validation", "nonceKey", "sequence"],
    "Kernel UserOperation nonce",
    context,
  );
  const nonceKey = captureNonceKey(nonceRecord, context);
  const nonce = encodeKernelV4Nonce({
    key: nonceKey.value,
    sequence: uint(nonceRecord.sequence, MAX_UINT64, "Kernel nonce sequence").toString(10),
  });
  const calls = captureCalls(record.calls, context);
  const execution = encodeKernelV4Execution({ calls });
  const gasRecord = exact(
    record.gas,
    [
      "callGasLimit",
      "verificationGasLimit",
      "preVerificationGas",
      "maxFeePerGas",
      "maxPriorityFeePerGas",
    ],
    "Kernel UserOperation gas",
    context,
  );
  const uint120 = (gas: unknown, label: string) => uint(gas, (1n << 120n) - 1n, label).toString(10);

  return prepareUserOperation({
    kind: record.kind,
    grantId: record.grantId,
    chainId: account.chainId,
    entryPoint: { version: "0.7", address: account.entryPoint },
    userOperation: {
      sender: account.account,
      nonce,
      callData:
        nonceKey.validationType === "0x00"
          ? execution
          : concat([EXECUTE_USER_OP_SELECTOR, execution]),
      callGasLimit: uint120(gasRecord.callGasLimit, "Kernel call gas limit"),
      verificationGasLimit: uint120(
        gasRecord.verificationGasLimit,
        "Kernel verification gas limit",
      ),
      preVerificationGas: uint120(gasRecord.preVerificationGas, "Kernel pre-verification gas"),
      maxFeePerGas: uint120(gasRecord.maxFeePerGas, "Kernel max fee per gas"),
      maxPriorityFeePerGas: uint120(
        gasRecord.maxPriorityFeePerGas,
        "Kernel max priority fee per gas",
      ),
      factory:
        account.state === "counterfactual"
          ? { address: account.factory, data: account.factoryDeployCalldata }
          : null,
      paymaster: null,
    },
  });
}

function validationBytes(
  value: unknown,
  context: CaptureContext,
): Readonly<{ type: "0x00" | "0x01" | "0x02"; identifier: Hex }> {
  const captured = captureRecord(value, "Kernel validation", context, fail);
  if (captured.kind === "root") {
    exactCapturedRecord(captured, ["kind"], "Kernel root validation", fail);
    return Object.freeze({ type: "0x00", identifier: `0x${"00".repeat(20)}` });
  }
  if (captured.kind === "validator") {
    exactCapturedRecord(captured, ["kind", "validator"], "Kernel validator validation", fail);
    return Object.freeze({
      type: "0x01",
      identifier: address(captured.validator, "Kernel validator"),
    });
  }
  if (captured.kind === "permission") {
    exactCapturedRecord(captured, ["kind", "permissionId"], "Kernel permission validation", fail);
    return Object.freeze({
      type: "0x02",
      identifier: pad(bytes4(captured.permissionId, "Kernel permission ID"), {
        size: 20,
        dir: "right",
      }),
    });
  }
  return fail("Kernel validation kind is invalid");
}

const VALIDATION_MODES: Readonly<Record<KernelV4ValidationMode, Hex>> = Object.freeze({
  standard: "0x00",
  enable: "0x08",
  "enable-replayable": "0x0c",
  replayable: "0x40",
  "enable-user-operation-replayable": "0x48",
  "enable-all-replayable": "0x4c",
});

function captureNonceKey(
  record: ExactRecord,
  context: CaptureContext,
): Readonly<{ value: string; validationType: "0x00" | "0x01" | "0x02" }> {
  if (typeof record.mode !== "string" || !Object.hasOwn(VALIDATION_MODES, record.mode)) {
    return fail("Kernel validation mode is invalid");
  }
  const mode = record.mode as KernelV4ValidationMode;
  const validation = validationBytes(record.validation, context);
  if (mode.includes("enable") && validation.type === "0x00") {
    return fail("Kernel enable mode cannot use root validation");
  }
  const key = concat([
    VALIDATION_MODES[mode],
    validation.type,
    validation.identifier,
    toHex(uint(record.nonceKey, MAX_UINT16, "Kernel nonce namespace"), { size: 2 }),
  ]);
  return Object.freeze({ value: hexToBigInt(key).toString(10), validationType: validation.type });
}

/** Returns the canonical decimal uint192 key accepted by EntryPoint 0.7 getNonce. */
export function encodeKernelV4NonceKey(value: KernelV4NonceKeyInput): string {
  const context: CaptureContext = new WeakSet();
  const record = exact(value, ["mode", "validation", "nonceKey"], "Kernel nonce key", context);
  return captureNonceKey(record, context).value;
}

/** Encodes EntryPoint 0.7 getNonce(sender, key) calldata for the canonical nonce key. */
export function encodeKernelV4NonceRead(value: KernelV4NonceReadInput): Hex {
  const context: CaptureContext = new WeakSet();
  const record = exact(value, ["account", "key"], "Kernel nonce read", context);
  return encodeFunctionData({
    abi: ENTRY_POINT_GET_NONCE_ABI,
    functionName: "getNonce",
    args: [
      getAddress(address(record.account, "Kernel nonce read account")),
      uint(record.key, (1n << 192n) - 1n, "Kernel nonce read key"),
    ],
  });
}

/** Combines a canonical uint192 EntryPoint key and uint64 sequence into the full nonce. */
export function encodeKernelV4Nonce(value: KernelV4NonceInput): string {
  const context: CaptureContext = new WeakSet();
  const record = exact(value, ["key", "sequence"], "Kernel nonce", context);
  const key = uint(record.key, (1n << 192n) - 1n, "Kernel nonce key");
  const sequence = uint(record.sequence, MAX_UINT64, "Kernel nonce sequence");
  return ((key << 64n) | sequence).toString(10);
}

/** ABI-encodes the policy signatures followed by the signer signature. */
export function encodeKernelV4PermissionSignature(value: readonly `0x${string}`[]): Hex {
  const context: CaptureContext = new WeakSet();
  const signatures = captureDenseArray(value, "Kernel permission signatures", context, fail);
  if (signatures.length < 1 || signatures.length > 256) {
    return fail("Kernel permission signature count is invalid");
  }
  return encodeAbiParameters(
    [{ name: "signatures", type: "bytes[]" }],
    [signatures.map((signature) => bytes(signature, "Kernel permission signature"))],
  );
}

/** ABI-encodes Kernel v4's EnableModeSignature struct. */
export function encodeKernelV4EnableSignature(value: KernelV4EnableSignatureInput): Hex {
  const context: CaptureContext = new WeakSet();
  const record = exact(
    value,
    ["nonce", "packages", "enableSignature", "userOperationSignature"],
    "Kernel enable signature",
    context,
  );
  const packages = captureInstalls(record.packages, context, "Kernel enable packages");
  return encodeAbiParameters(
    [
      { name: "nonce", type: "uint256" },
      INSTALL_ARRAY_PARAMETER,
      { name: "enableSignature", type: "bytes" },
      { name: "userOpSignature", type: "bytes" },
    ],
    [
      uint(record.nonce, MAX_UINT256, "Kernel install nonce"),
      installTuples(packages),
      bytes(record.enableSignature, "Kernel enable signature"),
      bytes(record.userOperationSignature, "Kernel UserOperation signature"),
    ],
  );
}

function captureCalls(value: unknown, context: CaptureContext): readonly Readonly<KernelV4Call>[] {
  const values = captureDenseArray(value, "Kernel calls", context, fail);
  if (values.length < 1 || values.length > 256) return fail("Kernel call count is invalid");
  return Object.freeze(
    values.map((entry, index) => {
      const record = exact(entry, ["target", "value", "data"], `Kernel call ${index}`, context);
      return Object.freeze({
        target: address(record.target, "Kernel call target"),
        value: uint(record.value, MAX_UINT256, "Kernel call value").toString(10),
        data: bytes(record.data, "Kernel call data"),
      });
    }),
  );
}

/** Encodes one or more calls through Kernel v4's ERC-7579 execute entrypoint. */
export function encodeKernelV4Execution(value: KernelV4ExecutionInput): Hex {
  const context: CaptureContext = new WeakSet();
  const record = exact(value, ["calls"], "Kernel execution", context);
  const calls = captureCalls(record.calls, context);
  const single = calls.length === 1 ? calls[0] : undefined;
  const mode = single ? (`0x${"00".repeat(32)}` as const) : (`0x0100${"00".repeat(30)}` as const);
  const executionData = single
    ? concat([single.target, toHex(BigInt(single.value), { size: 32 }), single.data])
    : encodeAbiParameters(
        [
          {
            name: "calls",
            type: "tuple[]",
            components: [
              { name: "to", type: "address" },
              { name: "value", type: "uint256" },
              { name: "data", type: "bytes" },
            ],
          },
        ],
        [calls.map((call) => ({ to: call.target, value: BigInt(call.value), data: call.data }))],
      );
  return encodeFunctionData({
    abi: KERNEL_ABI,
    functionName: "execute",
    args: [mode, executionData],
  });
}
