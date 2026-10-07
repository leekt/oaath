export {
  encodeKernelInstallNonceInvalidationCall,
  encodeKernelPermissionUninstallCalls,
} from "@oaath/protocol";

import {
  type CanonicalEip712TypedData,
  type CaptureContext,
  captureDenseArray,
  captureRecord,
  createKernelReplayableInstallTypedData,
  type ExactRecord,
  exactCapturedRecord,
  KERNEL_INSTALL_COMPONENTS,
  type KernelInstall,
  OaathProtocolError,
  type KernelModuleType as ProtocolKernelV4ModuleType,
  parseKernelInstallPackages,
} from "@oaath/protocol";
import type { Hex } from "cetane";
import {
  concatHex,
  decodeAbiParameters,
  decodeFunctionData,
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  hashTypedData,
  keccak256,
  padHex,
  toHex,
} from "cetane/utils";
import {
  KERNEL_V4_ENTRY_POINT_V09,
  KERNEL_V4_FACTORY_V09,
  KERNEL_V4_FACTORY_V09_CODE_HASH,
  KERNEL_V4_UUPS_IMPLEMENTATION_V09,
} from "./kernel/deployment/v4-artifacts.js";

export {
  KERNEL_V4_ENTRY_POINT_V09,
  KERNEL_V4_FACTORY_V09,
  KERNEL_V4_FACTORY_V09_CODE_HASH,
  KERNEL_V4_UUPS_IMPLEMENTATION_V09,
} from "./kernel/deployment/v4-artifacts.js";

import { type KernelRuntimeErrorCode, OaathKernelRuntimeError } from "./kernel/types.js";
import {
  type PreparedPaymaster,
  type PreparedUserOperation,
  prepareUserOperation,
} from "./prepared-user-operation.js";

const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const BYTES4 = /^0x[0-9a-f]{8}$/u;
const BYTES32 = /^0x[0-9a-f]{64}$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const MAX_UINT16 = (1n << 16n) - 1n;
const MAX_UINT48 = (1n << 48n) - 1n;
const MAX_UINT64 = (1n << 64n) - 1n;
const MAX_UINT256 = (1n << 256n) - 1n;
const BOUND_ACCOUNTS = new WeakSet<object>();
const VALIDITY_TIME_RANGE_MODE_SELECTOR = "0x1ba8f415" as const;

export const KERNEL_V4_CREATE2_DEPLOYER = "0x4e59b44847b379578588920ca78fbf26c0b4956c" as const;
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
/**
 * Kernel v4 executeUserOp(PackedUserOperation,bytes32) selector. Every non-root
 * validation prefixes its callData with it so that Kernel enforces the
 * validation's own selector allow-list.
 */
export const KERNEL_V4_EXECUTE_USER_OP_SELECTOR = "0x8dd7712f" as const;

export type KernelV4ModuleType = ProtocolKernelV4ModuleType;
export type KernelV4ValidationMode =
  | "standard"
  | "enable"
  | "enable-replayable"
  | "replayable"
  | "enable-user-operation-replayable"
  | "enable-all-replayable";

export interface KernelV4Deployment {
  readonly profile: "kernel-v4-uups-entrypoint-v0.9";
  readonly kernelVersion: "0.4.0";
  readonly accountType: "uups";
  readonly chainId: number;
  readonly entryPoint: Readonly<{
    version: "0.9";
    address: typeof KERNEL_V4_ENTRY_POINT_V09;
  }>;
  readonly implementation: typeof KERNEL_V4_UUPS_IMPLEMENTATION_V09;
  readonly factory: typeof KERNEL_V4_FACTORY_V09;
  readonly factoryRuntimeCodeHash: typeof KERNEL_V4_FACTORY_V09_CODE_HASH;
  /** The canonical CREATE2 deployer every address above is derived through. */
  readonly create2Deployer: typeof KERNEL_V4_CREATE2_DEPLOYER;
}

export type { KernelInstall };

export interface KernelCall {
  readonly target: `0x${string}`;
  readonly value: string;
  readonly data: `0x${string}`;
}

export interface KernelUserOperationGas {
  readonly callGasLimit: string;
  readonly verificationGasLimit: string;
  readonly preVerificationGas: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
}

export type KernelValidation =
  | Readonly<{ kind: "root" }>
  | Readonly<{ kind: "validator"; validator: `0x${string}` }>
  | Readonly<{ kind: "permission"; permissionId: `0x${string}` }>;

export interface KernelV4ModuleDataInput {
  readonly selectors: readonly `0x${string}`[];
}

export interface KernelV4SignerDataInput extends KernelV4ModuleDataInput {
  readonly permissionId: `0x${string}`;
}

export interface KernelV4AccountInput {
  readonly initialPackages: readonly KernelInstall[];
  readonly accountIndex: string;
}

export interface KernelV4NonceKeyInput {
  readonly mode: KernelV4ValidationMode;
  readonly validation: KernelValidation;
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
  readonly account: KernelV4AccountDescriptor | KernelV4ExistingAccountDescriptor;
  readonly nonce: KernelV4UserOperationNonceInput;
  readonly calls: readonly KernelCall[];
  readonly gas: KernelUserOperationGas;
  /** Optional request-time attenuation enforced by the installed OAAth validity policy. */
  readonly validityTimeRange?: Readonly<KernelValidityTimeRange>;
  /**
   * Optional EntryPoint 0.9 paymaster sponsorship. Absent or null prepares a
   * self-funded operation. The fields are hashed into the operation identity,
   * so sponsorship can never be attached or swapped after preparation.
   */
  readonly paymaster?: Readonly<PreparedPaymaster> | null;
}

export interface KernelV4EnableSignatureInput {
  readonly nonce: string;
  readonly packages: readonly KernelInstall[];
  readonly enableSignature: `0x${string}`;
  readonly userOperationSignature: `0x${string}`;
}

export interface KernelV4ReplayableInstallDigestInput {
  /** The Kernel account whose root validation authorizes the install. */
  readonly account: `0x${string}`;
  /** Kernel's own install nonce, `key << 64 | sequence`, as a decimal uint256. */
  readonly nonce: string;
  readonly packages: readonly KernelInstall[];
}

export interface KernelV4ExecutionInput {
  readonly calls: readonly KernelCall[];
  /** Optional exact ERC-7579 mode range; omission preserves the existing zero mode. */
  readonly validityTimeRange?: Readonly<KernelValidityTimeRange>;
}

export interface KernelValidityTimeRange {
  /** Inclusive lower endpoint, as canonical decimal uint48 seconds. */
  readonly validAfter: string;
  /** Inclusive nonzero upper endpoint, strictly greater than validAfter. */
  readonly validUntil: string;
}

export type KernelV4AccountReadRequest =
  | Readonly<{ type: "chain_id"; chainId: number }>
  | Readonly<{
      type: "code";
      chainId: number;
      address: `0x${string}`;
    }>
  | Readonly<{
      type: "runtime_code_hash";
      chainId: number;
      address: `0x${string}`;
    }>
  | Readonly<{
      type: "kernel_factory_implementation";
      chainId: number;
      factory: `0x${string}`;
      calldata: `0x${string}`;
    }>
  | Readonly<{
      type: "kernel_factory_account";
      chainId: number;
      factory: `0x${string}`;
      calldata: `0x${string}`;
    }>
  | Readonly<{
      type: "kernel_account_implementation" | "kernel_v4_account_root";
      chainId: number;
      account: `0x${string}`;
    }>
  | Readonly<{
      /** The raw P-256 root validator's stored public key for one account. */
      type: "kernel_p256_owner";
      chainId: number;
      validator: `0x${string}`;
      account: `0x${string}`;
    }>
  | Readonly<{
      /** EntryPoint 0.9 `getNonce(account, key)`: the key's full decimal uint256 nonce. */
      type: "entry_point_lane_nonce";
      chainId: number;
      entryPoint: `0x${string}`;
      account: `0x${string}`;
      /** Canonical decimal uint192 key, as `encodeKernelNonceKey` returns. */
      key: string;
    }>;

export interface KernelV4AccountReadCapability {
  readonly read: (request: KernelV4AccountReadRequest) => Promise<unknown>;
}

export interface KernelV4BindAccountInput extends KernelV4AccountInput {
  readonly chainId: number;
  readonly reads: KernelV4AccountReadCapability;
}

/**
 * Minimal client surface consumed by createKernelV4Reads.
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
    /** Present only when a read names its block. */
    blockTag?: "latest" | "finalized";
  }) => Promise<{ data?: `0x${string}` | undefined }>;
}

export interface KernelV4AccountDescriptor {
  readonly profile: "kernel-v4-uups-entrypoint-v0.9";
  readonly state: "counterfactual" | "deployed";
  readonly chainId: number;
  readonly entryPoint: typeof KERNEL_V4_ENTRY_POINT_V09;
  readonly implementation: typeof KERNEL_V4_UUPS_IMPLEMENTATION_V09;
  readonly factory: typeof KERNEL_V4_FACTORY_V09;
  readonly account: `0x${string}`;
  readonly accountIndex: string;
  readonly initialPackages: readonly Readonly<KernelInstall>[];
  readonly factoryAddressCalldata: `0x${string}`;
  readonly factoryDeployCalldata: `0x${string}`;
}

/**
 * A deployed Kernel v4 account bound by its address alone. It carries no
 * factory derivation, so it can never prepare a deployment; the root validation
 * it records is the account's current root, read onchain.
 */
export interface KernelV4ExistingAccountDescriptor {
  readonly profile: "kernel-v4-uups-entrypoint-v0.9";
  readonly state: "deployed";
  readonly chainId: number;
  readonly entryPoint: typeof KERNEL_V4_ENTRY_POINT_V09;
  readonly implementation: typeof KERNEL_V4_UUPS_IMPLEMENTATION_V09;
  readonly account: `0x${string}`;
  /** Current root ValidationId: `0x01 || validator` or `0x02 || permissionId || 0`. */
  readonly rootValidator: `0x${string}`;
}

const ENTRY_POINT = Object.freeze({
  version: "0.9" as const,
  address: KERNEL_V4_ENTRY_POINT_V09,
});

const INSTALL_ARRAY_PARAMETER = {
  name: "packages",
  type: "tuple[]",
  components: KERNEL_INSTALL_COMPONENTS,
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

/** The pinned raw P-256 validator's public-key getter (leekt/P256Validator). */
const P256_VALIDATOR_ABI = [
  {
    type: "function",
    name: "publicKey",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [
      { name: "x", type: "uint256" },
      { name: "y", type: "uint256" },
    ],
  },
] as const;

const KERNEL_ABI = [
  {
    type: "function",
    name: "nonce",
    stateMutability: "view",
    inputs: [{ name: "key", type: "uint192" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "root",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes21" }],
  },
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

function kernelError(code: KernelRuntimeErrorCode, message: string): never {
  throw new OaathKernelRuntimeError(code, message);
}

function fail(message: string): never {
  return kernelError("kernel_runtime_input_invalid", message);
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
  return kernelError("kernel_runtime_evidence_invalid", message);
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
    return kernelError(
      "kernel_runtime_read_unavailable",
      "Kernel v4 account evidence is unavailable",
    );
  }
}

function captureInstalls(
  value: unknown,
  _context: CaptureContext,
  label: string,
): readonly Readonly<KernelInstall>[] {
  try {
    return parseKernelInstallPackages(value);
  } catch (error) {
    if (error instanceof OaathProtocolError && error.code === "signing_request_invalid") {
      return fail(`${label} is invalid`);
    }
    throw error;
  }
}

function captureInitialPackages(
  value: unknown,
  context: CaptureContext,
): readonly Readonly<KernelInstall>[] {
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

function installTuples(installs: readonly Readonly<KernelInstall>[]): readonly Readonly<{
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

/**
 * Captures ERC-7579 install packages exactly, including Kernel's rule that every
 * policy package is followed by the signer package of the same permission ID.
 * Not part of the public surface: it exists so a caller-injected package list
 * enters this SDK's owned representation once, wherever the boundary is.
 */
export function captureKernelV4Installs(value: unknown): readonly Readonly<KernelInstall>[] {
  return captureInstalls(value, new WeakSet(), "Kernel install packages");
}

/**
 * One owned frozen profile per chain, so `exactKernelDeployment`'s identity
 * gate keeps refusing every foreign object. Growth is bounded by the distinct
 * chain identifiers this process resolves, which its own configuration owns.
 */
const OPEN_DEPLOYMENTS = new Map<number, Readonly<KernelV4Deployment>>();

/**
 * Resolves the Kernel v4 deployment profile for one chain. Every EVM chain
 * resolves: the profile's addresses are CREATE2 canonical and therefore
 * chain-independent, and `bindKernelV4Account` proves the actual on-chain
 * capability from read evidence before any account depends on it. Only a
 * malformed chain identifier is unsupported; no chain is blocked here.
 */
export function kernelV4Deployment(chainId: unknown): Readonly<KernelV4Deployment> {
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
    return kernelError("kernel_runtime_chain_unsupported", "Kernel v4 chain is unsupported");
  }
  const open = OPEN_DEPLOYMENTS.get(chainId);
  if (open) return open;
  const created: Readonly<KernelV4Deployment> = Object.freeze({
    profile: "kernel-v4-uups-entrypoint-v0.9",
    kernelVersion: "0.4.0",
    accountType: "uups",
    chainId,
    entryPoint: ENTRY_POINT,
    implementation: KERNEL_V4_UUPS_IMPLEMENTATION_V09,
    factory: KERNEL_V4_FACTORY_V09,
    factoryRuntimeCodeHash: KERNEL_V4_FACTORY_V09_CODE_HASH,
    create2Deployer: KERNEL_V4_CREATE2_DEPLOYER,
  });
  OPEN_DEPLOYMENTS.set(chainId, created);
  return created;
}

/** Encodes Kernel v4 validator internalData: packed allowed selectors. */
export function encodeKernelV4ValidatorData(value: KernelV4ModuleDataInput): Hex {
  const context: CaptureContext = new WeakSet();
  const record = exact(value, ["selectors"], "Kernel validator data", context);
  return concatHex(["0x", ...captureSelectors(record.selectors, context)]);
}

/** Encodes Kernel v4 policy internalData. */
export function encodeKernelV4PolicyData(permissionId: `0x${string}`): Hex {
  return bytes4(permissionId, "Kernel permission ID");
}

/** Encodes Kernel v4 signer internalData: permission ID followed by packed allowed selectors. */
export function encodeKernelV4SignerData(value: KernelV4SignerDataInput): Hex {
  const context: CaptureContext = new WeakSet();
  const record = exact(value, ["permissionId", "selectors"], "Kernel signer data", context);
  return concatHex([
    bytes4(record.permissionId, "Kernel permission ID"),
    ...captureSelectors(record.selectors, context),
  ]);
}

export function encodeKernelV4Initialize(installs: readonly KernelInstall[]): Hex {
  const context: CaptureContext = new WeakSet();
  const packages = captureInitialPackages(installs, context);
  return encodeFunctionData({
    abi: KERNEL_ABI,
    functionName: "initialize",
    args: [installTuples(packages)],
  });
}

export function encodeKernelV4InstallModules(installs: readonly KernelInstall[]): Hex {
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
 * Adapts one public client into the exact account read capability
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
      if (request.type === "entry_point_lane_nonce") {
        const result = await client.call({
          to: request.entryPoint,
          data: encodeKernelV4NonceRead({ account: request.account, key: request.key }),
        });
        if (!result.data) return undefined;
        const parameters = [{ type: "uint256" }] as const;
        const [nonce] = decodeAbiParameters(parameters, result.data);
        // Noncanonical return data is contradictory evidence, not a nonce.
        return encodeAbiParameters(parameters, [nonce]) === result.data.toLowerCase()
          ? nonce.toString(10)
          : undefined;
      }
      if (request.type === "kernel_p256_owner") {
        const result = await client.call({
          to: request.validator,
          data: encodeFunctionData({
            abi: P256_VALIDATOR_ABI,
            functionName: "publicKey",
            args: [request.account],
          }),
        });
        if (!result.data) return undefined;
        const parameters = [{ type: "uint256" }, { type: "uint256" }] as const;
        const [x, y] = decodeAbiParameters(parameters, result.data);
        // The key profile's public material is this exact encoding; noncanonical
        // return data is contradictory evidence, not a key.
        const encoded = encodeAbiParameters(parameters, [x, y]);
        return encoded === result.data.toLowerCase() ? encoded : undefined;
      }
      if (request.type === "kernel_v4_account_root") {
        const result = await client.call({
          to: request.account,
          data: encodeFunctionData({ abi: KERNEL_ABI, functionName: "root" }),
        });
        if (!result.data) return undefined;
        const parameters = [{ type: "bytes21" }] as const;
        const [root] = decodeAbiParameters(parameters, result.data);
        // Noncanonical return data is contradictory evidence, not a root.
        return encodeAbiParameters(parameters, [root]).toLowerCase() === result.data.toLowerCase()
          ? root.toLowerCase()
          : undefined;
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
 * Chain, EntryPoint, implementation and factory code evidence for one v4
 * deployment profile, shared by counterfactual and existing-account binding.
 */
async function proveDeploymentCode(
  read: KernelV4AccountReadCapability["read"],
  deployment: Readonly<KernelV4Deployment>,
): Promise<void> {
  const factory = deployment.factory;
  const observedChainId = await readEvidence(read, {
    type: "chain_id",
    chainId: deployment.chainId,
  });
  if (observedChainId !== deployment.chainId) {
    return evidenceInvalid("Kernel v4 chain evidence does not match the deployment profile");
  }

  // EntryPoint caches the EIP-712 chain domain in immutable runtime bytes.
  // Its canonical CREATE2 address commits to the reviewed creation code.
  evidenceCode(
    await readEvidence(read, {
      type: "code",
      chainId: deployment.chainId,
      address: deployment.entryPoint.address,
    }),
    "Kernel v4 EntryPoint code",
  );
  // Kernel caches chain ID in its immutables, so its runtime hash varies by
  // chain. The canonical CREATE2 address commits to the reviewed init code;
  // require code here and prove the factory's implementation binding below.
  evidenceCode(
    await readEvidence(read, {
      type: "code",
      chainId: deployment.chainId,
      address: deployment.implementation,
    }),
    "Kernel v4 implementation code",
  );
  evidenceCodeHash(
    await readEvidence(read, {
      type: "runtime_code_hash",
      chainId: deployment.chainId,
      address: factory,
    }),
    KERNEL_V4_FACTORY_V09_CODE_HASH,
    "Kernel v4 factory runtime code",
  );
}

/** The hash-pinned factory must report the profile's UUPS implementation. */
async function proveFactoryImplementation(
  read: KernelV4AccountReadCapability["read"],
  deployment: Readonly<KernelV4Deployment>,
): Promise<void> {
  const factory = deployment.factory;
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
}

const ROOT_VALIDATION = /^0x(?:01[0-9a-f]{40}|02[0-9a-f]{8}0{32})$/u;
const EXISTING_ACCOUNTS = new WeakSet<object>();

/**
 * Binds a deployed Kernel v4 account at its existing address. Nothing is
 * derived from a factory: the account must already carry the profile's UUPS
 * implementation, and its current root validation is read, never assumed.
 */
export async function bindKernelV4ExistingAccount(value: {
  readonly chainId: number;
  readonly address: `0x${string}`;
  readonly reads: KernelV4AccountReadCapability;
}): Promise<Readonly<KernelV4ExistingAccountDescriptor>> {
  const context: CaptureContext = new WeakSet();
  const record = exact(value, ["chainId", "address", "reads"], "Kernel existing account", context);
  const deployment = kernelV4Deployment(record.chainId);
  const account = address(record.address, "Kernel existing account address");
  const readsRecord = exact(record.reads, ["read"], "Kernel account reads", context);
  const read = callable(readsRecord.read, "Kernel account read capability");
  await proveDeploymentCode(read, deployment);
  await proveFactoryImplementation(read, deployment);
  evidenceCode(
    await readEvidence(read, { type: "code", chainId: deployment.chainId, address: account }),
    "Kernel existing account code",
  );
  const implementation = evidenceAddress(
    await readEvidence(read, {
      type: "kernel_account_implementation",
      chainId: deployment.chainId,
      account,
    }),
    "Kernel account implementation",
  );
  if (implementation !== deployment.implementation) {
    return evidenceInvalid("Kernel account implementation does not match the deployment profile");
  }
  const root = await readEvidence(read, {
    type: "kernel_v4_account_root",
    chainId: deployment.chainId,
    account,
  });
  if (typeof root !== "string" || !ROOT_VALIDATION.test(root) || /^0x(?:01|02)0{40}$/u.test(root)) {
    return evidenceInvalid("Kernel v4 root validation is invalid or unsupported");
  }
  if (root.startsWith("0x01")) {
    evidenceCode(
      await readEvidence(read, {
        type: "code",
        chainId: deployment.chainId,
        address: `0x${root.slice(4)}`,
      }),
      "Kernel v4 root validator code",
    );
  }
  const descriptor: Readonly<KernelV4ExistingAccountDescriptor> = Object.freeze({
    profile: deployment.profile,
    state: "deployed",
    chainId: deployment.chainId,
    entryPoint: deployment.entryPoint.address,
    implementation: deployment.implementation,
    account,
    rootValidator: root as `0x${string}`,
  });
  EXISTING_ACCOUNTS.add(descriptor);
  return descriptor;
}

/** True for a descriptor this SDK instance bound by address. */
export function isKernelV4ExistingAccount(
  value: unknown,
): value is Readonly<KernelV4ExistingAccountDescriptor> {
  return !!value && typeof value === "object" && EXISTING_ACCOUNTS.has(value);
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

  await proveDeploymentCode(read, deployment);
  for (const module of new Set(initialPackages.map((install) => install.module))) {
    evidenceCode(
      await readEvidence(read, { type: "code", chainId: deployment.chainId, address: module }),
      "Kernel v4 initial module code",
    );
  }

  await proveFactoryImplementation(read, deployment);

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
): Readonly<KernelV4AccountDescriptor | KernelV4ExistingAccountDescriptor> {
  // An address-bound descriptor is this module's own frozen object; it has no
  // factory derivation to cross-check.
  if (isKernelV4ExistingAccount(value)) return value;
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
 * Builds and hashes one immutable EntryPoint 0.9 UserOperation from a proven
 * Kernel v4 account descriptor and the native v4 nonce/execution codecs.
 */
export function prepareKernelV4UserOperation(
  value: KernelV4UserOperationInput,
): PreparedUserOperation {
  const context: CaptureContext = new WeakSet();
  const captured = captureRecord(value, "Kernel UserOperation", context, fail);
  // Validity attenuation and paymaster sponsorship are the two optional axes;
  // every present field is still captured exactly at this boundary.
  const keys = ["kind", "grantId", "account", "nonce", "calls", "gas"];
  if (Object.hasOwn(captured, "validityTimeRange")) keys.push("validityTimeRange");
  if (Object.hasOwn(captured, "paymaster")) keys.push("paymaster");
  const record = exactCapturedRecord(captured, keys, "Kernel UserOperation", fail);
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
  const execution = encodeKernelV4Execution(
    Object.hasOwn(record, "validityTimeRange")
      ? {
          calls,
          validityTimeRange: record.validityTimeRange as Readonly<KernelValidityTimeRange>,
        }
      : { calls },
  );
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
    entryPoint: { version: "0.9", address: account.entryPoint },
    userOperation: {
      sender: account.account,
      nonce,
      // Root validation is exempt from Kernel's selector allow-list, and a
      // permission installed with no hook allow-lists execute(bytes32,bytes) and
      // takes Kernel's fast path, so both carry plain execute calldata; the
      // policy modules of a permission decode exactly that. Only a validator
      // validation routes through executeUserOp, where Kernel checks the inner
      // selector against the same allow-list.
      callData:
        nonceKey.validationType === "0x01"
          ? concatHex([KERNEL_V4_EXECUTE_USER_OP_SELECTOR, execution])
          : execution,
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
        account.state === "counterfactual" && !isKernelV4ExistingAccount(account)
          ? { address: account.factory, data: account.factoryDeployCalldata }
          : null,
      paymaster: capturePaymaster(record.paymaster, context),
    },
  });
}

/**
 * Captures the optional paymaster input exactly. The shapes are the ones
 * parsePreparedUserOperation validates and Cetane's getSigningHash hashes,
 * so a sponsored operation's identity covers its sponsorship byte for byte.
 */
function capturePaymaster(
  value: unknown,
  context: CaptureContext,
): Readonly<PreparedPaymaster> | null {
  if (value === undefined || value === null) return null;
  const record = exact(
    value,
    ["address", "verificationGasLimit", "postOpGasLimit", "data"],
    "Kernel UserOperation paymaster",
    context,
  );
  const uint120 = (gas: unknown, label: string) => uint(gas, (1n << 120n) - 1n, label).toString(10);
  return Object.freeze({
    address: address(record.address, "Kernel paymaster address"),
    verificationGasLimit: uint120(
      record.verificationGasLimit,
      "Kernel paymaster verification gas limit",
    ),
    postOpGasLimit: uint120(record.postOpGasLimit, "Kernel paymaster post-operation gas limit"),
    data: bytes(record.data, "Kernel paymaster data"),
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
      identifier: padHex(bytes4(captured.permissionId, "Kernel permission ID"), {
        size: 20,
        dir: "right",
      }),
    });
  }
  return fail("Kernel validation kind is invalid");
}

/**
 * Kernel v4's validation mode byte, pinned against src/types/Types.sol: bit
 * `0x08` enables inline installs, bit `0x04` makes the enable signature
 * chain-agnostic, bit `0x40` makes the UserOperation signature chain-agnostic.
 *
 * Two of these six are reachable through a composed runtime, and both are proven
 * on-chain by the local Anvil suites:
 *
 * - `standard` — every operation whose validation is already installed.
 * - `enable-replayable` — the first operation of an all-chain materialization,
 *   whose enable signature is the one chain-agnostic owner approval. The
 *   two-chain proof replays a single owner signature onto a second chain.
 *
 * The other four stay unreachable by construction, because each would weaken an
 * invariant this SDK owns rather than add a capability:
 * - `enable` binds the owner approval to one chain, which is exactly the
 *   per-chain re-approval an all-chain grant exists to avoid.
 * - `replayable`, `enable-user-operation-replayable` and `enable-all-replayable`
 *   all set bit `0x40`, which makes Kernel validate the *operation* against a
 *   chain-agnostic hash. A prepared operation identity must stay bound to one
 *   chain: a replayable operation signature could be included on every supported
 *   chain from one submission, and no `(grantId, chainId)` lane could own it.
 */
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
  const key = concatHex([
    VALIDATION_MODES[mode],
    validation.type,
    validation.identifier,
    toHex(uint(record.nonceKey, MAX_UINT16, "Kernel nonce namespace"), { size: 2 }),
  ]);
  return Object.freeze({ value: BigInt(key).toString(10), validationType: validation.type });
}

/** Returns the canonical decimal uint192 key accepted by EntryPoint 0.9 getNonce. */
export function encodeKernelV4NonceKey(value: KernelV4NonceKeyInput): string {
  const context: CaptureContext = new WeakSet();
  const record = exact(value, ["mode", "validation", "nonceKey"], "Kernel nonce key", context);
  return captureNonceKey(record, context).value;
}

/** Internal: checks the mode of an already validated prepared-operation nonce. */
export function isKernelV4EnableNonce(nonce: string): boolean {
  return BigInt(nonce) >> 248n === BigInt(VALIDATION_MODES["enable-replayable"]);
}

/** Encodes EntryPoint 0.9 getNonce(sender, key) calldata for the canonical nonce key. */
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

/**
 * Encodes the Kernel account's nonce(uint192) read. Call the account, not
 * EntryPoint; the uint256 result includes the key and effective sequence,
 * respecting Kernel's global minimum. A missing account/result is not zero.
 */
export function encodeKernelV4InstallNonceRead(value: { readonly key: string }): Hex {
  const record = exact(value, ["key"], "Kernel install nonce read", new WeakSet());
  return encodeFunctionData({
    abi: KERNEL_ABI,
    functionName: "nonce",
    args: [uint(record.key, (1n << 192n) - 1n, "Kernel install nonce key")],
  });
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

/**
 * The canonical EIP-712 value one owner signature must cover to authorize a
 * replayable enable-mode install, computed the way Kernel v4 computes it.
 *
 * Derivation, against the vendored Kernel v4 source:
 * `Kernel._processUserOp` reads the enable-signature-replayable flag from the
 * validation mode byte (`isEnableReplayable`, bit `0x04`, src/types/Types.sol)
 * and hands it to `ModuleManager._verifyInstallSignatureRaw`, which selects
 * `_hashTypedDataSansChainId` over `_hashTypedData` for exactly that flag and
 * hashes `keccak256(INSTALL_PACKAGES_STRUCT_HASH ‖ nonce ‖ _installHash(packages))`
 * under it, then verifies the result against the account's *root* validation with
 * the account itself as the requester.
 *
 * Solady's `_hashTypedDataSansChainId` builds its domain separator from
 * `EIP712Domain(string name,string version,address verifyingContract)` — the
 * chain ID is absent, and `verifyingContract` is `address(this)`, the account.
 * Kernel's `_domainNameAndVersion` returns name "Kernel", version "0.4.0". The
 * digest therefore binds the account, the install nonce and the exact packages,
 * and nothing else: it is identical on every chain.
 *
 * That is what makes one owner approval an all-chain approval. Every module and
 * account address in this SDK is CREATE2-derived and chain-independent, so the
 * same initial packages yield the same account on every supported chain, so the
 * same digest — and one signature over it — authorizes the same install on a
 * chain that did not exist when the owner approved.
 *
 * The replayable flag covers the *enable* signature only. The UserOperation
 * signature beside it stays chain-bound: `_processUserOp` only replaces the
 * operation hash with a chain-agnostic one under the separate `isReplayable`
 * flag (bit `0x40`), which this SDK never sets.
 */
export function kernelV4ReplayableInstallTypedData(
  value: KernelV4ReplayableInstallDigestInput,
): Readonly<CanonicalEip712TypedData> {
  const context: CaptureContext = new WeakSet();
  const record = exact(
    value,
    ["account", "nonce", "packages"],
    "Kernel replayable install",
    context,
  );
  const account = address(record.account, "Kernel replayable install account");
  const nonce = uint(record.nonce, MAX_UINT256, "Kernel install nonce").toString(10);
  const packages = captureInstalls(record.packages, context, "Kernel enable packages");
  try {
    return createKernelReplayableInstallTypedData({ account, nonce, packages });
  } catch (error) {
    if (error instanceof OaathProtocolError && error.code === "signing_request_invalid") {
      return fail("Kernel replayable install typed data is invalid");
    }
    throw error;
  }
}

/** The digest of the canonical replayable install typed data. */
export function kernelV4ReplayableInstallDigest(value: KernelV4ReplayableInstallDigestInput): Hex {
  const typedData = kernelV4ReplayableInstallTypedData(value);
  return hashTypedData(typedData);
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

function captureCalls(value: unknown, context: CaptureContext): readonly Readonly<KernelCall>[] {
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

function captureValidityTimeRange(
  value: unknown,
  context: CaptureContext,
): Readonly<KernelValidityTimeRange> {
  const record = exact(value, ["validAfter", "validUntil"], "Kernel validity time range", context);
  const validAfter = uint(record.validAfter, MAX_UINT48, "Kernel validity range validAfter");
  const validUntil = uint(record.validUntil, MAX_UINT48, "Kernel validity range validUntil");
  if (validUntil === 0n || validAfter >= validUntil) {
    return fail("Kernel validity time range is invalid");
  }
  return Object.freeze({
    validAfter: validAfter.toString(10),
    validUntil: validUntil.toString(10),
  });
}

/** Encodes one or more calls through Kernel v4's ERC-7579 execute entrypoint. */
export function encodeKernelV4Execution(value: KernelV4ExecutionInput): Hex {
  const context: CaptureContext = new WeakSet();
  const captured = captureRecord(value, "Kernel execution", context, fail);
  const record = exactCapturedRecord(
    captured,
    Object.hasOwn(captured, "validityTimeRange") ? ["calls", "validityTimeRange"] : ["calls"],
    "Kernel execution",
    fail,
  );
  const calls = captureCalls(record.calls, context);
  const single = calls.length === 1 ? calls[0] : undefined;
  const validityTimeRange = Object.hasOwn(record, "validityTimeRange")
    ? captureValidityTimeRange(record.validityTimeRange, context)
    : null;
  const mode = validityTimeRange
    ? concatHex([
        single ? "0x00" : "0x01",
        `0x${"00".repeat(5)}`,
        VALIDITY_TIME_RANGE_MODE_SELECTOR,
        toHex(BigInt(validityTimeRange.validAfter), { size: 6 }),
        toHex(BigInt(validityTimeRange.validUntil), { size: 6 }),
        `0x${"00".repeat(10)}`,
      ])
    : single
      ? (`0x${"00".repeat(32)}` as const)
      : (`0x0100${"00".repeat(30)}` as const);
  const executionData = single
    ? concatHex([single.target, toHex(BigInt(single.value), { size: 32 }), single.data])
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

/** Decodes only the exact execute forms this runtime produces. Internal evidence boundary. */
export function decodeKernelV4Execution(value: unknown): readonly Readonly<KernelCall>[] {
  const data = bytes(value, "Kernel execution calldata");
  const decoded = decodeFunctionData({ abi: KERNEL_ABI, data });
  if (decoded.functionName !== "execute") return fail("unsupported Kernel execution");
  const [mode, executionData] = decoded.args;
  const callType = mode.slice(2, 4);
  let calls: readonly Readonly<KernelCall>[];
  if (callType === "00") {
    if (executionData.length < 106) return fail("truncated Kernel execution");
    calls = captureCalls(
      [
        {
          target: executionData.slice(0, 42),
          value: BigInt(`0x${executionData.slice(42, 106)}`).toString(10),
          data: `0x${executionData.slice(106)}`,
        },
      ],
      new WeakSet(),
    );
  } else if (callType === "01") {
    const [batch] = decodeAbiParameters(
      [
        {
          type: "tuple[]",
          components: [
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "data", type: "bytes" },
          ],
        },
      ],
      executionData,
    );
    calls = captureCalls(
      batch.map((call) => ({
        target: call.to,
        value: call.value.toString(10),
        data: call.data,
      })),
      new WeakSet(),
    );
  } else {
    return fail("unsupported Kernel call type");
  }
  const validityTimeRange =
    `0x${mode.slice(14, 22)}` === VALIDITY_TIME_RANGE_MODE_SELECTOR
      ? {
          validAfter: BigInt(`0x${mode.slice(22, 34)}`).toString(10),
          validUntil: BigInt(`0x${mode.slice(34, 46)}`).toString(10),
        }
      : undefined;
  const canonical = encodeKernelV4Execution(
    validityTimeRange ? { calls, validityTimeRange } : { calls },
  );
  // Reject unsupported mode bits, non-atomic try execution, noncanonical ABI,
  // and trailing bytes; their semantics are not represented by these calls.
  if (canonical !== data) return fail("unsupported Kernel execution encoding");
  return calls;
}
