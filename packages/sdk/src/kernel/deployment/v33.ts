const zeroAddress = "0x0000000000000000000000000000000000000000" as const;

/**
 * Kernel 0.3.3 accounts: existing accounts bound at their address, and
 * ECDSA-owned accounts derived through ZeroDev's MetaFactory route. A derived
 * account's address is the one ZeroDev's SDK computes; it is never replaced.
 */
import { type CaptureContext, captureRecord } from "@oaath/protocol";
import {
  concatHex,
  decodeAbiParameters,
  encodeAbiParameters,
  encodeFunctionData,
  getContractAddress,
  keccak256,
  parseAbi,
  toHex,
} from "cetane/utils";
import {
  KERNEL_V4_CREATE2_DEPLOYER,
  KERNEL_V4_IMPLEMENTATION_SLOT,
  type KernelV4ReadClient,
} from "../../kernel-v4.js";
import {
  exactInput,
  inputAddress,
  inputCapability,
  inputInvalid,
  inputUint,
  isBytes,
  runtimeFail,
} from "../internal.js";
import { readKernelV33PermissionState } from "../permission/v33-revocation.js";

export const KERNEL_ENTRY_POINT_V07 = Object.freeze({
  version: "0.7" as const,
  address: "0x0000000071727de22e5e9d8baf0edac6f37da032" as const,
  runtimeCodeHash: "0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58" as const,
});

// ZeroDev SDK constants at cd7c05b53b6ae6bede7dfefe9e59fbddfadf0c0a.
// Contract ABI: zerodevapp/kernel v3.3, cd697c7e21715d015e0643af22310a99aa17433b.
const IMPLEMENTATION = "0xd6cedde84be40893d153be9d467cd6ad37875b28" as const;
const FACTORY = "0x2577507b78c2008ff367261cb6285d44ba5ef2e9" as const;
export const ECDSA_VALIDATOR = "0x845adb2c711129d4f3966735ed98a9f09fc4ce57" as const;
/** ZeroDev's `metaFactoryAddress` (FactoryStaker); `deployWithFactory` forwards to FACTORY. */
const META_FACTORY = "0xd703aae79538628d27099b8c4f621be4ccd142d5" as const;
/** ZeroDev's `initCodeHash`: Solady's ERC-1967 proxy creation code for IMPLEMENTATION. */
const PROXY_INIT_CODE_HASH =
  "0xc452397f1e7518f8cea0566ac057e243bb1643f6298aba8eec8cdee78ee3b3dd" as const;
// Runtime code of the CREATE2 artifacts; neither has a chain-dependent immutable,
// and the factory's code embeds IMPLEMENTATION, so these pin the whole route.
const FACTORY_RUNTIME_CODE_HASH =
  "0xcc4b1b98f5716bf61042d87bfedd4709a5c9a597c41f3bb0e6fb6fe1a4ebd37a" as const;
const META_FACTORY_RUNTIME_CODE_HASH =
  "0x4527f3642a53f1f4ce76beb05f955a8859b7245a1ff20da5be9a518d2fcd64aa" as const;
const MAX_UINT256 = (1n << 256n) - 1n;
const ABI = parseAbi([
  "function accountId() view returns (string)",
  "function entrypoint() view returns (address)",
  "function rootValidator() view returns (bytes21)",
  "function ecdsaValidatorStorage(address) view returns (address)",
  "function currentNonce() view returns (uint32)",
  "function validationConfig(bytes21) view returns (uint32 nonce, address hook)",
  "function approved(address) view returns (bool)",
  "function initialize(bytes21 rootValidator, address hook, bytes validatorData, bytes hookData, bytes[] initConfig)",
  "function deployWithFactory(address factory, bytes createData, bytes32 salt) payable returns (address)",
]);

export interface KernelV33Deployment {
  readonly profile: "kernel-v3.3-entrypoint-v0.7";
  readonly kernelVersion: "0.3.3";
  readonly chainId: number;
  readonly entryPoint: typeof KERNEL_ENTRY_POINT_V07;
  readonly implementation: typeof IMPLEMENTATION;
  readonly factory: typeof FACTORY;
  readonly factoryRuntimeCodeHash: typeof FACTORY_RUNTIME_CODE_HASH;
  /** The UserOperation `factory` of a derived account's deployment. */
  readonly metaFactory: typeof META_FACTORY;
  readonly metaFactoryRuntimeCodeHash: typeof META_FACTORY_RUNTIME_CODE_HASH;
  readonly ecdsaValidator: typeof ECDSA_VALIDATOR;
  /** The canonical CREATE2 deployer the reviewed contracts are derived through. */
  readonly create2Deployer: typeof KERNEL_V4_CREATE2_DEPLOYER;
}

const deployments = new Map<number, Readonly<KernelV33Deployment>>();

export function kernelV33Deployment(chainId: unknown): Readonly<KernelV33Deployment> {
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
    return inputInvalid("Kernel chain ID is invalid");
  }
  let deployment = deployments.get(chainId);
  if (!deployment) {
    deployment = Object.freeze({
      profile: "kernel-v3.3-entrypoint-v0.7",
      kernelVersion: "0.3.3",
      chainId,
      entryPoint: KERNEL_ENTRY_POINT_V07,
      implementation: IMPLEMENTATION,
      factory: FACTORY,
      factoryRuntimeCodeHash: FACTORY_RUNTIME_CODE_HASH,
      metaFactory: META_FACTORY,
      metaFactoryRuntimeCodeHash: META_FACTORY_RUNTIME_CODE_HASH,
      ecdsaValidator: ECDSA_VALIDATOR,
      create2Deployer: KERNEL_V4_CREATE2_DEPLOYER,
    });
    deployments.set(chainId, deployment);
  }
  return deployment;
}

export type KernelV33ReadRequest =
  | Readonly<{ type: "chain_id"; chainId: number }>
  | Readonly<{ type: "code"; chainId: number; address: `0x${string}` }>
  | Readonly<{ type: "runtime_code_hash"; chainId: number; address: `0x${string}` }>
  | Readonly<{ type: "kernel_ecdsa_owner"; chainId: number; account: `0x${string}` }>
  | Readonly<{
      type: "kernel_v33_factory_approval";
      chainId: number;
      metaFactory: `0x${string}`;
      factory: `0x${string}`;
    }>
  | Readonly<{
      type: "kernel_v33_permission_nonce" | "kernel_v33_permission_state";
      chainId: number;
      account: `0x${string}`;
      permissionId: `0x${string}`;
      /** Named block every call of this read is answered at; omitted is the client's default. */
      blockTag?: "latest" | "finalized";
    }>
  | Readonly<{
      type:
        | "kernel_account_implementation"
        | "kernel_account_version"
        | "kernel_account_entrypoint"
        | "kernel_account_root_validator";
      chainId: number;
      account: `0x${string}`;
    }>;

export interface KernelV33Reads {
  readonly read: (request: KernelV33ReadRequest) => Promise<unknown>;
}

export interface BindKernelV33AccountInput {
  readonly chainId: number;
  readonly address: `0x${string}`;
  readonly reads: KernelV33Reads;
}

interface KernelV33AccountCommon {
  readonly profile: "kernel-v3.3-entrypoint-v0.7";
  readonly version: "0.3.3";
  readonly chainId: number;
  readonly account: `0x${string}`;
  readonly entryPoint: typeof KERNEL_ENTRY_POINT_V07.address;
  readonly implementation: typeof IMPLEMENTATION;
}

export interface KernelV33DeployedAccountDescriptor extends KernelV33AccountCommon {
  readonly state: "deployed";
  /** Current root validation, rather than the account's historical factory initializer. */
  readonly rootValidator: `0x${string}`;
}

/**
 * A derived account with no code when bound. Its operations carry the
 * MetaFactory deployment; once deployed, rebind it to drop the factory.
 */
export interface KernelV33CounterfactualAccountDescriptor extends KernelV33AccountCommon {
  readonly state: "counterfactual";
  /** The root validation the factory initializer installs: the ECDSA validator. */
  readonly rootValidator: `0x${string}`;
  readonly owner: `0x${string}`;
  readonly accountIndex: string;
  readonly factory: typeof META_FACTORY;
  readonly factoryData: `0x${string}`;
}

export type KernelV33AccountDescriptor =
  | KernelV33DeployedAccountDescriptor
  | KernelV33CounterfactualAccountDescriptor;

export interface KernelV33Derivation {
  readonly address: `0x${string}`;
  readonly factory: typeof META_FACTORY;
  readonly factoryData: `0x${string}`;
}

/**
 * Offline derivation of an ECDSA-owned account, byte for byte ZeroDev's
 * `createKernelAccount` for 0.3.3 on EntryPoint 0.7 with its defaults: root
 * validator `0x01 || ECDSA_VALIDATOR`, no hook (`address(0)`, `0x`), owner as
 * validator data, empty initConfig, and the MetaFactory route. The address is
 * KernelFactory's CREATE2 of the proxy at `keccak256(initData || index)`, so
 * it is the same on every chain.
 */
export function deriveKernelV33Account(
  value: Readonly<{ owner?: unknown; accountIndex?: unknown }>,
): Readonly<KernelV33Derivation> {
  const owner = inputAddress(value.owner, "Kernel v3.3 account owner");
  const index = toHex(inputUint(value.accountIndex, MAX_UINT256, "Kernel account index"), {
    size: 32,
  });
  const initData = encodeFunctionData({
    abi: ABI,
    functionName: "initialize",
    args: [`0x01${ECDSA_VALIDATOR.slice(2)}`, zeroAddress, owner, "0x", []],
  });
  return Object.freeze({
    address: getContractAddress({
      opcode: "CREATE2",
      from: FACTORY,
      salt: keccak256(concatHex([initData, index])),
      bytecodeHash: PROXY_INIT_CODE_HASH,
    }).toLowerCase() as `0x${string}`,
    factory: META_FACTORY,
    factoryData: encodeFunctionData({
      abi: ABI,
      functionName: "deployWithFactory",
      args: [FACTORY, initData, index],
    }),
  });
}

const boundAccounts = new WeakSet<object>();

function mismatch(message: string): never {
  return runtimeFail("kernel_runtime_binding_mismatch", message);
}

/** Internal proof check used by the runtime before preparing an operation. */
export function provenKernelV33Account(value: unknown): Readonly<KernelV33AccountDescriptor> {
  if (!value || typeof value !== "object" || !boundAccounts.has(value)) {
    return mismatch("Kernel v3.3 account has not been bound by this SDK instance");
  }
  return value as Readonly<KernelV33AccountDescriptor>;
}

type Evidence = (request: KernelV33ReadRequest) => Promise<unknown>;

function evidenceReader(reads: unknown, context: CaptureContext): Evidence {
  const read = inputCapability<KernelV33Reads["read"]>(
    exactInput(reads, ["read"], "Kernel v3.3 reads", context).read,
    "Kernel v3.3 read capability",
  );
  return async (request) => {
    try {
      return await read(Object.freeze(request));
    } catch {
      return runtimeFail(
        "kernel_runtime_read_unavailable",
        "Kernel v3.3 account evidence could not be read",
      );
    }
  };
}

async function proveChain(evidence: Evidence, deployment: KernelV33Deployment): Promise<void> {
  const chainId = deployment.chainId;
  if ((await evidence({ type: "chain_id", chainId })) !== chainId) {
    mismatch("Kernel v3.3 chain does not match the requested chain");
  }
}

async function proveCode(
  evidence: Evidence,
  chainId: number,
  address: `0x${string}`,
): Promise<void> {
  const code = await evidence({ type: "code", chainId, address });
  if (!isBytes(code) || code === "0x") mismatch("Kernel v3.3 deployment code is absent or invalid");
}

async function proveEntryPointAndImplementation(
  evidence: Evidence,
  deployment: KernelV33Deployment,
): Promise<void> {
  const chainId = deployment.chainId;
  await proveCode(evidence, chainId, deployment.implementation);
  if (
    (await evidence({
      type: "runtime_code_hash",
      chainId,
      address: deployment.entryPoint.address,
    })) !== KERNEL_ENTRY_POINT_V07.runtimeCodeHash
  ) {
    mismatch("Kernel v3.3 EntryPoint runtime code does not match");
  }
}

/**
 * Binds a deployed 0.3.3 proxy at its existing address. It does not create an
 * account, change its owner, or authorize an operation. Unavailable evidence
 * never triggers deployment, a retry, or a switch to another Kernel version.
 */
export async function bindKernelV33Account(
  value: BindKernelV33AccountInput,
): Promise<Readonly<KernelV33DeployedAccountDescriptor>> {
  const context: CaptureContext = new WeakSet();
  const record = exactInput(
    value,
    ["chainId", "address", "reads"],
    "Kernel existing account",
    context,
  );
  const deployment = kernelV33Deployment(record.chainId);
  const account = inputAddress(record.address, "Kernel existing account address");
  const evidence = evidenceReader(record.reads, context);
  const chainId = deployment.chainId;
  await proveChain(evidence, deployment);
  const requireCode = (address: `0x${string}`) => proveCode(evidence, chainId, address);
  await requireCode(account);
  await proveEntryPointAndImplementation(evidence, deployment);
  if (
    (await evidence({ type: "kernel_account_implementation", chainId, account })) !==
    deployment.implementation
  ) {
    return mismatch("Kernel account implementation is not v3.3");
  }
  if (
    (await evidence({ type: "kernel_account_version", chainId, account })) !==
    "kernel.advanced.v0.3.3"
  ) {
    return mismatch("Kernel account version is not v3.3");
  }
  if (
    (await evidence({ type: "kernel_account_entrypoint", chainId, account })) !==
    deployment.entryPoint.address
  ) {
    return mismatch("Kernel v3.3 account EntryPoint does not match");
  }
  const rootValidator = await evidence({ type: "kernel_account_root_validator", chainId, account });
  if (
    typeof rootValidator !== "string" ||
    !/^0x(?:01[0-9a-f]{40}|02[0-9a-f]{8}0{32})$/u.test(rootValidator) ||
    /^0x(?:01|02)0{40}$/u.test(rootValidator)
  ) {
    return mismatch("Kernel v3.3 root validation is invalid or unsupported");
  }
  if (rootValidator.startsWith("0x01")) await requireCode(`0x${rootValidator.slice(4)}`);
  const descriptor: Readonly<KernelV33DeployedAccountDescriptor> = Object.freeze({
    profile: deployment.profile,
    version: "0.3.3",
    state: "deployed",
    chainId,
    account,
    entryPoint: deployment.entryPoint.address,
    implementation: deployment.implementation,
    rootValidator: rootValidator as `0x${string}`,
  });
  boundAccounts.add(descriptor);
  return descriptor;
}

export interface BindDerivedKernelV33AccountInput {
  readonly chainId: number;
  readonly owner: `0x${string}`;
  readonly accountIndex: string;
  readonly reads: KernelV33Reads;
}

/**
 * Binds the account `deriveKernelV33Account` names. With code at that address
 * it is bound exactly as an existing account, so another implementation fails
 * closed. Without code, the MetaFactory route is proven before a counterfactual
 * descriptor exists: pinned factory and MetaFactory runtime code, the
 * MetaFactory's approval of the factory, and the implementation, validator and
 * EntryPoint code. Binding never deploys; an operation carries the factory.
 */
export async function bindDerivedKernelV33Account(
  value: BindDerivedKernelV33AccountInput,
): Promise<Readonly<KernelV33AccountDescriptor>> {
  const context: CaptureContext = new WeakSet();
  const record = exactInput(
    value,
    ["chainId", "owner", "accountIndex", "reads"],
    "Kernel derived account",
    context,
  );
  const deployment = kernelV33Deployment(record.chainId);
  const derivation = deriveKernelV33Account(record);
  const evidence = evidenceReader(record.reads, context);
  const chainId = deployment.chainId;
  await proveChain(evidence, deployment);
  const code = await evidence({ type: "code", chainId, address: derivation.address });
  if (!isBytes(code)) return mismatch("Kernel v3.3 account code is invalid");
  if (code !== "0x") {
    return bindKernelV33Account({
      chainId,
      address: derivation.address,
      reads: Object.freeze({ read: evidence }),
    });
  }
  await proveEntryPointAndImplementation(evidence, deployment);
  await proveCode(evidence, chainId, deployment.ecdsaValidator);
  for (const [address, expected] of [
    [deployment.factory, deployment.factoryRuntimeCodeHash],
    [deployment.metaFactory, deployment.metaFactoryRuntimeCodeHash],
  ] as const) {
    if ((await evidence({ type: "runtime_code_hash", chainId, address })) !== expected)
      return mismatch("Kernel v3.3 factory route runtime code does not match");
  }
  if (
    (await evidence({
      type: "kernel_v33_factory_approval",
      chainId,
      metaFactory: deployment.metaFactory,
      factory: deployment.factory,
    })) !== true
  ) {
    return mismatch("Kernel v3.3 MetaFactory does not approve the factory");
  }
  const descriptor: Readonly<KernelV33CounterfactualAccountDescriptor> = Object.freeze({
    profile: deployment.profile,
    version: "0.3.3",
    state: "counterfactual",
    chainId,
    account: derivation.address,
    entryPoint: deployment.entryPoint.address,
    implementation: deployment.implementation,
    rootValidator: `0x01${deployment.ecdsaValidator.slice(2)}` as `0x${string}`,
    owner: inputAddress(record.owner, "Kernel v3.3 account owner"),
    accountIndex: inputUint(record.accountIndex, MAX_UINT256, "Kernel account index").toString(10),
    factory: derivation.factory,
    factoryData: derivation.factoryData,
  });
  boundAccounts.add(descriptor);
  return descriptor;
}

/** Uses a public RPC client for account evidence; no bundler methods are called. */
export function createKernelV33Reads(client: KernelV4ReadClient): KernelV33Reads {
  const captured = captureRecord(client, "Kernel read client", new WeakSet(), inputInvalid);
  const getChainId = inputCapability<KernelV4ReadClient["getChainId"]>(
    captured.getChainId,
    "getChainId",
  );
  const getCode = inputCapability<KernelV4ReadClient["getCode"]>(captured.getCode, "getCode");
  const getStorageAt = inputCapability<KernelV4ReadClient["getStorageAt"]>(
    captured.getStorageAt,
    "getStorageAt",
  );
  const call = inputCapability<KernelV4ReadClient["call"]>(captured.call, "call");
  return Object.freeze({
    async read(request: KernelV33ReadRequest): Promise<unknown> {
      switch (request.type) {
        case "chain_id":
          return getChainId();
        case "code":
          return (await getCode({ address: request.address })) ?? "0x";
        case "runtime_code_hash": {
          const code = await getCode({ address: request.address });
          return code && code !== "0x" ? keccak256(code) : undefined;
        }
        case "kernel_account_implementation": {
          const result = await getStorageAt({
            address: request.account,
            slot: KERNEL_V4_IMPLEMENTATION_SLOT,
          });
          if (typeof result !== "string" || !/^0x0{24}[0-9a-fA-F]{40}$/u.test(result)) {
            return mismatch("Kernel implementation storage is invalid");
          }
          return `0x${result.slice(-40).toLowerCase()}`;
        }
        case "kernel_ecdsa_owner": {
          const response = await call({
            to: ECDSA_VALIDATOR,
            data: encodeFunctionData({
              abi: ABI,
              functionName: "ecdsaValidatorStorage",
              args: [request.account],
            }),
          });
          if (!response.data || !/^0x0{24}[0-9a-fA-F]{40}$/u.test(response.data))
            return mismatch("Kernel ECDSA owner evidence is invalid");
          return `0x${response.data.slice(-40).toLowerCase()}`;
        }
        case "kernel_v33_factory_approval": {
          const response = await call({
            to: request.metaFactory,
            data: encodeFunctionData({
              abi: ABI,
              functionName: "approved",
              args: [request.factory],
            }),
          });
          const parameters = [{ type: "bool" }] as const;
          const data = response.data?.toLowerCase();
          if (!data || !isBytes(data))
            return mismatch("Kernel v3.3 factory approval evidence is invalid");
          const [approved] = decodeAbiParameters(parameters, data as `0x${string}`);
          if (encodeAbiParameters(parameters, [approved]) !== data)
            return mismatch("Kernel v3.3 factory approval evidence is noncanonical");
          return approved;
        }
        case "kernel_v33_permission_state":
          return readKernelV33PermissionState({
            permissionId: request.permissionId,
            call: async (data) =>
              (
                await call({
                  to: request.account,
                  data,
                  ...(request.blockTag === undefined ? {} : { blockTag: request.blockTag }),
                })
              ).data,
          });
        case "kernel_v33_permission_nonce": {
          if (!/^0x[0-9a-f]{8}$/u.test(request.permissionId))
            return inputInvalid("Kernel v3.3 permission ID is invalid");
          const current = await call({
            to: request.account,
            data: encodeFunctionData({ abi: ABI, functionName: "currentNonce" }),
          });
          const validation = await call({
            to: request.account,
            data: encodeFunctionData({
              abi: ABI,
              functionName: "validationConfig",
              args: [`0x02${request.permissionId.slice(2)}${"00".repeat(16)}`],
            }),
          });
          if (!current.data || !validation.data)
            return mismatch("Kernel v3.3 validation nonce is unreadable");
          const nonceTypes = [{ type: "uint32" }] as const;
          const configTypes = [{ type: "uint32" }, { type: "address" }] as const;
          const [nonce] = decodeAbiParameters(nonceTypes, current.data);
          const config = decodeAbiParameters(configTypes, validation.data);
          if (
            encodeAbiParameters(nonceTypes, [nonce]) !== current.data.toLowerCase() ||
            encodeAbiParameters(configTypes, config).toLowerCase() !== validation.data.toLowerCase()
          )
            return mismatch("Kernel v3.3 validation nonce is noncanonical");
          const effective = config[0] === nonce ? nonce + 1 : nonce;
          if (effective < 1 || effective > 0xffffffff || config[0] >= effective)
            return mismatch("Kernel v3.3 validation nonce cannot enable this permission");
          return effective.toString(10);
        }
        default: {
          const functionName =
            request.type === "kernel_account_version"
              ? "accountId"
              : request.type === "kernel_account_entrypoint"
                ? "entrypoint"
                : "rootValidator";
          const type =
            functionName === "accountId"
              ? "string"
              : functionName === "entrypoint"
                ? "address"
                : "bytes21";
          const response = await call({
            to: request.account,
            data: encodeFunctionData({ abi: ABI, functionName }),
          });
          const data = response.data;
          if (!data || !isBytes(data.toLowerCase()))
            return mismatch("Kernel account call returned invalid evidence");
          const parameters = [{ type }] as const;
          const [result] = decodeAbiParameters(parameters, data);
          if (encodeAbiParameters(parameters, [result]).toLowerCase() !== data.toLowerCase()) {
            return mismatch("Kernel account call returned noncanonical evidence");
          }
          return type === "string" ? result : result.toLowerCase();
        }
      }
    },
  });
}
