/** Existing Kernel 0.3.3 accounts; this profile never derives a replacement address. */
import { type CaptureContext, captureRecord } from "@oaath/protocol";
import {
  decodeAbiParameters,
  encodeAbiParameters,
  encodeFunctionData,
  keccak256,
  parseAbi,
} from "viem";
import {
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
  KERNEL_V4_IMPLEMENTATION_SLOT,
  type KernelV4ReadClient,
} from "../../kernel-v4.js";
import {
  exactInput,
  inputAddress,
  inputCapability,
  inputInvalid,
  isBytes,
  runtimeFail,
} from "../internal.js";

// ZeroDev SDK constants at cd7c05b53b6ae6bede7dfefe9e59fbddfadf0c0a.
// Contract ABI: zerodevapp/kernel v3.3, cd697c7e21715d015e0643af22310a99aa17433b.
const IMPLEMENTATION = "0xd6cedde84be40893d153be9d467cd6ad37875b28" as const;
const FACTORY = "0x2577507b78c2008ff367261cb6285d44ba5ef2e9" as const;
const ECDSA_VALIDATOR = "0x845adb2c711129d4f3966735ed98a9f09fc4ce57" as const;
const ABI = parseAbi([
  "function accountId() view returns (string)",
  "function entrypoint() view returns (address)",
  "function rootValidator() view returns (bytes21)",
  "function ecdsaValidatorStorage(address) view returns (address)",
]);

export interface KernelV33Deployment {
  readonly profile: "kernel-v3.3-entrypoint-v0.7";
  readonly kernelVersion: "0.3.3";
  readonly chainId: number;
  readonly entryPoint: Readonly<{ version: "0.7"; address: typeof KERNEL_V4_ENTRY_POINT_V07 }>;
  readonly implementation: typeof IMPLEMENTATION;
  readonly factory: typeof FACTORY;
  readonly ecdsaValidator: typeof ECDSA_VALIDATOR;
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
      entryPoint: Object.freeze({ version: "0.7", address: KERNEL_V4_ENTRY_POINT_V07 }),
      implementation: IMPLEMENTATION,
      factory: FACTORY,
      ecdsaValidator: ECDSA_VALIDATOR,
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

export interface BindKernelAccountInput {
  readonly version: "0.3.3";
  readonly chainId: number;
  readonly address: `0x${string}`;
  readonly reads: KernelV33Reads;
}

export interface KernelV33AccountDescriptor {
  readonly profile: "kernel-v3.3-entrypoint-v0.7";
  readonly version: "0.3.3";
  readonly state: "deployed";
  readonly chainId: number;
  readonly account: `0x${string}`;
  readonly entryPoint: typeof KERNEL_V4_ENTRY_POINT_V07;
  readonly implementation: typeof IMPLEMENTATION;
  /** Current root validation, rather than the account's historical factory initializer. */
  readonly rootValidator: `0x${string}`;
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

/**
 * Binds a deployed 0.3.3 proxy at its existing address. It does not create an
 * account, change its owner, or authorize an operation. Unavailable evidence
 * never triggers deployment, a retry, or a switch to another Kernel version.
 */
export async function bindKernelAccount(
  value: BindKernelAccountInput,
): Promise<Readonly<KernelV33AccountDescriptor>> {
  const context: CaptureContext = new WeakSet();
  const record = exactInput(
    value,
    ["version", "chainId", "address", "reads"],
    "Kernel existing account",
    context,
  );
  if (record.version !== "0.3.3")
    return inputInvalid("Kernel existing account version is unsupported");
  const deployment = kernelV33Deployment(record.chainId);
  const account = inputAddress(record.address, "Kernel existing account address");
  const read = inputCapability<KernelV33Reads["read"]>(
    exactInput(record.reads, ["read"], "Kernel v3.3 reads", context).read,
    "Kernel v3.3 read capability",
  );
  async function evidence(request: KernelV33ReadRequest): Promise<unknown> {
    try {
      return await read(Object.freeze(request));
    } catch {
      return runtimeFail(
        "kernel_runtime_read_unavailable",
        "Kernel v3.3 account evidence could not be read",
      );
    }
  }
  const chainId = deployment.chainId;
  if ((await evidence({ type: "chain_id", chainId })) !== chainId) {
    return mismatch("Kernel v3.3 chain does not match the requested chain");
  }
  async function requireCode(address: `0x${string}`): Promise<void> {
    const code = await evidence({ type: "code", chainId, address });
    if (!isBytes(code) || code === "0x")
      mismatch("Kernel v3.3 deployment code is absent or invalid");
  }
  await requireCode(account);
  await requireCode(deployment.implementation);
  if (
    (await evidence({
      type: "runtime_code_hash",
      chainId,
      address: deployment.entryPoint.address,
    })) !== KERNEL_V4_ENTRY_POINT_V07_CODE_HASH
  ) {
    return mismatch("Kernel v3.3 EntryPoint runtime code does not match");
  }
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
  const descriptor: Readonly<KernelV33AccountDescriptor> = Object.freeze({
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
