import {
  getKernelAddressFromECDSA,
  getValidatorAddress,
  signerToEcdsaValidator,
} from "@zerodev/ecdsa-validator";
import { createKernelAccount } from "@zerodev/sdk";
import { KERNEL_V3_3 } from "@zerodev/sdk/constants";
import { createPublicClient, custom, defineChain, type Hex, recoverMessageAddress } from "viem";
import { entryPoint07Address, type UserOperation } from "viem/account-abstraction";
import { toAccount } from "viem/accounts";
import {
  captureKernelAccountProfile,
  createKernelAccountActionInput,
  type KernelAccountActionInput,
  type KernelAccountProfile,
} from "./identity-profile.js";
import { type CaptureContext, exactRecord } from "./internal/exact-record.js";
import { KERNEL_RUNTIME_CAPABILITIES } from "./kernel-runtime-capabilities.js";
import {
  type PreparedFactory,
  type PreparedUserOperation,
  parsePreparedUserOperation,
} from "./prepared-user-operation.js";

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const SIGNATURE = /^0x[0-9a-f]{130}$/u;
const ROOT_VALIDATION_ID = /^0x[0-9a-f]{42}$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;

export type EcdsaKernelOwnerErrorCode =
  | "ecdsa_kernel_owner_input_invalid"
  | "ecdsa_kernel_owner_signer_invalid"
  | "ecdsa_kernel_owner_binding_mismatch"
  | "ecdsa_kernel_owner_runtime_unavailable"
  | "ecdsa_kernel_owner_restoration_required"
  | "ecdsa_kernel_owner_restoration_absent"
  | "ecdsa_kernel_owner_restoration_unavailable"
  | "ecdsa_kernel_owner_restoration_unreadable"
  | "ecdsa_kernel_owner_prepared_operation_invalid"
  | "ecdsa_kernel_owner_signing_failed";

export class OgpEcdsaKernelOwnerError extends Error {
  readonly code: EcdsaKernelOwnerErrorCode;

  constructor(code: EcdsaKernelOwnerErrorCode, message: string) {
    super(message);
    this.name = "OgpEcdsaKernelOwnerError";
    this.code = code;
  }
}

export interface EcdsaOwnerSignerCapability {
  readonly address: `0x${string}`;
  readonly signMessageHash: (request: Readonly<{ hash: `0x${string}` }>) => Promise<unknown>;
}

export type EcdsaKernelOwnerRestorationReadRequest =
  | Readonly<{ type: "chain_id"; chainId: number }>
  | Readonly<{
      type: "account_code";
      chainId: number;
      account: `0x${string}`;
    }>
  | Readonly<{
      type: "kernel_root_validator";
      chainId: number;
      account: `0x${string}`;
    }>
  | Readonly<{
      type: "ecdsa_validator_owner";
      chainId: number;
      validator: `0x${string}`;
      account: `0x${string}`;
    }>;

export interface EcdsaKernelOwnerRestorationReadCapability {
  readonly read: (request: EcdsaKernelOwnerRestorationReadRequest) => Promise<unknown>;
}

export interface RestoredEcdsaKernelOwner {
  readonly status: "deployed";
  readonly chainId: number;
  readonly account: `0x${string}`;
  readonly validator: `0x${string}`;
  readonly owner: `0x${string}`;
}

export interface EcdsaKernelOwnerRuntime {
  readonly profile: Readonly<KernelAccountProfile>;
  readonly action: Readonly<KernelAccountActionInput>;
  readonly accountAddress: `0x${string}`;
  readonly validatorAddress: `0x${string}`;
  readonly factory: Readonly<PreparedFactory>;
  readonly restore: (reads: unknown) => Promise<Readonly<RestoredEcdsaKernelOwner>>;
  readonly signPreparedUserOperation: (value: unknown) => Promise<`0x${string}`>;
}

interface CapturedSigner {
  readonly address: `0x${string}`;
  readonly signMessageHash: EcdsaOwnerSignerCapability["signMessageHash"];
}

function ownerError(code: EcdsaKernelOwnerErrorCode, message: string): never {
  throw new OgpEcdsaKernelOwnerError(code, message);
}

function lowerAddress(value: string): `0x${string}` {
  return value.toLowerCase() as `0x${string}`;
}

function address(value: unknown, code: EcdsaKernelOwnerErrorCode): `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value) || value === ZERO_ADDRESS) {
    return ownerError(code, "ECDSA Kernel owner address is invalid");
  }
  return value as `0x${string}`;
}

function captureSigner(
  value: unknown,
  expectedAddress: `0x${string}`,
  context: CaptureContext,
): CapturedSigner {
  let record: Record<string, unknown>;
  try {
    record = exactRecord(
      value,
      ["address", "signMessageHash"],
      "ECDSA owner signer capability",
      context,
      (message) => ownerError("ecdsa_kernel_owner_signer_invalid", message),
    );
  } catch (error) {
    if (error instanceof OgpEcdsaKernelOwnerError) throw error;
    return ownerError(
      "ecdsa_kernel_owner_signer_invalid",
      "ECDSA owner signer capability could not be captured safely",
    );
  }
  const signerAddress = address(record.address, "ecdsa_kernel_owner_signer_invalid");
  if (signerAddress !== expectedAddress) {
    return ownerError(
      "ecdsa_kernel_owner_binding_mismatch",
      "ECDSA owner signer does not match the selected profile",
    );
  }
  if (typeof record.signMessageHash !== "function") {
    return ownerError(
      "ecdsa_kernel_owner_signer_invalid",
      "ECDSA owner signing capability is invalid",
    );
  }
  return Object.freeze({
    address: signerAddress,
    signMessageHash: record.signMessageHash as EcdsaOwnerSignerCapability["signMessageHash"],
  });
}

function captureReads(value: unknown): EcdsaKernelOwnerRestorationReadCapability {
  let record: Record<string, unknown>;
  try {
    record = exactRecord(
      value,
      ["read"],
      "ECDSA owner restoration read capability",
      new WeakSet(),
      (message) => ownerError("ecdsa_kernel_owner_restoration_unreadable", message),
    );
  } catch (error) {
    if (error instanceof OgpEcdsaKernelOwnerError) throw error;
    return ownerError(
      "ecdsa_kernel_owner_restoration_unreadable",
      "ECDSA owner restoration reader could not be captured safely",
    );
  }
  if (typeof record.read !== "function") {
    return ownerError(
      "ecdsa_kernel_owner_restoration_unreadable",
      "ECDSA owner restoration reader is invalid",
    );
  }
  return Object.freeze({
    read: record.read as EcdsaKernelOwnerRestorationReadCapability["read"],
  });
}

function rawHash(value: unknown): `0x${string}` {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return ownerError("ecdsa_kernel_owner_signing_failed", "ECDSA signing request is invalid");
  }
  const record = exactRecord(value, ["raw"], "ECDSA signing message", new WeakSet(), () =>
    ownerError("ecdsa_kernel_owner_signing_failed", "ECDSA signing request is invalid"),
  );
  if (typeof record.raw !== "string" || !HASH.test(record.raw)) {
    return ownerError("ecdsa_kernel_owner_signing_failed", "ECDSA signing request is invalid");
  }
  return record.raw as `0x${string}`;
}

function contractSignature(value: string): Hex {
  const recoveryByte = value.slice(-2);
  if (recoveryByte === "1b" || recoveryByte === "1c") return value as Hex;
  if (recoveryByte === "00") return `${value.slice(0, -2)}1b` as Hex;
  if (recoveryByte === "01") return `${value.slice(0, -2)}1c` as Hex;
  return ownerError(
    "ecdsa_kernel_owner_signing_failed",
    "ECDSA owner signature recovery byte is invalid",
  );
}

function asViemUserOperation(value: PreparedUserOperation): UserOperation<"0.7"> {
  const operation = value.userOperation;
  return {
    sender: operation.sender,
    nonce: BigInt(operation.nonce),
    callData: operation.callData,
    callGasLimit: BigInt(operation.callGasLimit),
    verificationGasLimit: BigInt(operation.verificationGasLimit),
    preVerificationGas: BigInt(operation.preVerificationGas),
    maxFeePerGas: BigInt(operation.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(operation.maxPriorityFeePerGas),
    signature: "0x",
    ...(operation.factory === null
      ? {}
      : { factory: operation.factory.address, factoryData: operation.factory.data }),
    ...(operation.paymaster === null
      ? {}
      : {
          paymaster: operation.paymaster.address,
          paymasterVerificationGasLimit: BigInt(operation.paymaster.verificationGasLimit),
          paymasterPostOpGasLimit: BigInt(operation.paymaster.postOpGasLimit),
          paymasterData: operation.paymaster.data,
        }),
  };
}

function sameFactory(left: Readonly<PreparedFactory>, right: Readonly<PreparedFactory>): boolean {
  return left.address === right.address && left.data === right.data;
}

function capturePreparedOperation(
  value: unknown,
  action: Readonly<KernelAccountActionInput>,
  accountAddress: `0x${string}`,
  factory: Readonly<PreparedFactory>,
  deployedVerified: boolean,
): PreparedUserOperation {
  let prepared: PreparedUserOperation;
  try {
    prepared = parsePreparedUserOperation(value);
  } catch {
    return ownerError(
      "ecdsa_kernel_owner_prepared_operation_invalid",
      "Prepared UserOperation is invalid",
    );
  }
  if (
    prepared.chainId !== action.chainId ||
    prepared.entryPoint.version !== "0.7" ||
    prepared.entryPoint.address !== lowerAddress(entryPoint07Address) ||
    prepared.userOperation.sender !== accountAddress
  ) {
    return ownerError(
      "ecdsa_kernel_owner_binding_mismatch",
      "Prepared UserOperation does not match the ECDSA Kernel owner",
    );
  }
  if (prepared.userOperation.factory === null) {
    if (!deployedVerified) {
      return ownerError(
        "ecdsa_kernel_owner_restoration_required",
        "Deployed ECDSA Kernel owner evidence is required before signing",
      );
    }
  } else if (!sameFactory(prepared.userOperation.factory, factory)) {
    return ownerError(
      "ecdsa_kernel_owner_binding_mismatch",
      "Prepared UserOperation factory does not match the ECDSA Kernel owner",
    );
  }
  return prepared;
}

/**
 * Builds one exact ECDSA root-owner runtime for a caller-supplied action chain.
 * The chain is an operation/materialization fact, never a Grant support policy.
 */
export async function createEcdsaKernelOwnerRuntime(
  value: unknown,
): Promise<Readonly<EcdsaKernelOwnerRuntime>> {
  try {
    const context: CaptureContext = new WeakSet();
    let record: Record<string, unknown>;
    try {
      record = exactRecord(
        value,
        ["profile", "chainId", "signer"],
        "ECDSA Kernel owner runtime input",
        context,
        (message) => ownerError("ecdsa_kernel_owner_input_invalid", message),
      );
    } catch (error) {
      if (error instanceof OgpEcdsaKernelOwnerError) throw error;
      return ownerError(
        "ecdsa_kernel_owner_input_invalid",
        "ECDSA Kernel owner runtime input could not be captured safely",
      );
    }
    let profile: Readonly<KernelAccountProfile>;
    try {
      profile = captureKernelAccountProfile(record.profile, context, (message) =>
        ownerError("ecdsa_kernel_owner_input_invalid", message),
      );
    } catch (error) {
      if (error instanceof OgpEcdsaKernelOwnerError) throw error;
      return ownerError("ecdsa_kernel_owner_input_invalid", "Kernel account profile is invalid");
    }
    if (profile.ownerCredential.kind !== "ecdsa") {
      return ownerError(
        "ecdsa_kernel_owner_input_invalid",
        "Selected Kernel owner profile is not ECDSA",
      );
    }
    let action: Readonly<KernelAccountActionInput>;
    try {
      action = createKernelAccountActionInput(profile, record.chainId);
    } catch {
      return ownerError("ecdsa_kernel_owner_input_invalid", "Kernel action chain is invalid");
    }
    const signer = captureSigner(record.signer, profile.ownerCredential.address, context);
    const chain = defineChain({
      id: action.chainId,
      name: `OGP action ${action.chainId}`,
      nativeCurrency: { name: "Native", symbol: "NATIVE", decimals: 18 },
      rpcUrls: { default: { http: ["http://127.0.0.1"] } },
    });
    const client = createPublicClient({
      chain,
      transport: custom({
        async request({ method }) {
          if (method === "eth_chainId") {
            return `0x${action.chainId.toString(16)}`;
          }
          throw new Error("ECDSA owner runtime has no RPC capability");
        },
      }),
    });
    const entryPoint = Object.freeze({ version: "0.7" as const, address: entryPoint07Address });
    const validatorAddress = lowerAddress(getValidatorAddress(entryPoint, KERNEL_V3_3));
    const accountAddress = lowerAddress(
      await getKernelAddressFromECDSA({
        publicClient: client,
        entryPoint,
        kernelVersion: KERNEL_V3_3,
        eoaAddress: signer.address,
        index: BigInt(profile.accountIndex),
      }),
    );
    const localSigner = toAccount({
      address: signer.address,
      async signMessage({ message }) {
        const hash = rawHash(message);
        let signature: unknown;
        try {
          signature = await Reflect.apply(signer.signMessageHash, undefined, [
            Object.freeze({ hash }),
          ]);
        } catch {
          return ownerError("ecdsa_kernel_owner_signing_failed", "ECDSA owner signing failed");
        }
        if (typeof signature !== "string" || !SIGNATURE.test(signature)) {
          return ownerError(
            "ecdsa_kernel_owner_signing_failed",
            "ECDSA owner signature is invalid",
          );
        }
        const normalizedSignature = contractSignature(signature);
        let recovered: `0x${string}`;
        try {
          recovered = lowerAddress(
            await recoverMessageAddress({ message: { raw: hash }, signature: normalizedSignature }),
          );
        } catch {
          return ownerError(
            "ecdsa_kernel_owner_signing_failed",
            "ECDSA owner signature is invalid",
          );
        }
        if (recovered !== signer.address) {
          return ownerError(
            "ecdsa_kernel_owner_signing_failed",
            "ECDSA owner signature does not match the selected profile",
          );
        }
        return normalizedSignature;
      },
      async signTransaction() {
        return ownerError(
          "ecdsa_kernel_owner_signing_failed",
          "ECDSA owner transaction signing is outside this runtime",
        );
      },
      async signTypedData() {
        return ownerError(
          "ecdsa_kernel_owner_signing_failed",
          "ECDSA owner typed-data signing is outside this runtime",
        );
      },
    });
    const validator = await signerToEcdsaValidator(client, {
      signer: localSigner,
      entryPoint,
      kernelVersion: KERNEL_V3_3,
    });
    if (lowerAddress(validator.address) !== validatorAddress) {
      return ownerError(
        "ecdsa_kernel_owner_runtime_unavailable",
        "ECDSA validator address does not match the pinned runtime",
      );
    }
    const account = await createKernelAccount(client, {
      plugins: { sudo: validator },
      entryPoint,
      kernelVersion: KERNEL_V3_3,
      index: BigInt(profile.accountIndex),
      address: accountAddress,
      useMetaFactory: profile.factoryRoute === "meta_factory",
    });
    if (lowerAddress(account.address) !== accountAddress) {
      return ownerError(
        "ecdsa_kernel_owner_runtime_unavailable",
        "Kernel account address does not match its exact derivation",
      );
    }
    const factoryData = await account.generateInitCode();
    const expectedFactory = lowerAddress(
      profile.factoryRoute === "kernel_factory"
        ? KERNEL_RUNTIME_CAPABILITIES.contracts.kernel.factory
        : KERNEL_RUNTIME_CAPABILITIES.contracts.kernel.metaFactory,
    );
    const factory = Object.freeze({
      address: lowerAddress(account.factoryAddress),
      data: factoryData.toLowerCase() as `0x${string}`,
    });
    if (factory.address !== expectedFactory || !BYTES.test(factory.data)) {
      return ownerError(
        "ecdsa_kernel_owner_runtime_unavailable",
        "Kernel account factory route does not match the selected profile",
      );
    }

    let deployedVerified = false;

    async function restore(readsValue: unknown): Promise<Readonly<RestoredEcdsaKernelOwner>> {
      const reads = captureReads(readsValue);
      async function read(request: EcdsaKernelOwnerRestorationReadRequest): Promise<unknown> {
        try {
          return await Reflect.apply(reads.read, undefined, [Object.freeze(request)]);
        } catch {
          return ownerError(
            "ecdsa_kernel_owner_restoration_unavailable",
            "ECDSA owner restoration evidence is unavailable",
          );
        }
      }
      const observedChainId = await read({ type: "chain_id", chainId: action.chainId });
      if (
        typeof observedChainId !== "number" ||
        !Number.isSafeInteger(observedChainId) ||
        observedChainId < 1
      ) {
        return ownerError(
          "ecdsa_kernel_owner_restoration_unreadable",
          "ECDSA owner restoration chain evidence is unreadable",
        );
      }
      if (observedChainId !== action.chainId) {
        return ownerError(
          "ecdsa_kernel_owner_binding_mismatch",
          "ECDSA owner restoration chain does not match the action",
        );
      }
      const code = await read({
        type: "account_code",
        chainId: action.chainId,
        account: accountAddress,
      });
      if (typeof code !== "string" || !BYTES.test(code)) {
        return ownerError(
          "ecdsa_kernel_owner_restoration_unreadable",
          "ECDSA Kernel account code evidence is unreadable",
        );
      }
      if (code === "0x") {
        return ownerError(
          "ecdsa_kernel_owner_restoration_absent",
          "ECDSA Kernel account is not deployed",
        );
      }
      const rootValidator = await read({
        type: "kernel_root_validator",
        chainId: action.chainId,
        account: accountAddress,
      });
      if (typeof rootValidator !== "string" || !ROOT_VALIDATION_ID.test(rootValidator)) {
        return ownerError(
          "ecdsa_kernel_owner_restoration_unreadable",
          "Kernel root-validator evidence is unreadable",
        );
      }
      const expectedRootValidator = `0x01${validatorAddress.slice(2)}`;
      if (rootValidator !== expectedRootValidator) {
        return ownerError(
          "ecdsa_kernel_owner_binding_mismatch",
          "Kernel root validator does not match the selected ECDSA runtime",
        );
      }
      const observedOwner = await read({
        type: "ecdsa_validator_owner",
        chainId: action.chainId,
        validator: validatorAddress,
        account: accountAddress,
      });
      if (typeof observedOwner !== "string" || !ADDRESS.test(observedOwner)) {
        return ownerError(
          "ecdsa_kernel_owner_restoration_unreadable",
          "ECDSA validator owner evidence is unreadable",
        );
      }
      if (observedOwner !== signer.address) {
        return ownerError(
          "ecdsa_kernel_owner_binding_mismatch",
          "ECDSA validator owner does not match the selected profile",
        );
      }
      deployedVerified = true;
      return Object.freeze({
        status: "deployed" as const,
        chainId: action.chainId,
        account: accountAddress,
        validator: validatorAddress,
        owner: signer.address,
      });
    }

    async function signPreparedUserOperation(value: unknown): Promise<`0x${string}`> {
      const prepared = capturePreparedOperation(
        value,
        action,
        accountAddress,
        factory,
        deployedVerified,
      );
      try {
        const signature = await account.signUserOperation({
          ...asViemUserOperation(prepared),
          chainId: action.chainId,
        });
        if (!SIGNATURE.test(signature)) {
          return ownerError(
            "ecdsa_kernel_owner_signing_failed",
            "Kernel owner signature is invalid",
          );
        }
        return signature;
      } catch (error) {
        if (error instanceof OgpEcdsaKernelOwnerError) throw error;
        return ownerError("ecdsa_kernel_owner_signing_failed", "ECDSA owner signing failed");
      }
    }

    return Object.freeze({
      profile,
      action,
      accountAddress,
      validatorAddress,
      factory,
      restore,
      signPreparedUserOperation,
    });
  } catch (error) {
    if (error instanceof OgpEcdsaKernelOwnerError) throw error;
    throw new OgpEcdsaKernelOwnerError(
      "ecdsa_kernel_owner_runtime_unavailable",
      "ECDSA Kernel owner runtime could not be created",
    );
  }
}
