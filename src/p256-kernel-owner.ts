import { p256 } from "@noble/curves/nist.js";
import { createKernelAccount } from "@zerodev/sdk";
import { KERNEL_V3_3 } from "@zerodev/sdk/constants";
import type { KernelValidator } from "@zerodev/sdk/types";
import {
  concatHex,
  createPublicClient,
  custom,
  encodeAbiParameters,
  type Hex,
  hexToBytes,
  keccak256,
  zeroAddress,
} from "viem";
import {
  entryPoint07Address,
  getUserOperationHash,
  type UserOperation,
} from "viem/account-abstraction";
import { toAccount } from "viem/accounts";
import {
  captureKernelAccountProfile,
  createKernelAccountActionInput,
  type KernelAccountActionInput,
  type KernelAccountProfile,
} from "./identity-profile.js";
import { type CaptureContext, exactRecord } from "./internal/exact-record.js";
import { deriveKernelV3_3AccountAddress } from "./internal/kernel-v3_3-account.js";
import { KERNEL_RUNTIME_CAPABILITIES } from "./kernel-runtime-capabilities.js";
import {
  type PreparedFactory,
  type PreparedUserOperation,
  parsePreparedUserOperation,
} from "./prepared-user-operation.js";

const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const PUBLIC_KEY = /^0x04[0-9a-f]{128}$/u;
const ROOT_VALIDATION_ID = /^0x[0-9a-f]{42}$/u;
const SIGNATURE = /^0x[0-9a-f]{128}$/u;
const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const P256_HALF_ORDER = P256_ORDER / 2n;
const PRECOMPILE_SUCCESS = `0x${"00".repeat(31)}01` as const;
const PRECOMPILE_INPUT = concatHex([
  "0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023",
  `0x${"00".repeat(31)}05`,
  `0x${"00".repeat(31)}01`,
  "0xa71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac957",
  "0x5d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b",
]);
const DUMMY_SIGNATURE =
  "0x635bc6d0f68ff895cae8a288ecf7542a6a9cd555df784b73e1e2ea7e9104b1db15e9015d280cb19527881c625fee43fd3a405d5b0d199a8c8e6589a7381209e4" as const;

export type P256KernelOwnerErrorCode =
  | "p256_kernel_owner_input_invalid"
  | "p256_kernel_owner_signer_invalid"
  | "p256_kernel_owner_binding_mismatch"
  | "p256_kernel_owner_runtime_unavailable"
  | "p256_kernel_owner_restoration_required"
  | "p256_kernel_owner_restoration_absent"
  | "p256_kernel_owner_restoration_unavailable"
  | "p256_kernel_owner_restoration_unreadable"
  | "p256_kernel_owner_prepared_operation_invalid"
  | "p256_kernel_owner_signing_failed";

export class OgpP256KernelOwnerError extends Error {
  readonly code: P256KernelOwnerErrorCode;

  constructor(code: P256KernelOwnerErrorCode, message: string) {
    super(message);
    this.name = "OgpP256KernelOwnerError";
    this.code = code;
  }
}

export interface P256OwnerSignerCapability {
  readonly publicKey: `0x${string}`;
  readonly signMessageHash: (request: Readonly<{ hash: `0x${string}` }>) => Promise<unknown>;
}

export type P256KernelOwnerRestorationReadRequest =
  | Readonly<{ type: "chain_id"; chainId: number }>
  | Readonly<{
      type: "p256_validator_code";
      chainId: number;
      validator: `0x${string}`;
    }>
  | Readonly<{
      type: "p256_precompile";
      chainId: number;
      precompile: `0x${string}`;
      input: `0x${string}`;
    }>
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
      type: "p256_validator_public_key";
      chainId: number;
      validator: `0x${string}`;
      account: `0x${string}`;
    }>;

export interface P256KernelOwnerRestorationReadCapability {
  readonly read: (request: P256KernelOwnerRestorationReadRequest) => Promise<unknown>;
}

export type RestoredP256KernelOwner =
  | Readonly<{
      status: "counterfactual";
      chainId: number;
      account: `0x${string}`;
      validator: `0x${string}`;
      publicKey: `0x${string}`;
    }>
  | Readonly<{
      status: "deployed";
      chainId: number;
      account: `0x${string}`;
      validator: `0x${string}`;
      publicKey: `0x${string}`;
    }>;

export interface P256KernelOwnerRuntime {
  readonly profile: Readonly<KernelAccountProfile>;
  readonly action: Readonly<KernelAccountActionInput>;
  readonly accountAddress: `0x${string}`;
  readonly validatorAddress: `0x${string}`;
  readonly enableData: `0x${string}`;
  readonly factory: Readonly<PreparedFactory>;
  readonly restore: (reads: unknown) => Promise<Readonly<RestoredP256KernelOwner>>;
  readonly signPreparedUserOperation: (value: unknown) => Promise<`0x${string}`>;
}

interface CapturedSigner {
  readonly publicKey: `0x${string}`;
  readonly signMessageHash: P256OwnerSignerCapability["signMessageHash"];
}

function ownerError(code: P256KernelOwnerErrorCode, message: string): never {
  throw new OgpP256KernelOwnerError(code, message);
}

function lowerAddress(value: string): `0x${string}` {
  return value.toLowerCase() as `0x${string}`;
}

function captureSigner(
  value: unknown,
  expectedPublicKey: `0x${string}`,
  context: CaptureContext,
): CapturedSigner {
  let record: Record<string, unknown>;
  try {
    record = exactRecord(
      value,
      ["publicKey", "signMessageHash"],
      "P-256 owner signer capability",
      context,
      (message) => ownerError("p256_kernel_owner_signer_invalid", message),
    );
  } catch (error) {
    if (error instanceof OgpP256KernelOwnerError) throw error;
    return ownerError(
      "p256_kernel_owner_signer_invalid",
      "P-256 owner signer capability could not be captured safely",
    );
  }
  if (typeof record.publicKey !== "string" || !PUBLIC_KEY.test(record.publicKey)) {
    return ownerError("p256_kernel_owner_signer_invalid", "P-256 signer public key is invalid");
  }
  if (record.publicKey !== expectedPublicKey) {
    return ownerError(
      "p256_kernel_owner_binding_mismatch",
      "P-256 owner signer does not match the selected profile",
    );
  }
  if (typeof record.signMessageHash !== "function") {
    return ownerError("p256_kernel_owner_signer_invalid", "P-256 signing capability is invalid");
  }
  return Object.freeze({
    publicKey: record.publicKey as `0x${string}`,
    signMessageHash: record.signMessageHash as P256OwnerSignerCapability["signMessageHash"],
  });
}

function captureReads(value: unknown): P256KernelOwnerRestorationReadCapability {
  let record: Record<string, unknown>;
  try {
    record = exactRecord(
      value,
      ["read"],
      "P-256 owner restoration read capability",
      new WeakSet(),
      (message) => ownerError("p256_kernel_owner_restoration_unreadable", message),
    );
  } catch (error) {
    if (error instanceof OgpP256KernelOwnerError) throw error;
    return ownerError(
      "p256_kernel_owner_restoration_unreadable",
      "P-256 owner restoration reader could not be captured safely",
    );
  }
  if (typeof record.read !== "function") {
    return ownerError(
      "p256_kernel_owner_restoration_unreadable",
      "P-256 owner restoration reader is invalid",
    );
  }
  return Object.freeze({
    read: record.read as P256KernelOwnerRestorationReadCapability["read"],
  });
}

function rawHash(value: unknown): `0x${string}` {
  try {
    const record = exactRecord(value, ["raw"], "P-256 signing message", new WeakSet(), () =>
      ownerError("p256_kernel_owner_signing_failed", "P-256 signing request is invalid"),
    );
    if (typeof record.raw !== "string" || !HASH.test(record.raw)) {
      return ownerError("p256_kernel_owner_signing_failed", "P-256 signing request is invalid");
    }
    return record.raw as `0x${string}`;
  } catch (error) {
    if (error instanceof OgpP256KernelOwnerError) throw error;
    return ownerError("p256_kernel_owner_signing_failed", "P-256 signing request is invalid");
  }
}

function coordinate(value: string): bigint {
  return BigInt(`0x${value}`);
}

function publicKeyCoordinates(publicKey: `0x${string}`): readonly [bigint, bigint] {
  return Object.freeze([coordinate(publicKey.slice(4, 68)), coordinate(publicKey.slice(68))]);
}

function normalizeSignature(
  value: unknown,
  hash: `0x${string}`,
  publicKey: `0x${string}`,
): `0x${string}` {
  if (typeof value !== "string" || !SIGNATURE.test(value)) {
    return ownerError("p256_kernel_owner_signing_failed", "P-256 owner signature is invalid");
  }
  const r = BigInt(`0x${value.slice(2, 66)}`);
  let s = BigInt(`0x${value.slice(66)}`);
  if (r <= 0n || r >= P256_ORDER || s <= 0n || s >= P256_ORDER) {
    return ownerError("p256_kernel_owner_signing_failed", "P-256 owner signature is invalid");
  }
  if (s > P256_HALF_ORDER) s = P256_ORDER - s;
  const normalized = `0x${r.toString(16).padStart(64, "0")}${s
    .toString(16)
    .padStart(64, "0")}` as const;
  let valid = false;
  try {
    valid = p256.verify(hexToBytes(normalized), hexToBytes(hash), hexToBytes(publicKey), {
      format: "compact",
      lowS: true,
      prehash: false,
    });
  } catch {}
  if (!valid) {
    return ownerError(
      "p256_kernel_owner_signing_failed",
      "P-256 owner signature does not match the selected profile",
    );
  }
  return normalized;
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

function exactRuntime(value: unknown): void {
  const expected = KERNEL_RUNTIME_CAPABILITIES.contracts.p256Validator;
  if (
    typeof value !== "string" ||
    !BYTES.test(value) ||
    (value.length - 2) / 2 !== expected.runtimeByteLength
  ) {
    ownerError(
      "p256_kernel_owner_restoration_unreadable",
      "P-256 validator runtime evidence is unreadable",
    );
  }
  if (keccak256(value as Hex) !== expected.runtimeKeccak256) {
    ownerError(
      "p256_kernel_owner_binding_mismatch",
      "P-256 validator runtime does not match the pinned artifact",
    );
  }
}

function capturePreparedOperation(
  value: unknown,
  action: Readonly<KernelAccountActionInput>,
  accountAddress: `0x${string}`,
  factory: Readonly<PreparedFactory>,
  substrateVerified: boolean,
  deployedVerified: boolean,
): PreparedUserOperation {
  let prepared: PreparedUserOperation;
  try {
    prepared = parsePreparedUserOperation(value);
  } catch {
    return ownerError(
      "p256_kernel_owner_prepared_operation_invalid",
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
      "p256_kernel_owner_binding_mismatch",
      "Prepared UserOperation does not match the P-256 Kernel owner",
    );
  }
  if (!substrateVerified) {
    return ownerError(
      "p256_kernel_owner_restoration_required",
      "P-256 validator and precompile evidence is required before signing",
    );
  }
  if (prepared.userOperation.factory === null) {
    if (!deployedVerified) {
      return ownerError(
        "p256_kernel_owner_restoration_required",
        "Deployed P-256 Kernel owner evidence is required before signing",
      );
    }
  } else if (!sameFactory(prepared.userOperation.factory, factory)) {
    return ownerError(
      "p256_kernel_owner_binding_mismatch",
      "Prepared UserOperation factory does not match the P-256 Kernel owner",
    );
  }
  return prepared;
}

/**
 * Builds one exact raw P-256 root-owner runtime for Kernel 0.3.3 and a concrete
 * action chain. Grant authority remains all-chain; this action alone owns chainId.
 */
export async function createP256KernelOwnerRuntime(
  value: unknown,
): Promise<Readonly<P256KernelOwnerRuntime>> {
  try {
    const context: CaptureContext = new WeakSet();
    let record: Record<string, unknown>;
    try {
      record = exactRecord(
        value,
        ["profile", "chainId", "signer"],
        "P-256 Kernel owner runtime input",
        context,
        (message) => ownerError("p256_kernel_owner_input_invalid", message),
      );
    } catch (error) {
      if (error instanceof OgpP256KernelOwnerError) throw error;
      return ownerError(
        "p256_kernel_owner_input_invalid",
        "P-256 Kernel owner runtime input could not be captured safely",
      );
    }

    let profile: Readonly<KernelAccountProfile>;
    try {
      profile = captureKernelAccountProfile(record.profile, context, (message) =>
        ownerError("p256_kernel_owner_input_invalid", message),
      );
    } catch (error) {
      if (error instanceof OgpP256KernelOwnerError) throw error;
      return ownerError("p256_kernel_owner_input_invalid", "Kernel account profile is invalid");
    }
    if (profile.ownerCredential.kind !== "p256") {
      return ownerError(
        "p256_kernel_owner_input_invalid",
        "Selected Kernel owner profile is not raw P-256",
      );
    }
    let action: Readonly<KernelAccountActionInput>;
    try {
      action = createKernelAccountActionInput(profile, record.chainId);
    } catch {
      return ownerError("p256_kernel_owner_input_invalid", "Kernel action chain is invalid");
    }
    const signer = captureSigner(record.signer, profile.ownerCredential.publicKey, context);
    const client = createPublicClient({
      transport: custom({
        async request({ method }) {
          if (method === "eth_chainId") return `0x${action.chainId.toString(16)}`;
          throw new Error("P-256 owner runtime has no RPC capability");
        },
      }),
    });
    const entryPoint = Object.freeze({ version: "0.7" as const, address: entryPoint07Address });
    const validatorAddress = lowerAddress(
      KERNEL_RUNTIME_CAPABILITIES.contracts.p256Validator.address,
    );
    const [pubX, pubY] = publicKeyCoordinates(signer.publicKey);
    const enableData = encodeAbiParameters(
      [
        { name: "x", type: "uint256" },
        { name: "y", type: "uint256" },
      ],
      [pubX, pubY],
    );

    async function signHash(hash: `0x${string}`): Promise<`0x${string}`> {
      let signature: unknown;
      try {
        signature = await Reflect.apply(signer.signMessageHash, undefined, [
          Object.freeze({ hash }),
        ]);
      } catch {
        return ownerError("p256_kernel_owner_signing_failed", "P-256 owner signing failed");
      }
      return normalizeSignature(signature, hash, signer.publicKey);
    }

    const localAccount = toAccount({
      address: zeroAddress,
      async signMessage({ message }) {
        return signHash(rawHash(message));
      },
      async signTransaction() {
        return ownerError(
          "p256_kernel_owner_signing_failed",
          "P-256 owner transaction signing is outside this runtime",
        );
      },
      async signTypedData() {
        return ownerError(
          "p256_kernel_owner_signing_failed",
          "P-256 owner typed-data signing is outside this runtime",
        );
      },
    });
    const validator: KernelValidator<"P256Validator"> = {
      ...localAccount,
      supportedKernelVersions: KERNEL_V3_3,
      validatorType: "SECONDARY",
      address: validatorAddress,
      source: "P256Validator",
      getIdentifier: () => validatorAddress,
      async getEnableData() {
        return enableData;
      },
      async getNonceKey(_accountAddress, customNonceKey) {
        return customNonceKey ?? 0n;
      },
      async getStubSignature() {
        return DUMMY_SIGNATURE;
      },
      async signUserOperation(userOperation) {
        const hash = getUserOperationHash({
          userOperation: { ...userOperation, signature: "0x" } as UserOperation<"0.7">,
          entryPointAddress: entryPoint.address,
          entryPointVersion: entryPoint.version,
          chainId: action.chainId,
        });
        return signHash(hash);
      },
      async isEnabled() {
        return false;
      },
    };
    if (
      lowerAddress(validator.address) !== validatorAddress ||
      validator.getIdentifier() !== validatorAddress ||
      (await validator.getEnableData()) !== enableData
    ) {
      return ownerError(
        "p256_kernel_owner_runtime_unavailable",
        "P-256 validator adapter does not match the pinned runtime",
      );
    }

    const accountAddress = deriveKernelV3_3AccountAddress(
      { validatorAddress, enableData, accountIndex: profile.accountIndex },
      (message) => ownerError("p256_kernel_owner_runtime_unavailable", message),
    );
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
        "p256_kernel_owner_runtime_unavailable",
        "Kernel account address does not match its exact P-256 derivation",
      );
    }
    const expectedFactory = lowerAddress(
      profile.factoryRoute === "kernel_factory"
        ? KERNEL_RUNTIME_CAPABILITIES.contracts.kernel.factory
        : KERNEL_RUNTIME_CAPABILITIES.contracts.kernel.metaFactory,
    );
    const factory = Object.freeze({
      address: lowerAddress(account.factoryAddress),
      data: (await account.generateInitCode()).toLowerCase() as `0x${string}`,
    });
    if (factory.address !== expectedFactory || !BYTES.test(factory.data)) {
      return ownerError(
        "p256_kernel_owner_runtime_unavailable",
        "Kernel account factory route does not match the selected P-256 profile",
      );
    }

    let substrateVerified = false;
    let deployedVerified = false;
    let restorationAttempt = 0;

    async function restore(readsValue: unknown): Promise<Readonly<RestoredP256KernelOwner>> {
      const attempt = ++restorationAttempt;
      substrateVerified = false;
      deployedVerified = false;
      const reads = captureReads(readsValue);
      function commitVerification(deployed: boolean): void {
        if (attempt !== restorationAttempt) {
          ownerError(
            "p256_kernel_owner_restoration_unavailable",
            "P-256 restoration was superseded",
          );
        }
        substrateVerified = true;
        deployedVerified = deployed;
      }
      async function read(request: P256KernelOwnerRestorationReadRequest): Promise<unknown> {
        try {
          return await Reflect.apply(reads.read, undefined, [Object.freeze(request)]);
        } catch {
          return ownerError(
            "p256_kernel_owner_restoration_unavailable",
            "P-256 owner restoration evidence is unavailable",
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
          "p256_kernel_owner_restoration_unreadable",
          "P-256 owner restoration chain evidence is unreadable",
        );
      }
      if (observedChainId !== action.chainId) {
        return ownerError(
          "p256_kernel_owner_binding_mismatch",
          "P-256 owner restoration chain does not match the action",
        );
      }
      const validatorCode = await read({
        type: "p256_validator_code",
        chainId: action.chainId,
        validator: validatorAddress,
      });
      if (validatorCode === "0x") {
        return ownerError(
          "p256_kernel_owner_restoration_absent",
          "P-256 validator is not deployed on the action chain",
        );
      }
      exactRuntime(validatorCode);
      const precompile = KERNEL_RUNTIME_CAPABILITIES.contracts.p256Validator.p256Precompile;
      const precompileResult = await read({
        type: "p256_precompile",
        chainId: action.chainId,
        precompile: lowerAddress(precompile),
        input: PRECOMPILE_INPUT,
      });
      if (typeof precompileResult !== "string" || !HASH.test(precompileResult)) {
        return ownerError(
          "p256_kernel_owner_restoration_unreadable",
          "P-256 precompile evidence is unreadable",
        );
      }
      if (precompileResult !== PRECOMPILE_SUCCESS) {
        return ownerError(
          "p256_kernel_owner_restoration_absent",
          "P-256 precompile is unavailable on the action chain",
        );
      }

      const accountCode = await read({
        type: "account_code",
        chainId: action.chainId,
        account: accountAddress,
      });
      if (typeof accountCode !== "string" || !BYTES.test(accountCode)) {
        return ownerError(
          "p256_kernel_owner_restoration_unreadable",
          "P-256 Kernel account code evidence is unreadable",
        );
      }
      if (accountCode === "0x") {
        commitVerification(false);
        return Object.freeze({
          status: "counterfactual" as const,
          chainId: action.chainId,
          account: accountAddress,
          validator: validatorAddress,
          publicKey: signer.publicKey,
        });
      }

      const rootValidator = await read({
        type: "kernel_root_validator",
        chainId: action.chainId,
        account: accountAddress,
      });
      if (typeof rootValidator !== "string" || !ROOT_VALIDATION_ID.test(rootValidator)) {
        return ownerError(
          "p256_kernel_owner_restoration_unreadable",
          "Kernel root-validator evidence is unreadable",
        );
      }
      if (rootValidator !== `0x01${validatorAddress.slice(2)}`) {
        return ownerError(
          "p256_kernel_owner_binding_mismatch",
          "Kernel root validator does not match the selected P-256 runtime",
        );
      }
      const observedPublicKey = await read({
        type: "p256_validator_public_key",
        chainId: action.chainId,
        validator: validatorAddress,
        account: accountAddress,
      });
      if (typeof observedPublicKey !== "string" || !PUBLIC_KEY.test(observedPublicKey)) {
        return ownerError(
          "p256_kernel_owner_restoration_unreadable",
          "P-256 validator public-key evidence is unreadable",
        );
      }
      if (observedPublicKey !== signer.publicKey) {
        return ownerError(
          "p256_kernel_owner_binding_mismatch",
          "P-256 validator public key does not match the selected profile",
        );
      }
      commitVerification(true);
      return Object.freeze({
        status: "deployed" as const,
        chainId: action.chainId,
        account: accountAddress,
        validator: validatorAddress,
        publicKey: signer.publicKey,
      });
    }

    async function signPreparedUserOperation(input: unknown): Promise<`0x${string}`> {
      const prepared = capturePreparedOperation(
        input,
        action,
        accountAddress,
        factory,
        substrateVerified,
        deployedVerified,
      );
      try {
        const signature = await account.signUserOperation({
          ...asViemUserOperation(prepared),
          chainId: action.chainId,
        });
        if (!SIGNATURE.test(signature)) {
          return ownerError(
            "p256_kernel_owner_signing_failed",
            "Kernel P-256 owner signature is invalid",
          );
        }
        return signature;
      } catch (error) {
        if (error instanceof OgpP256KernelOwnerError) throw error;
        return ownerError("p256_kernel_owner_signing_failed", "P-256 owner signing failed");
      }
    }

    return Object.freeze({
      profile,
      action,
      accountAddress,
      validatorAddress,
      enableData,
      factory,
      restore,
      signPreparedUserOperation,
    });
  } catch (error) {
    if (error instanceof OgpP256KernelOwnerError) throw error;
    throw new OgpP256KernelOwnerError(
      "p256_kernel_owner_runtime_unavailable",
      "P-256 Kernel owner runtime could not be created",
    );
  }
}
