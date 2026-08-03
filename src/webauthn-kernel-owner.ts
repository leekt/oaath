import { p256 } from "@noble/curves/nist.js";
import {
  getValidatorAddress,
  PasskeyValidatorContractVersion,
  toPasskeyValidator,
} from "@zerodev/passkey-validator";
import { constants, createKernelAccount, KernelV3_1AccountAbi } from "@zerodev/sdk";
import { KERNEL_V3_3 } from "@zerodev/sdk/constants";
import { b64ToBytes, base64FromUint8Array } from "@zerodev/webauthn-key";
import {
  concatHex,
  createPublicClient,
  custom,
  encodeAbiParameters,
  encodeFunctionData,
  getContractAddress,
  hexToBytes,
  keccak256,
  pad,
  sha256,
  toHex,
  zeroAddress,
} from "viem";
import { entryPoint07Address, type UserOperation } from "viem/account-abstraction";
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

const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const PUBLIC_KEY = /^0x04[0-9a-f]{128}$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const AUTHENTICATOR_ID = /^[A-Za-z0-9_-]{1,1024}$/u;
const RP_ID = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/u;
const ROOT_VALIDATION_ID = /^0x[0-9a-f]{42}$/u;
const UINT256_MAX = (1n << 256n) - 1n;
const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const TEXT = new TextEncoder();

const ASSERTION_PARAMETERS = [
  { name: "authenticatorData", type: "bytes" },
  { name: "clientDataJSON", type: "string" },
  { name: "responseTypeLocation", type: "uint256" },
  { name: "r", type: "uint256" },
  { name: "s", type: "uint256" },
  { name: "usePrecompiled", type: "bool" },
] as const;

export type WebAuthnKernelOwnerErrorCode =
  | "webauthn_kernel_owner_input_invalid"
  | "webauthn_kernel_owner_signer_invalid"
  | "webauthn_kernel_owner_binding_mismatch"
  | "webauthn_kernel_owner_runtime_unavailable"
  | "webauthn_kernel_owner_restoration_required"
  | "webauthn_kernel_owner_restoration_absent"
  | "webauthn_kernel_owner_restoration_unavailable"
  | "webauthn_kernel_owner_restoration_unreadable"
  | "webauthn_kernel_owner_prepared_operation_invalid"
  | "webauthn_kernel_owner_signing_failed";

export class OgpWebAuthnKernelOwnerError extends Error {
  readonly code: WebAuthnKernelOwnerErrorCode;

  constructor(code: WebAuthnKernelOwnerErrorCode, message: string) {
    super(message);
    this.name = "OgpWebAuthnKernelOwnerError";
    this.code = code;
  }
}

export interface WebAuthnOwnerAssertion {
  readonly authenticatorData: `0x${string}`;
  readonly clientDataJSON: string;
  readonly responseTypeLocation: string;
  readonly r: `0x${string}`;
  readonly s: `0x${string}`;
}

export interface WebAuthnOwnerSignerCapability {
  readonly publicKey: `0x${string}`;
  readonly authenticatorId: string;
  readonly authenticatorIdHash: `0x${string}`;
  readonly rpId: string;
  readonly signMessageHash: (request: Readonly<{ hash: `0x${string}` }>) => Promise<unknown>;
}

export type WebAuthnKernelOwnerRestorationReadRequest =
  | Readonly<{ type: "chain_id"; chainId: number }>
  | Readonly<{ type: "account_code"; chainId: number; account: `0x${string}` }>
  | Readonly<{
      type: "kernel_root_validator";
      chainId: number;
      account: `0x${string}`;
    }>
  | Readonly<{
      type: "runtime_code";
      chainId: number;
      contract: "webauthn_validator" | "p256_verifier";
      address: `0x${string}`;
    }>
  | Readonly<{
      type: "webauthn_validator_initialized";
      chainId: number;
      validator: `0x${string}`;
      account: `0x${string}`;
    }>
  | Readonly<{
      type: "webauthn_validator_public_key";
      chainId: number;
      validator: `0x${string}`;
      account: `0x${string}`;
    }>;

export interface WebAuthnKernelOwnerRestorationReadCapability {
  readonly read: (request: WebAuthnKernelOwnerRestorationReadRequest) => Promise<unknown>;
}

export interface RestoredWebAuthnKernelOwner {
  readonly status: "deployed";
  readonly chainId: number;
  readonly account: `0x${string}`;
  readonly validator: `0x${string}`;
  readonly publicKey: `0x${string}`;
  readonly authenticatorIdHash: `0x${string}`;
}

export interface WebAuthnKernelOwnerRuntime {
  readonly profile: Readonly<KernelAccountProfile>;
  readonly action: Readonly<KernelAccountActionInput>;
  readonly accountAddress: `0x${string}`;
  readonly validatorAddress: `0x${string}`;
  readonly factory: Readonly<PreparedFactory>;
  readonly restore: (reads: unknown) => Promise<Readonly<RestoredWebAuthnKernelOwner>>;
  readonly signPreparedUserOperation: (value: unknown) => Promise<`0x${string}`>;
}

interface CapturedSigner {
  readonly publicKey: `0x${string}`;
  readonly authenticatorId: string;
  readonly authenticatorIdHash: `0x${string}`;
  readonly rpId: string;
  readonly signMessageHash: WebAuthnOwnerSignerCapability["signMessageHash"];
}

function ownerError(code: WebAuthnKernelOwnerErrorCode, message: string): never {
  throw new OgpWebAuthnKernelOwnerError(code, message);
}

function lowerAddress(value: string): `0x${string}` {
  return value.toLowerCase() as `0x${string}`;
}

function captureSigner(
  value: unknown,
  expectedPublicKey: `0x${string}`,
  expectedAuthenticatorIdHash: `0x${string}`,
  context: CaptureContext,
): CapturedSigner {
  let record: Record<string, unknown>;
  try {
    record = exactRecord(
      value,
      ["publicKey", "authenticatorId", "authenticatorIdHash", "rpId", "signMessageHash"],
      "WebAuthn owner signer capability",
      context,
      (message) => ownerError("webauthn_kernel_owner_signer_invalid", message),
    );
  } catch (error) {
    if (error instanceof OgpWebAuthnKernelOwnerError) throw error;
    ownerError(
      "webauthn_kernel_owner_signer_invalid",
      "WebAuthn owner signer capability could not be captured safely",
    );
  }
  if (record.publicKey !== expectedPublicKey || !PUBLIC_KEY.test(String(record.publicKey))) {
    ownerError(
      "webauthn_kernel_owner_binding_mismatch",
      "WebAuthn owner signer public key does not match the selected profile",
    );
  }
  if (
    record.authenticatorIdHash !== expectedAuthenticatorIdHash ||
    typeof record.authenticatorIdHash !== "string" ||
    !HASH.test(record.authenticatorIdHash)
  ) {
    return ownerError(
      "webauthn_kernel_owner_binding_mismatch",
      "WebAuthn owner signer authenticator does not match the selected profile",
    );
  }
  if (
    typeof record.authenticatorId !== "string" ||
    !AUTHENTICATOR_ID.test(record.authenticatorId)
  ) {
    return ownerError(
      "webauthn_kernel_owner_signer_invalid",
      "WebAuthn owner authenticator identifier is invalid",
    );
  }
  let authenticatorBytes: Uint8Array;
  try {
    authenticatorBytes = b64ToBytes(record.authenticatorId);
  } catch {
    return ownerError(
      "webauthn_kernel_owner_signer_invalid",
      "WebAuthn owner authenticator identifier is invalid",
    );
  }
  if (
    base64FromUint8Array(authenticatorBytes, true) !== record.authenticatorId ||
    keccak256(toHex(authenticatorBytes)) !== expectedAuthenticatorIdHash
  ) {
    return ownerError(
      "webauthn_kernel_owner_binding_mismatch",
      "WebAuthn owner authenticator identifier does not match the selected profile",
    );
  }
  if (typeof record.rpId !== "string" || !RP_ID.test(record.rpId) || record.rpId.includes("..")) {
    return ownerError("webauthn_kernel_owner_signer_invalid", "WebAuthn owner RP ID is invalid");
  }
  if (typeof record.signMessageHash !== "function") {
    return ownerError(
      "webauthn_kernel_owner_signer_invalid",
      "WebAuthn owner signing capability is invalid",
    );
  }
  return Object.freeze({
    publicKey: record.publicKey as `0x${string}`,
    authenticatorId: record.authenticatorId,
    authenticatorIdHash: record.authenticatorIdHash as `0x${string}`,
    rpId: record.rpId,
    signMessageHash: record.signMessageHash as WebAuthnOwnerSignerCapability["signMessageHash"],
  });
}

function captureReads(value: unknown): WebAuthnKernelOwnerRestorationReadCapability {
  let record: Record<string, unknown>;
  try {
    record = exactRecord(
      value,
      ["read"],
      "WebAuthn owner restoration read capability",
      new WeakSet(),
      (message) => ownerError("webauthn_kernel_owner_restoration_unreadable", message),
    );
  } catch (error) {
    if (error instanceof OgpWebAuthnKernelOwnerError) throw error;
    return ownerError(
      "webauthn_kernel_owner_restoration_unreadable",
      "WebAuthn owner restoration reader could not be captured safely",
    );
  }
  if (typeof record.read !== "function") {
    return ownerError(
      "webauthn_kernel_owner_restoration_unreadable",
      "WebAuthn owner restoration reader is invalid",
    );
  }
  return Object.freeze({
    read: record.read as WebAuthnKernelOwnerRestorationReadCapability["read"],
  });
}

function rawHash(value: unknown): `0x${string}` {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return ownerError(
      "webauthn_kernel_owner_signing_failed",
      "WebAuthn signing request is invalid",
    );
  }
  const record = exactRecord(value, ["raw"], "WebAuthn signing message", new WeakSet(), () =>
    ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn signing request is invalid"),
  );
  if (typeof record.raw !== "string" || !HASH.test(record.raw)) {
    return ownerError(
      "webauthn_kernel_owner_signing_failed",
      "WebAuthn signing request is invalid",
    );
  }
  return record.raw as `0x${string}`;
}

function uint256(value: unknown): bigint {
  if (typeof value !== "string" || !DECIMAL_UINT.test(value)) {
    return ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn assertion is invalid");
  }
  const parsed = BigInt(value);
  if (parsed > UINT256_MAX) {
    return ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn assertion is invalid");
  }
  return parsed;
}

function matchesAt(source: Uint8Array, expected: Uint8Array, offset: number): boolean {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset + expected.length > source.length) {
    return false;
  }
  return expected.every((byte, index) => source[offset + index] === byte);
}

function encodeAssertion(
  value: unknown,
  hash: `0x${string}`,
  signer: CapturedSigner,
  context: CaptureContext,
): `0x${string}` {
  let record: Record<string, unknown>;
  try {
    record = exactRecord(
      value,
      ["authenticatorData", "clientDataJSON", "responseTypeLocation", "r", "s"],
      "WebAuthn owner assertion",
      context,
      () => ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn assertion is invalid"),
    );
  } catch (error) {
    if (error instanceof OgpWebAuthnKernelOwnerError) throw error;
    return ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn assertion is invalid");
  }
  if (
    typeof record.authenticatorData !== "string" ||
    !BYTES.test(record.authenticatorData) ||
    record.authenticatorData.length < 76 ||
    record.authenticatorData.length > 2050 ||
    typeof record.clientDataJSON !== "string"
  ) {
    return ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn assertion is invalid");
  }
  const clientData = TEXT.encode(record.clientDataJSON);
  if (clientData.length === 0 || clientData.length > 4096) {
    return ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn assertion is invalid");
  }
  const responseTypeLocation = uint256(record.responseTypeLocation);
  if (responseTypeLocation > BigInt(Number.MAX_SAFE_INTEGER)) {
    return ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn assertion is invalid");
  }
  if (
    typeof record.r !== "string" ||
    !HASH.test(record.r) ||
    typeof record.s !== "string" ||
    !HASH.test(record.s)
  ) {
    return ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn assertion is invalid");
  }
  const r = BigInt(record.r);
  const s = BigInt(record.s);
  if (r === 0n || r >= P256_ORDER || s === 0n || s > P256_ORDER / 2n) {
    return ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn assertion is invalid");
  }
  const authenticatorData = record.authenticatorData as `0x${string}`;
  if (authenticatorData.slice(0, 66) !== sha256(toHex(TEXT.encode(signer.rpId)))) {
    return ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn assertion is invalid");
  }
  const flags = Number.parseInt(authenticatorData.slice(66, 68), 16);
  if (
    (flags & 0x01) === 0 ||
    (flags & 0x04) === 0 ||
    ((flags & 0x08) === 0 && (flags & 0x10) !== 0)
  ) {
    return ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn assertion is invalid");
  }
  const challenge = base64FromUint8Array(hexToBytes(hash), true);
  if (
    !matchesAt(clientData, TEXT.encode(`"challenge":"${challenge}"`), 23) ||
    !matchesAt(clientData, TEXT.encode('"type":"webauthn.get"'), Number(responseTypeLocation))
  ) {
    return ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn assertion is invalid");
  }
  try {
    const parsed = JSON.parse(record.clientDataJSON) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    const client = parsed as Record<string, unknown>;
    if (client.type !== "webauthn.get" || client.challenge !== challenge) throw new Error();
  } catch {
    return ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn assertion is invalid");
  }
  const messageHash = sha256(concatHex([authenticatorData, sha256(toHex(clientData))]));
  let verified = false;
  try {
    verified = p256.verify(
      `${record.r.slice(2)}${record.s.slice(2)}`,
      messageHash.slice(2),
      signer.publicKey.slice(2),
      { lowS: true },
    );
  } catch {}
  if (!verified) {
    return ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn assertion is invalid");
  }
  return encodeAbiParameters(ASSERTION_PARAMETERS, [
    authenticatorData,
    record.clientDataJSON,
    responseTypeLocation,
    r,
    s,
    false,
  ]);
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

function exactRuntime(
  value: unknown,
  expected: Readonly<{ runtimeKeccak256: `0x${string}`; runtimeByteLength: number }>,
): void {
  if (
    typeof value !== "string" ||
    !BYTES.test(value) ||
    (value.length - 2) / 2 !== expected.runtimeByteLength
  ) {
    ownerError(
      "webauthn_kernel_owner_restoration_unreadable",
      "WebAuthn dependency runtime evidence is unreadable",
    );
  }
  if (keccak256(value as `0x${string}`) !== expected.runtimeKeccak256) {
    ownerError(
      "webauthn_kernel_owner_binding_mismatch",
      "WebAuthn dependency runtime does not match the pinned artifact",
    );
  }
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
      "webauthn_kernel_owner_prepared_operation_invalid",
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
      "webauthn_kernel_owner_binding_mismatch",
      "Prepared UserOperation does not match the WebAuthn Kernel owner",
    );
  }
  if (prepared.userOperation.factory === null) {
    if (!deployedVerified) {
      return ownerError(
        "webauthn_kernel_owner_restoration_required",
        "Deployed WebAuthn Kernel owner evidence is required before signing",
      );
    }
  } else if (!sameFactory(prepared.userOperation.factory, factory)) {
    return ownerError(
      "webauthn_kernel_owner_binding_mismatch",
      "Prepared UserOperation factory does not match the WebAuthn Kernel owner",
    );
  }
  return prepared;
}

function deriveAccountAddress(
  validatorAddress: `0x${string}`,
  enableData: `0x${string}`,
  accountIndex: string,
): `0x${string}` {
  const sdk = constants.KernelVersionToAddressesMap[KERNEL_V3_3];
  const manifest = KERNEL_RUNTIME_CAPABILITIES.contracts.kernel;
  if (
    typeof sdk.metaFactoryAddress !== "string" ||
    lowerAddress(sdk.accountImplementationAddress) !== lowerAddress(manifest.implementation) ||
    lowerAddress(sdk.factoryAddress) !== lowerAddress(manifest.factory) ||
    lowerAddress(sdk.metaFactoryAddress) !== lowerAddress(manifest.metaFactory) ||
    typeof sdk.initCodeHash !== "string" ||
    !HASH.test(sdk.initCodeHash)
  ) {
    return ownerError(
      "webauthn_kernel_owner_runtime_unavailable",
      "Kernel account derivation does not match the pinned runtime",
    );
  }
  const initializationData = encodeFunctionData({
    abi: KernelV3_1AccountAbi,
    functionName: "initialize",
    args: [
      pad(concatHex(["0x01", validatorAddress]), { size: 21, dir: "right" }),
      zeroAddress,
      enableData,
      "0x",
      [],
    ],
  });
  const initCodeHash = sdk.initCodeHash as `0x${string}`;
  return lowerAddress(
    getContractAddress({
      bytecodeHash: initCodeHash,
      from: sdk.factoryAddress,
      opcode: "CREATE2",
      salt: keccak256(concatHex([initializationData, toHex(BigInt(accountIndex), { size: 32 })])),
    }),
  );
}

/**
 * Builds one exact patched WebAuthn root-owner runtime for a concrete action chain.
 * Grant authority remains all-chain; this action alone owns chainId.
 */
export async function createWebAuthnKernelOwnerRuntime(
  value: unknown,
): Promise<Readonly<WebAuthnKernelOwnerRuntime>> {
  try {
    const context: CaptureContext = new WeakSet();
    let record: Record<string, unknown>;
    try {
      record = exactRecord(
        value,
        ["profile", "chainId", "signer"],
        "WebAuthn Kernel owner runtime input",
        context,
        (message) => ownerError("webauthn_kernel_owner_input_invalid", message),
      );
    } catch (error) {
      if (error instanceof OgpWebAuthnKernelOwnerError) throw error;
      return ownerError(
        "webauthn_kernel_owner_input_invalid",
        "WebAuthn Kernel owner runtime input could not be captured safely",
      );
    }
    let profile: Readonly<KernelAccountProfile>;
    try {
      profile = captureKernelAccountProfile(record.profile, context, (message) =>
        ownerError("webauthn_kernel_owner_input_invalid", message),
      );
    } catch (error) {
      if (error instanceof OgpWebAuthnKernelOwnerError) throw error;
      return ownerError("webauthn_kernel_owner_input_invalid", "Kernel account profile is invalid");
    }
    if (profile.ownerCredential.kind !== "webauthn") {
      return ownerError(
        "webauthn_kernel_owner_input_invalid",
        "Selected Kernel owner profile is not WebAuthn",
      );
    }
    let action: Readonly<KernelAccountActionInput>;
    try {
      action = createKernelAccountActionInput(profile, record.chainId);
    } catch {
      return ownerError("webauthn_kernel_owner_input_invalid", "Kernel action chain is invalid");
    }
    const signer = captureSigner(
      record.signer,
      profile.ownerCredential.publicKey,
      profile.ownerCredential.authenticatorIdHash,
      context,
    );
    const chainId = action.chainId;
    const client = createPublicClient({
      transport: custom({
        async request({ method }) {
          if (method === "eth_chainId") return `0x${chainId.toString(16)}`;
          throw new Error("WebAuthn owner runtime has no RPC capability");
        },
      }),
    });
    const entryPoint = Object.freeze({ version: "0.7" as const, address: entryPoint07Address });
    const validatorAddress = lowerAddress(
      getValidatorAddress(entryPoint, KERNEL_V3_3, PasskeyValidatorContractVersion.V0_0_3_PATCHED),
    );
    if (
      validatorAddress !==
      lowerAddress(KERNEL_RUNTIME_CAPABILITIES.contracts.webauthnValidator.address)
    ) {
      return ownerError(
        "webauthn_kernel_owner_runtime_unavailable",
        "WebAuthn validator address does not match the pinned patched runtime",
      );
    }
    const [pubX, pubY] = [
      BigInt(`0x${signer.publicKey.slice(4, 68)}`),
      BigInt(`0x${signer.publicKey.slice(68)}`),
    ];
    const validator = await toPasskeyValidator(client, {
      webAuthnKey: {
        pubX,
        pubY,
        authenticatorId: signer.authenticatorId,
        authenticatorIdHash: signer.authenticatorIdHash,
        rpID: signer.rpId,
        async signMessageCallback(message) {
          const hash = rawHash(message);
          let assertion: unknown;
          try {
            assertion = await Reflect.apply(signer.signMessageHash, undefined, [
              Object.freeze({ hash }),
            ]);
          } catch {
            return ownerError(
              "webauthn_kernel_owner_signing_failed",
              "WebAuthn owner signing failed",
            );
          }
          return encodeAssertion(assertion, hash, signer, context);
        },
      },
      entryPoint,
      kernelVersion: KERNEL_V3_3,
      validatorContractVersion: PasskeyValidatorContractVersion.V0_0_3_PATCHED,
    });
    if (lowerAddress(validator.address) !== validatorAddress) {
      return ownerError(
        "webauthn_kernel_owner_runtime_unavailable",
        "WebAuthn validator address does not match the pinned patched runtime",
      );
    }
    const enableData = (await validator.getEnableData()).toLowerCase() as `0x${string}`;
    const accountAddress = deriveAccountAddress(validatorAddress, enableData, profile.accountIndex);
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
        "webauthn_kernel_owner_runtime_unavailable",
        "Kernel account address does not match its exact WebAuthn derivation",
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
        "webauthn_kernel_owner_runtime_unavailable",
        "Kernel account factory route does not match the selected WebAuthn profile",
      );
    }

    let deployedVerified = false;

    async function restore(readsValue: unknown): Promise<Readonly<RestoredWebAuthnKernelOwner>> {
      const reads = captureReads(readsValue);
      async function read(request: WebAuthnKernelOwnerRestorationReadRequest): Promise<unknown> {
        try {
          return await Reflect.apply(reads.read, undefined, [Object.freeze(request)]);
        } catch {
          return ownerError(
            "webauthn_kernel_owner_restoration_unavailable",
            "WebAuthn owner restoration evidence is unavailable",
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
          "webauthn_kernel_owner_restoration_unreadable",
          "WebAuthn owner restoration chain evidence is unreadable",
        );
      }
      if (observedChainId !== action.chainId) {
        return ownerError(
          "webauthn_kernel_owner_binding_mismatch",
          "WebAuthn owner restoration chain does not match the action",
        );
      }
      const code = await read({
        type: "account_code",
        chainId: action.chainId,
        account: accountAddress,
      });
      if (typeof code !== "string" || !BYTES.test(code)) {
        return ownerError(
          "webauthn_kernel_owner_restoration_unreadable",
          "WebAuthn Kernel account code evidence is unreadable",
        );
      }
      if (code === "0x") {
        return ownerError(
          "webauthn_kernel_owner_restoration_absent",
          "WebAuthn Kernel account is not deployed",
        );
      }
      const rootValidator = await read({
        type: "kernel_root_validator",
        chainId: action.chainId,
        account: accountAddress,
      });
      if (typeof rootValidator !== "string" || !ROOT_VALIDATION_ID.test(rootValidator)) {
        return ownerError(
          "webauthn_kernel_owner_restoration_unreadable",
          "Kernel root-validator evidence is unreadable",
        );
      }
      if (rootValidator !== `0x01${validatorAddress.slice(2)}`) {
        return ownerError(
          "webauthn_kernel_owner_binding_mismatch",
          "Kernel root validator does not match the patched WebAuthn runtime",
        );
      }
      const contracts = KERNEL_RUNTIME_CAPABILITIES.contracts;
      exactRuntime(
        await read({
          type: "runtime_code",
          chainId: action.chainId,
          contract: "webauthn_validator",
          address: validatorAddress,
        }),
        contracts.webauthnValidator,
      );
      exactRuntime(
        await read({
          type: "runtime_code",
          chainId: action.chainId,
          contract: "p256_verifier",
          address: lowerAddress(contracts.p256Verifier.address),
        }),
        contracts.p256Verifier,
      );
      const initialized = await read({
        type: "webauthn_validator_initialized",
        chainId: action.chainId,
        validator: validatorAddress,
        account: accountAddress,
      });
      if (typeof initialized !== "boolean") {
        return ownerError(
          "webauthn_kernel_owner_restoration_unreadable",
          "WebAuthn validator initialization evidence is unreadable",
        );
      }
      if (!initialized) {
        return ownerError(
          "webauthn_kernel_owner_restoration_absent",
          "WebAuthn validator is not initialized for the Kernel account",
        );
      }
      const publicKey = await read({
        type: "webauthn_validator_public_key",
        chainId: action.chainId,
        validator: validatorAddress,
        account: accountAddress,
      });
      if (typeof publicKey !== "string" || !PUBLIC_KEY.test(publicKey)) {
        return ownerError(
          "webauthn_kernel_owner_restoration_unreadable",
          "WebAuthn validator public-key evidence is unreadable",
        );
      }
      if (publicKey !== signer.publicKey) {
        return ownerError(
          "webauthn_kernel_owner_binding_mismatch",
          "WebAuthn validator public key does not match the selected profile",
        );
      }
      deployedVerified = true;
      return Object.freeze({
        status: "deployed" as const,
        chainId: action.chainId,
        account: accountAddress,
        validator: validatorAddress,
        publicKey: signer.publicKey,
        authenticatorIdHash: signer.authenticatorIdHash,
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
        if (!BYTES.test(signature) || signature === "0x") {
          return ownerError(
            "webauthn_kernel_owner_signing_failed",
            "Kernel WebAuthn owner signature is invalid",
          );
        }
        return signature.toLowerCase() as `0x${string}`;
      } catch (error) {
        if (error instanceof OgpWebAuthnKernelOwnerError) throw error;
        return ownerError("webauthn_kernel_owner_signing_failed", "WebAuthn owner signing failed");
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
    if (error instanceof OgpWebAuthnKernelOwnerError) throw error;
    throw new OgpWebAuthnKernelOwnerError(
      "webauthn_kernel_owner_runtime_unavailable",
      "WebAuthn Kernel owner runtime could not be created",
    );
  }
}
