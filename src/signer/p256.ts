import { KERNEL_V3_3 } from "@zerodev/sdk/constants";
import type { KernelValidator } from "@zerodev/sdk/types";
import type { Client, Hex, SignableMessage } from "viem";
import { zeroAddress } from "viem";
import {
  entryPoint07Address,
  getUserOperationHash,
  type UserOperation,
} from "viem/account-abstraction";
import { toAccount } from "viem/accounts";
import { getChainId } from "viem/actions";
import { exactRecord } from "../internal/exact-record.js";
import {
  encodeP256ValidatorEnableData,
  isP256PublicKeyEncoding,
  normalizeP256ValidatorSignature,
} from "../internal/p256-validator.js";
import { KERNEL_RUNTIME_CAPABILITIES } from "../kernel-runtime-capabilities.js";
import { type KernelSigner, OgpKernelSignerError, type P256SigningKey } from "./types.js";

const HASH = /^0x[0-9a-f]{64}$/u;
const DUMMY_SIGNATURE =
  "0x635bc6d0f68ff895cae8a288ecf7542a6a9cd555df784b73e1e2ea7e9104b1db15e9015d280cb19527881c625fee43fd3a405d5b0d199a8c8e6589a7381209e4" as const;

function fail(code: "kernel_signer_invalid" | "kernel_signing_failed", message: string): never {
  throw new OgpKernelSignerError(code, message);
}

function captureSigningKey(value: P256SigningKey): Readonly<P256SigningKey> {
  let record: Record<string, unknown>;
  try {
    record = exactRecord(
      value,
      ["publicKey", "signMessageHash"],
      "P-256 signing key",
      new WeakSet(),
      (message) => fail("kernel_signer_invalid", message),
    );
  } catch (error) {
    if (error instanceof OgpKernelSignerError) throw error;
    return fail("kernel_signer_invalid", "P-256 signing key could not be captured safely");
  }
  if (!isP256PublicKeyEncoding(record.publicKey)) {
    return fail("kernel_signer_invalid", "P-256 public key is invalid");
  }
  if (typeof record.signMessageHash !== "function") {
    return fail("kernel_signer_invalid", "P-256 signing capability is invalid");
  }
  return Object.freeze({
    publicKey: record.publicKey,
    signMessageHash: record.signMessageHash as P256SigningKey["signMessageHash"],
  });
}

function rawHash(message: SignableMessage): `0x${string}` {
  if (
    typeof message !== "object" ||
    message === null ||
    !("raw" in message) ||
    typeof message.raw !== "string" ||
    !HASH.test(message.raw)
  ) {
    return fail("kernel_signing_failed", "P-256 validator accepts only a raw 32-byte hash");
  }
  return message.raw as `0x${string}`;
}

async function createValidator(
  client: Client,
  signer: Readonly<P256SigningKey>,
): Promise<KernelValidator<"P256Validator">> {
  const chainId = await getChainId(client);
  const address =
    KERNEL_RUNTIME_CAPABILITIES.contracts.p256Validator.address.toLowerCase() as `0x${string}`;
  const enableData = encodeP256ValidatorEnableData(signer.publicKey, (message) =>
    fail("kernel_signer_invalid", message),
  );
  const signHash = async (hash: `0x${string}`): Promise<Hex> => {
    let signature: unknown;
    try {
      signature = await Reflect.apply(signer.signMessageHash, undefined, [Object.freeze({ hash })]);
    } catch {
      return fail("kernel_signing_failed", "P-256 signing failed");
    }
    return normalizeP256ValidatorSignature(signature, hash, signer.publicKey, (message) =>
      fail("kernel_signing_failed", message),
    );
  };
  const account = toAccount({
    address: zeroAddress,
    async signMessage({ message }) {
      return signHash(rawHash(message));
    },
    async signTransaction() {
      return fail("kernel_signing_failed", "P-256 validator does not sign transactions");
    },
    async signTypedData() {
      return fail("kernel_signing_failed", "P-256 validator does not sign typed data");
    },
  });

  return {
    ...account,
    supportedKernelVersions: KERNEL_V3_3,
    validatorType: "SECONDARY",
    address,
    source: "P256Validator",
    getIdentifier: () => address,
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
        entryPointAddress: entryPoint07Address,
        entryPointVersion: "0.7",
        chainId,
      });
      return signHash(hash);
    },
    async isEnabled() {
      return false;
    },
  };
}

/** Adapt a raw P-256 signing key to leekt/P256Validator. */
export function toP256KernelSigner(
  value: P256SigningKey,
): KernelSigner<KernelValidator<"P256Validator">> {
  const signer = captureSigningKey(value);
  return Object.freeze({
    validator(client: Client) {
      return createValidator(client, signer);
    },
  });
}
