/**
 * ECDSA (secp256k1) KeyProfile. Owns public material, signing normalization,
 * and local verification only.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type CaptureContext, captureRecord } from "@oaath/protocol";
import { hashMessage, recoverAddress } from "viem";
import type { KernelDeployment } from "../deployment/profile.js";
import {
  exactInput,
  inputAddress,
  inputCapability,
  inputInvalid,
  invokeCapability,
  isBytesOfLength,
  runtimeFail,
} from "../internal.js";
import { exactKernelDeployment } from "../modules.js";
import type { KeyProfile } from "../types.js";

/** 65-byte placeholder with a canonical low-s component; used for gas estimation only. */
const DUMMY_SIGNATURE = `0x${"11".repeat(32)}${"22".repeat(32)}1c` as const;

export interface EcdsaSignRequest {
  readonly hash: `0x${string}`;
}

/** The minimal viem LocalAccount surface consumed by this key profile. */
export interface EcdsaKeyAccount {
  readonly address: `0x${string}`;
  readonly sign: (request: EcdsaSignRequest) => Promise<unknown>;
}

export interface EcdsaKeyInput {
  readonly account: EcdsaKeyAccount;
  /**
   * Caller-bound ERC-7579 ECDSA validator module. Kernel v4 pins no ECDSA
   * validator deployment, and bindKernelV4Account proves the module has code on
   * the action chain before an account address depends on it.
   */
  readonly validator: `0x${string}`;
}

/** The connected viem WalletClient surface; private-key custody remains with the wallet. */
export interface EcdsaWalletClient {
  readonly account?: Readonly<{ address: `0x${string}` }> | undefined;
  readonly signMessage: (
    request: Readonly<{
      account: `0x${string}`;
      message: Readonly<{ raw: `0x${string}` }>;
    }>,
  ) => Promise<unknown>;
}

export interface EcdsaWalletKeyInput {
  readonly wallet: EcdsaWalletClient;
  /** The validator must accept EIP-191 signatures, as Kernel v3.3's ECDSA validator does. */
  readonly validator: `0x${string}`;
}

/** One personal_sign prompt over the operation digest; no account request or signing retry. */
export function ecdsaWalletKey(value: EcdsaWalletKeyInput): Readonly<KeyProfile> {
  const context: CaptureContext = new WeakSet();
  const record = exactInput(value, ["wallet", "validator"], "ECDSA wallet key", context);
  const validator = inputAddress(record.validator, "ECDSA key validator");
  const wallet = captureRecord(record.wallet, "ECDSA wallet", context, inputInvalid);
  const account = captureRecord(wallet.account, "ECDSA wallet account", context, inputInvalid);
  const owner = inputAddress(account.address, "ECDSA wallet address");
  const signMessage = inputCapability<EcdsaWalletClient["signMessage"]>(
    wallet.signMessage,
    "ECDSA wallet signMessage capability",
  );
  return profile(
    owner,
    validator,
    ({ hash }) =>
      signMessage(Object.freeze({ account: owner, message: Object.freeze({ raw: hash }) })),
    (hash) => hashMessage({ raw: hash }),
  );
}

export function ecdsaKey(value: EcdsaKeyInput): Readonly<KeyProfile> {
  const context: CaptureContext = new WeakSet();
  const record = exactInput(value, ["account", "validator"], "ECDSA key", context);
  const validator = inputAddress(record.validator, "ECDSA key validator");
  // Exactness stops at the viem account: it legitimately carries extra signing
  // members. Only address and sign are captured and used.
  const account = captureRecord(record.account, "ECDSA key account", context, inputInvalid);
  const owner = inputAddress(account.address, "ECDSA key address");
  const sign = inputCapability<EcdsaKeyAccount["sign"]>(account.sign, "ECDSA key sign capability");

  return profile(owner, validator, sign, (hash) => hash);
}

function profile(
  owner: `0x${string}`,
  validator: `0x${string}`,
  sign: EcdsaKeyAccount["sign"],
  signatureHash: (hash: `0x${string}`) => `0x${string}`,
): Readonly<KeyProfile> {
  async function verify(hash: `0x${string}`, signature: `0x${string}`): Promise<boolean> {
    if (!isBytesOfLength(signature, 65)) return false;
    try {
      return (
        (await recoverAddress({ hash: signatureHash(hash), signature })).toLowerCase() === owner
      );
    } catch {
      return false;
    }
  }

  return Object.freeze({
    kind: "ecdsa" as const,
    publicMaterial: owner,
    resolveValidator: (deployment: Readonly<KernelDeployment>) => {
      exactKernelDeployment(deployment);
      return validator;
    },
    // A reviewed kind installs the permission signer module pinned to its kind.
    // signerModule stays null: reviewed kinds resolve their signer from the
    // pinned registry, and the capture layer refuses a self-bound module.
    // The self-verification inside this profile's own sign() is deliberate
    // duplication of the capture layer's check — this factory is publicly
    // exported, so direct callers need the guarantee too. Do not "clean it up".
    signerModule: null,
    dummySignature: DUMMY_SIGNATURE,
    async sign(hash: `0x${string}`): Promise<`0x${string}`> {
      const produced = await invokeCapability(
        sign,
        Object.freeze({ hash }),
        "ECDSA key signing failed",
      );
      if (typeof produced !== "string" || !isBytesOfLength(produced.toLowerCase(), 65)) {
        return runtimeFail("kernel_runtime_signature_invalid", "ECDSA signature is invalid");
      }
      const signature = produced.toLowerCase() as `0x${string}`;
      if (!(await verify(hash, signature))) {
        return runtimeFail(
          "kernel_runtime_signature_invalid",
          "ECDSA signature does not match the bound key",
        );
      }
      return signature;
    },
    verify,
  });
}
