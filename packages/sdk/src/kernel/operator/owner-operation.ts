/**
 * One exact owner operation for a factory-derived or an existing (imported)
 * Kernel 0.4.0 account: the request its root reviews and signs offline, and
 * the verification a holder of the signed artifact runs before submitting it.
 * Nothing is read from a chain: the caller states the nonce, gas, fees,
 * paymaster, and whether a derived account is deployed; an existing account is
 * deployed and carries no factory. Submission and observation stay with the
 * caller.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  isKernelExistingAccountProfile,
  type KernelDerivedAccountProfile,
  type KernelExistingAccountProfile,
  OAATH_OWNER_OPERATION_REQUEST_VERSION,
  OAATH_SIGNED_OWNER_OPERATION_VERSION,
  type OwnerCredentialProfile,
  type OwnerOperationRequest,
  ownerUserOperationForCetane,
  parseKernelAccountProfile,
  parseOwnerOperationRequest,
  parseSignedOwnerOperation,
  type SignedOwnerOperation,
} from "@oaath/protocol";
import type { Hex } from "cetane";
import { toRpc } from "cetane/execution/erc4337";
import {
  deriveKernelV4RootAccountAddress,
  encodeKernelV4Execution,
  encodeKernelV4FactoryDeploy,
  encodeKernelV4Nonce,
  encodeKernelV4NonceKey,
  KERNEL_V4_ENTRY_POINT_V09,
  KERNEL_V4_FACTORY_V09,
  kernelV4Deployment,
} from "../../kernel-v4.js";
import { type PreparedPaymaster, prepareUserOperation } from "../../prepared-user-operation.js";
import { ECDSA_VALIDATOR } from "../deployment/v33.js";
import { captureKeyProfile, exactInput, inputInvalid, runtimeFail } from "../internal.js";
import { credentialKey } from "../key/credential.js";
import { ecdsaKey, ecdsaWalletKey } from "../key/ecdsa.js";
import { p256Key } from "../key/p256.js";
import { webauthnVerifier } from "../key/webauthn.js";
import type { KernelCall, KernelUserOperationGas, KeyProfile } from "../types.js";
import { ownerOperator } from "./owner.js";

export interface PrepareOwnerOperationInput {
  /**
   * The factory-derived or existing Kernel 0.4.0 account profile; its owner
   * credential is the signing root.
   */
  readonly account: Readonly<KernelDerivedAccountProfile | KernelExistingAccountProfile>;
  readonly chainId: number;
  /**
   * `false` adds the Kernel factory deployment, so the first operation deploys
   * a derived account. An existing account is deployed: always `true`.
   */
  readonly deployed: boolean;
  readonly calls: readonly Readonly<KernelCall>[];
  /** Root-validation uint16 lane and that lane's next EntryPoint sequence on this chain. */
  readonly nonce: Readonly<{ lane: string; sequence: string }>;
  readonly gas: Readonly<KernelUserOperationGas>;
  /** Optional sponsorship; its fields are part of the signed hash. */
  readonly paymaster?: Readonly<PreparedPaymaster> | null;
}

export interface PreparedOwnerOperation {
  readonly request: Readonly<OwnerOperationRequest>;
  /**
   * Asks the root for its one signature over `request.userOperationHash`. A
   * key of another credential is refused before it is asked. Submits nothing.
   */
  sign(root: Readonly<KeyProfile>): Promise<Readonly<SignedOwnerOperation>>;
}

/** The relying party a WebAuthn root's assertion must name. */
export interface OwnerOperationRelyingParty {
  readonly rpId: string;
  readonly origin: string;
}

export interface VerifiedOwnerOperation {
  readonly signed: Readonly<SignedOwnerOperation>;
  readonly entryPoint: `0x${string}`;
  /** The signed operation in ERC-4337 JSON-RPC form, for `eth_sendUserOperation`. */
  readonly userOperation: Readonly<Record<string, Hex>>;
}

function rootValidator(credential: Readonly<OwnerCredentialProfile>): `0x${string}` | null {
  return credential.kind === "ecdsa" ? ECDSA_VALIDATOR : null;
}

/** An existing account's own address. */
function existingAddress(account: Readonly<OwnerOperationRequest["account"]>): `0x${string}` {
  return (account as Readonly<KernelExistingAccountProfile>).address as `0x${string}`;
}

/** The single root package the account was derived from, for the request's chain. */
function rootPackages(account: Readonly<KernelDerivedAccountProfile>, chainId: number) {
  const key = credentialKey({
    credential: account.ownerCredential,
    validator: rootValidator(account.ownerCredential),
  });
  return ownerOperator({ key }).resolvePackages(kernelV4Deployment(chainId));
}

/**
 * Prepares the exact request for one owner operation. The account address and
 * factory deployment are derived offline from the profile, so the same input
 * always yields the same request and hash.
 */
export function prepareOwnerOperation(
  value: PrepareOwnerOperationInput,
): Readonly<PreparedOwnerOperation> {
  const context = new WeakSet<object>();
  const keys = ["account", "chainId", "deployed", "calls", "nonce", "gas"];
  if (value !== null && typeof value === "object" && Object.hasOwn(value, "paymaster"))
    keys.push("paymaster");
  const input = exactInput(value, keys, "owner operation", context);
  if (typeof input.deployed !== "boolean") return inputInvalid("owner operation state is invalid");
  if (typeof input.chainId !== "number") return inputInvalid("owner operation chain is invalid");
  const nonce = exactInput(input.nonce, ["lane", "sequence"], "owner operation nonce", context);
  const account = parseKernelAccountProfile(input.account);
  const existing = isKernelExistingAccountProfile(account);
  if (existing ? account.kernelVersion !== "0.4.0" : account.factoryRoute !== "kernel_factory")
    return runtimeFail(
      "kernel_runtime_unsupported",
      "owner operations require a factory-derived or an existing Kernel 0.4.0 account",
    );
  if (existing && !input.deployed)
    return inputInvalid("an existing account is deployed; nothing deploys it");
  const accountInput = existing
    ? null
    : {
        initialPackages: rootPackages(account, input.chainId),
        accountIndex: account.accountIndex,
      };
  const gas = exactInput(
    input.gas,
    [
      "callGasLimit",
      "verificationGasLimit",
      "preVerificationGas",
      "maxFeePerGas",
      "maxPriorityFeePerGas",
    ],
    "owner operation gas",
    context,
  );
  const calls = input.calls as readonly Readonly<KernelCall>[];
  // The prepared operation owns field capture and the hash; the protocol owner
  // then re-proves callData against the reviewed calls and that hash.
  const prepared = prepareUserOperation({
    kind: "execution",
    grantId: "owner",
    chainId: input.chainId,
    entryPoint: { version: "0.9", address: KERNEL_V4_ENTRY_POINT_V09 },
    userOperation: {
      sender: accountInput
        ? deriveKernelV4RootAccountAddress(accountInput)
        : existingAddress(account),
      nonce: encodeKernelV4Nonce({
        key: encodeKernelV4NonceKey({
          mode: "standard",
          validation: { kind: "root" },
          nonceKey: nonce.lane as string,
        }),
        sequence: nonce.sequence as string,
      }),
      callData: encodeKernelV4Execution({ calls }),
      ...gas,
      factory:
        input.deployed || !accountInput
          ? null
          : { address: KERNEL_V4_FACTORY_V09, data: encodeKernelV4FactoryDeploy(accountInput) },
      paymaster: input.paymaster ?? null,
    },
  });
  const request = parseOwnerOperationRequest({
    version: OAATH_OWNER_OPERATION_REQUEST_VERSION,
    kind: "kernel-owner-operation",
    account,
    chainId: prepared.chainId,
    entryPoint: prepared.entryPoint.address,
    calls,
    userOperation: prepared.userOperation,
    userOperationHash: prepared.userOperationHash,
  });
  const root = credentialKey({
    credential: request.account.ownerCredential,
    validator: rootValidator(request.account.ownerCredential),
  });
  return Object.freeze({
    request,
    async sign(value: Readonly<KeyProfile>) {
      const key = captureKeyProfile(value);
      if (key.kind !== root.kind || key.publicMaterial !== root.publicMaterial)
        return runtimeFail(
          "kernel_runtime_binding_mismatch",
          "owner operation key does not match the account's root credential",
        );
      const signature = await key.sign(request.userOperationHash);
      return parseSignedOwnerOperation({
        version: OAATH_SIGNED_OWNER_OPERATION_VERSION,
        request,
        signature,
      });
    },
  });
}

const refuse = async (): Promise<never> =>
  runtimeFail("kernel_runtime_signing_failed", "a verifier cannot sign");

/** Whether `signature` is the root's, under every encoding its validator accepts. */
async function rootSigned(
  credential: Readonly<OwnerCredentialProfile>,
  hash: `0x${string}`,
  signature: `0x${string}`,
  relyingParty: Readonly<OwnerOperationRelyingParty> | undefined,
): Promise<boolean> {
  if (credential.kind === "ecdsa") {
    // The ECDSA validator accepts the raw digest or its EIP-191 message hash.
    const account = { address: credential.address, sign: refuse };
    const wallet = { account: { address: credential.address }, signMessage: refuse };
    return (
      (await ecdsaKey({ account, validator: ECDSA_VALIDATOR }).verify(hash, signature)) ||
      (await ecdsaWalletKey({ wallet, validator: ECDSA_VALIDATOR }).verify(hash, signature))
    );
  }
  if (credential.kind === "p256")
    return p256Key({ credential, sign: refuse }).verify(hash, signature);
  if (relyingParty === undefined)
    return inputInvalid("a WebAuthn root's signature requires its relying party");
  return webauthnVerifier({ credential, ...relyingParty })(hash, signature);
}

/**
 * Verifies a signed owner operation before submission: the protocol shape and
 * hash, the account's address (its offline derivation and factory deployment,
 * or an existing profile's own address with no factory) and the reviewed
 * EntryPoint, then the root's signature over the hash. Any mismatch
 * fails with `kernel_runtime_binding_mismatch` or
 * `kernel_runtime_signature_invalid`; nothing is submitted.
 */
export async function verifyOwnerOperation(
  value: unknown,
  relyingParty?: Readonly<OwnerOperationRelyingParty>,
): Promise<Readonly<VerifiedOwnerOperation>> {
  const signed = parseSignedOwnerOperation(value);
  const { request } = signed;
  const { account } = request;
  const factory = request.userOperation.factory;
  let bound: boolean;
  if (isKernelExistingAccountProfile(account)) {
    // An existing account executes at its own address and is never deployed here.
    bound = request.userOperation.sender === account.address && factory === null;
  } else {
    const accountInput = {
      initialPackages: rootPackages(account, request.chainId),
      accountIndex: account.accountIndex,
    };
    bound =
      request.userOperation.sender === deriveKernelV4RootAccountAddress(accountInput) &&
      (factory === null ||
        (factory.address === KERNEL_V4_FACTORY_V09 &&
          factory.data === encodeKernelV4FactoryDeploy(accountInput)));
  }
  if (request.entryPoint !== KERNEL_V4_ENTRY_POINT_V09 || !bound)
    return runtimeFail(
      "kernel_runtime_binding_mismatch",
      "owner operation is not bound to its derived account",
    );
  if (
    !(await rootSigned(
      request.account.ownerCredential,
      request.userOperationHash,
      signed.signature,
      relyingParty,
    ))
  )
    return runtimeFail(
      "kernel_runtime_signature_invalid",
      "owner operation signature is not the account root's",
    );
  return Object.freeze({
    signed,
    entryPoint: request.entryPoint,
    userOperation: Object.freeze(
      toRpc(
        { ...ownerUserOperationForCetane(request.userOperation), signature: signed.signature },
        "0.9",
      ),
    ),
  });
}
