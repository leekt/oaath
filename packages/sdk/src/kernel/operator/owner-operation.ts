/**
 * One exact owner operation for a factory-derived Kernel 0.4.0 account or an
 * existing (imported) Kernel 0.4.0 or 0.3.3 account (EntryPoint 0.9 or 0.7):
 * the request its root reviews and signs offline, and
 * the verification a holder of the signed artifact runs before submitting it.
 * Nothing is read from a chain: the caller states the nonce, gas, fees,
 * paymaster, and whether a derived account is deployed; an existing account is
 * deployed and carries no factory. Submission and observation stay with the
 * caller.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  encodeKernelPermissionUninstallCalls,
  isKernelExistingAccountProfile,
  type KernelDerivedAccountProfile,
  type KernelExistingAccountProfile,
  OAATH_OWNER_OPERATION_REQUEST_VERSION,
  OAATH_SIGNED_OWNER_OPERATION_VERSION,
  type OwnerCredentialProfile,
  type OwnerOperationRequest,
  ownerOperationEntryPointVersion,
  ownerUserOperationForCetane,
  parseKernelAccountProfile,
  parseOwnerOperationRequest,
  parseSignedOwnerOperation,
  type SignedOwnerOperation,
} from "@oaath/protocol";
import type { Hex } from "cetane";
import { toRpc } from "cetane/execution/erc4337";
import { decodeAbiParameters } from "cetane/utils";
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
import {
  deriveKernelV33Account,
  ECDSA_VALIDATOR,
  KERNEL_ENTRY_POINT_V07,
} from "../deployment/v33.js";
import { captureKeyProfile, exactInput, inputInvalid, runtimeFail } from "../internal.js";
import { credentialKey } from "../key/credential.js";
import { ecdsaKey, ecdsaWalletKey } from "../key/ecdsa.js";
import { p256Key } from "../key/p256.js";
import { webauthnVerifier } from "../key/webauthn.js";
import {
  type KernelAllChainApproval,
  parseKernelAllChainApproval,
} from "../permission/materialize.js";
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
  /**
   * An existing Kernel 0.3.3 account that is not deployed yet: its account
   * index, so `deployed: false` adds its MetaFactory deployment
   * (`deriveKernelV33Account`); the derived address must be the profile's.
   */
  readonly accountIndex?: string;
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

/** The account's EntryPoint: 0.7 for an existing Kernel 0.3.3 account, else 0.9. */
function ownerEntryPoint(account: Readonly<OwnerOperationRequest["account"]>) {
  return ownerOperationEntryPointVersion(account) === "0.7"
    ? ({ version: "0.7", address: KERNEL_ENTRY_POINT_V07.address } as const)
    : ({ version: "0.9", address: KERNEL_V4_ENTRY_POINT_V09 } as const);
}

const DEPLOY_WITH_FACTORY = [{ type: "address" }, { type: "bytes" }, { type: "bytes32" }] as const;

/** A counterfactual Kernel 0.3.3 account's MetaFactory deployment at `accountIndex`. */
function v33Counterfactual(
  account: Readonly<KernelExistingAccountProfile>,
  accountIndex: unknown,
): Readonly<{ address: `0x${string}`; data: `0x${string}` }> {
  if (account.ownerCredential.kind !== "ecdsa")
    return inputInvalid("a Kernel 0.3.3 account's root is an ECDSA owner");
  if (typeof accountIndex !== "string")
    return inputInvalid("a counterfactual Kernel 0.3.3 account needs its account index");
  const derived = deriveKernelV33Account({ owner: account.ownerCredential.address, accountIndex });
  if (derived.address !== account.address)
    return runtimeFail(
      "kernel_runtime_binding_mismatch",
      "the owner and account index derive another address",
    );
  return Object.freeze({ address: derived.factory, data: derived.factoryData as `0x${string}` });
}

/** Whether `factory` is exactly the account's own Kernel 0.3.3 deployment. */
function isV33Deployment(
  account: Readonly<KernelExistingAccountProfile>,
  factory: Readonly<{ address: `0x${string}`; data: `0x${string}` }>,
): boolean {
  try {
    const [, , salt] = decodeAbiParameters(DEPLOY_WITH_FACTORY, `0x${factory.data.slice(10)}`);
    const expected = v33Counterfactual(account, BigInt(salt).toString(10));
    return expected.address === factory.address && expected.data === factory.data;
  } catch {
    return false;
  }
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
  if (value !== null && typeof value === "object" && Object.hasOwn(value, "accountIndex"))
    keys.push("accountIndex");
  const input = exactInput(value, keys, "owner operation", context);
  if (typeof input.deployed !== "boolean") return inputInvalid("owner operation state is invalid");
  if (typeof input.chainId !== "number") return inputInvalid("owner operation chain is invalid");
  const nonce = exactInput(input.nonce, ["lane", "sequence"], "owner operation nonce", context);
  const account = parseKernelAccountProfile(input.account);
  const existing = isKernelExistingAccountProfile(account);
  if (!existing && account.factoryRoute !== "kernel_factory")
    return runtimeFail(
      "kernel_runtime_unsupported",
      "owner operations require a factory-derived or an existing Kernel account",
    );
  // Only a Kernel 0.3.3 account may still be counterfactual, at its index.
  const v33Deployment =
    existing && !input.deployed && account.kernelVersion === "0.3.3"
      ? v33Counterfactual(account, input.accountIndex)
      : null;
  if (existing && !input.deployed && v33Deployment === null)
    return inputInvalid("an existing Kernel 0.4.0 account is deployed; nothing deploys it");
  if (input.accountIndex !== undefined && v33Deployment === null)
    return inputInvalid("an account index only deploys a counterfactual Kernel 0.3.3 account");
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
    entryPoint: ownerEntryPoint(account),
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
        v33Deployment ??
        (input.deployed || !accountInput
          ? null
          : { address: KERNEL_V4_FACTORY_V09, data: encodeKernelV4FactoryDeploy(accountInput) }),
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

export interface PrepareOwnerPermissionUninstallInput {
  /** The Grant's factory-derived or existing Kernel 0.4.0 account profile. */
  readonly account: PrepareOwnerOperationInput["account"];
  readonly chainId: number;
  /**
   * The Grant's install approval (`token.authorization_details[0].enable`): its
   * packages name the permission's signer and policies, prefixed by the
   * permission ID.
   */
  readonly approval: Readonly<KernelAllChainApproval>;
  readonly nonce: PrepareOwnerOperationInput["nonce"];
  readonly gas: PrepareOwnerOperationInput["gas"];
  readonly paymaster?: PrepareOwnerOperationInput["paymaster"];
}

/**
 * The owner operation that uninstalls one installed Kernel 0.4.0 permission:
 * its policies in reverse install order, then its signer. An installed
 * permission means a deployed account, so no factory is included. An approval
 * for another account fails with `kernel_runtime_binding_mismatch`.
 */
export function prepareOwnerPermissionUninstall(
  value: PrepareOwnerPermissionUninstallInput,
): Readonly<PreparedOwnerOperation> {
  const keys = ["account", "chainId", "approval", "nonce", "gas"];
  if (value !== null && typeof value === "object" && Object.hasOwn(value, "paymaster"))
    keys.push("paymaster");
  const input = exactInput(value, keys, "owner permission uninstall", new WeakSet());
  if (typeof input.chainId !== "number") return inputInvalid("owner operation chain is invalid");
  const approval = parseKernelAllChainApproval(input.approval);
  const account = parseKernelAccountProfile(input.account);
  const address = isKernelExistingAccountProfile(account)
    ? existingAddress(account)
    : account.factoryRoute === "kernel_factory"
      ? deriveKernelV4RootAccountAddress({
          initialPackages: rootPackages(account, input.chainId),
          accountIndex: account.accountIndex,
        })
      : null;
  if (address !== null && approval.account !== address)
    return runtimeFail(
      "kernel_runtime_binding_mismatch",
      "the install approval belongs to another account",
    );
  return prepareOwnerOperation({
    account: input.account as PrepareOwnerOperationInput["account"],
    chainId: input.chainId,
    deployed: true,
    calls: encodeKernelPermissionUninstallCalls({
      account: approval.account,
      packages: approval.packages,
    }),
    nonce: input.nonce as PrepareOwnerOperationInput["nonce"],
    gas: input.gas as PrepareOwnerOperationInput["gas"],
    ...(Object.hasOwn(input, "paymaster")
      ? { paymaster: input.paymaster as Readonly<PreparedPaymaster> | null }
      : {}),
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
    // An existing account executes at its own address; only a counterfactual
    // Kernel 0.3.3 account carries a deployment, exactly its own.
    bound =
      request.userOperation.sender === account.address &&
      (factory === null ||
        (account.kernelVersion === "0.3.3" && isV33Deployment(account, factory)));
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
  const entryPoint = ownerEntryPoint(account);
  if (request.entryPoint !== entryPoint.address || !bound)
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
        entryPoint.version,
      ),
    ),
  });
}
