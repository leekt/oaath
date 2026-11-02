/**
 * The account root's owner key held in the OAAth portal: pass it to
 * `createOAAth(...).owner(key)` and every `sendCalls` signature is one exact
 * owner operation the root reviews and signs there (flag "owner signs hash"),
 * while routing, fallback and journaling stay the realm's.
 *
 * ```text
 * portalOwnerKey({ issuer, clientId, redirectUri, account })
 *   a public key profile for the account's root credential (never signs)
 * owner(key).sendCalls(...)
 *   prepared operation -> the protocol owner-operation request (calls, gas,
 *   factory, paymaster, hash) -> portal popup (requestOwnerOperationApproval)
 *   -> the root's verified signature -> encoded for the runtime -> routes
 * ```
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type KernelAccountProfile,
  OAATH_OWNER_OPERATION_REQUEST_VERSION,
  parseKernelAccountProfile,
  parseOwnerOperationRequest,
} from "@oaath/protocol";
import { ECDSA_VALIDATOR } from "../kernel/deployment/v33.js";
import { credentialKey } from "../kernel/key/credential.js";
import type { KeyProfile } from "../kernel/types.js";
import type { PreparedUserOperation } from "../prepared-user-operation.js";
import { clientFail, mapClientFailure } from "./errors.js";
import type { OaathAuthorizationLauncher, OaathLoginOptions } from "./oauth-login.js";
import { requestOwnerOperationApproval } from "./owner-operation-approval.js";

export interface OaathPortalOwnerKeyOptions extends OaathLoginOptions {
  /** The account's protocol profile, as the login's id_token `oaath_account` names it. */
  readonly account: Readonly<KernelAccountProfile>;
  /**
   * Opens the portal somewhere other than a fresh popup. A send runs after
   * estimation, outside the user's gesture, where browsers block a new popup.
   */
  readonly launch?: OaathAuthorizationLauncher;
}

interface PortalOwner {
  readonly options: OaathLoginOptions;
  readonly launch: OaathAuthorizationLauncher | undefined;
  readonly account: Readonly<KernelAccountProfile>;
  /** Signatures the portal flow verified as the root's, by the hash they sign. */
  readonly verified: Map<string, string>;
}

const portalOwners = new WeakMap<object, PortalOwner>();

/** A public owner key whose signatures come from the account's root in the portal. */
export function portalOwnerKey(value: OaathPortalOwnerKeyOptions): Readonly<KeyProfile> {
  if (!value || typeof value !== "object")
    return clientFail("oaath_client_input_invalid", "portal owner key options are required");
  const { account: accountValue, launch, ...options } = value;
  if (launch !== undefined && typeof launch !== "function")
    return clientFail("oaath_client_capability_invalid", "launch must be a function");
  let account: Readonly<KernelAccountProfile>;
  let base: Readonly<KeyProfile>;
  try {
    account = parseKernelAccountProfile(accountValue);
    base = credentialKey({
      credential: account.ownerCredential,
      validator: account.ownerCredential.kind === "ecdsa" ? ECDSA_VALIDATOR : null,
    });
  } catch (error) {
    return mapClientFailure(error, "the portal owner key's account is invalid");
  }
  const verified = new Map<string, string>();
  // Public material only: it never signs. It verifies exactly the signatures
  // the portal flow already proved to be the root's over the same hash.
  const key: Readonly<KeyProfile> = Object.freeze({
    ...base,
    verify: async (hash: `0x${string}`, signature: `0x${string}`) =>
      verified.get(hash) === signature.toLowerCase(),
  });
  portalOwners.set(key, Object.freeze({ options, launch, account, verified }));
  return key;
}

/** The portal owner a key came from, if it is one. */
export function portalOwnerOf(value: unknown): PortalOwner | undefined {
  return typeof value === "object" && value !== null ? portalOwners.get(value) : undefined;
}

/**
 * The root's signature over exactly `prepared` running `calls`, from the
 * portal. The request is the protocol's own capture of the prepared
 * operation, so the portal shows and the root signs what the realm submits.
 */
export async function portalOwnerSignature(
  owner: PortalOwner,
  address: `0x${string}`,
  prepared: Readonly<PreparedUserOperation>,
  calls: readonly Readonly<{ target: `0x${string}`; value: string; data: `0x${string}` }>[],
): Promise<`0x${string}`> {
  if (prepared.userOperation.sender !== address)
    return clientFail("oaath_client_state_conflict", "the operation is for another account");
  let request: ReturnType<typeof parseOwnerOperationRequest>;
  try {
    request = parseOwnerOperationRequest({
      version: OAATH_OWNER_OPERATION_REQUEST_VERSION,
      kind: "kernel-owner-operation",
      account: owner.account,
      chainId: prepared.chainId,
      entryPoint: prepared.entryPoint.address,
      calls,
      userOperation: prepared.userOperation,
      userOperationHash: prepared.userOperationHash,
    });
  } catch (error) {
    return mapClientFailure(error, "the operation cannot be approved in the portal");
  }
  const approved = await requestOwnerOperationApproval({
    ...owner.options,
    ...(owner.launch === undefined ? {} : { launch: owner.launch }),
    request,
  });
  // requestOwnerOperationApproval verified it as the root's over this hash.
  const signature = approved.signed.signature.toLowerCase() as `0x${string}`;
  owner.verified.set(request.userOperationHash, signature);
  return signature;
}
