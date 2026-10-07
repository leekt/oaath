/**
 * An account root's one signature over a dapp's owner operation.
 *
 * The portal re-captures the relay's request with the protocol owner (calls
 * against callData, root nonce, the UserOperation hash) and refuses it unless
 * it executes on the chosen account with the chosen root, before the root is
 * asked. What is signed is the UserOperation hash itself; OAAth never submits.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type OwnerOperationRequest,
  parseKernelAccountProfile,
  parseOwnerOperationRequest,
  sameKernelAccountProfile,
  sameOwnerCredentialProfile,
} from "@oaath/protocol";
import { ECDSA_VALIDATOR, kernelKey } from "@oaath/sdk/kernel";
import type { PortalAccount } from "./api.js";
import { RootSigningError, rootKey } from "./root-signing.js";
import { findWallet } from "./session.js";
import type { RememberedSigner } from "./signers.js";

function refuse(code: string): never {
  throw new RootSigningError(code);
}

/** The relay's request, accepted only for this account and its root. */
export function reviewedOperation(input: {
  readonly request: unknown;
  readonly signer: RememberedSigner;
  readonly account: PortalAccount;
}): Readonly<OwnerOperationRequest> {
  let request: Readonly<OwnerOperationRequest>;
  let matches: boolean;
  try {
    request = parseOwnerOperationRequest(input.request);
    matches =
      request.userOperation.sender === input.account.address &&
      sameKernelAccountProfile(request.account, parseKernelAccountProfile(input.account.profile)) &&
      sameOwnerCredentialProfile(request.account.ownerCredential, input.signer.profile);
  } catch {
    return refuse("request-invalid");
  }
  if (!matches) return refuse("request-mismatch");
  return request;
}

/** Asks the root for its signature over the operation's hash: the decision artifact. */
export async function signOperation(
  request: Readonly<OwnerOperationRequest>,
  signer: RememberedSigner,
): Promise<string> {
  const profile = signer.profile;
  if (profile.kind === "ecdsa") {
    // A wallet signs the hash as an EIP-191 message, which the ECDSA root validator accepts.
    const wallet = await findWallet(signer.rdns);
    const accounts = await wallet.provider.request({ method: "eth_requestAccounts" });
    if (
      !Array.isArray(accounts) ||
      !accounts.some((entry) => entry?.toLowerCase?.() === profile.address)
    )
      return refuse("wallet-account-mismatch");
    const key = kernelKey({
      wallet: {
        account: { address: profile.address },
        signMessage: ({ message }) =>
          wallet.provider.request({
            method: "personal_sign",
            params: [message.raw, profile.address],
          }),
      },
      validator: ECDSA_VALIDATOR,
    });
    return key.sign(request.userOperationHash);
  }
  // The passkey asserts over the hash; the typed data argument is unused here.
  const key = await rootKey(signer, null);
  return key.sign(request.userOperationHash);
}
