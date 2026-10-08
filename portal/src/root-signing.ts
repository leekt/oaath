/**
 * The one signature the product ever asks for: an account root approving a
 * dapp's signer and policy as a Kernel replayable install.
 *
 * The relay composes the request and its signing request; the portal never
 * signs what it did not derive itself. The SDK prepares the same approval from
 * the composed request and the account's registry address, and the relay's
 * digest must equal it before the root is prompted.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  hashGrantPolicy,
  hashOwnerSigningRequest,
  hashPermissionRequest,
  isKernelExistingAccountProfile,
  type PermissionRequest,
  parseKernelAccountProfile,
  parseOperatorCredentialProfile,
  parseOwnerCredentialProfile,
  parsePermissionRequest,
  sameKernelAccountProfile,
  sameOperatorCredentialProfile,
  sameOwnerCredentialProfile,
} from "@oaath/protocol";
import {
  ECDSA_VALIDATOR,
  type KernelPermissionDecision,
  kernelKey,
  prepareDerivedAccountPermissionApproval,
  prepareKernelPermissionApproval,
} from "@oaath/sdk/kernel";
import type { GrantDetail, PortalAccount, PrepareGrantResponse } from "./api.js";
import { assertionFields, bytesFromBase64Url, findWallet } from "./session.js";
import type { RememberedSigner } from "./signers.js";

/** A refusal with a closed code the screen turns into copy. */
export class RootSigningError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(`root signing failed: ${code}`);
    this.name = "RootSigningError";
    this.code = code;
  }
}

function refuse(code: string): never {
  throw new RootSigningError(code);
}

/**
 * The relay's composed request, accepted only if it is exactly what the user
 * is shown: the dapp's signer and policy, the chosen signer as owner, and the
 * chosen account. Narrowing is not offered, so the approved policy is the
 * requested one.
 */
export function reviewedRequest(input: {
  readonly prepared: PrepareGrantResponse;
  /** What the user was shown: the dapp's signer and policy. */
  readonly detail: Pick<GrantDetail, "signer" | "policy">;
  readonly signer: RememberedSigner;
  readonly account: PortalAccount;
}): Readonly<PermissionRequest> {
  const { prepared, detail, signer, account } = input;
  let request: Readonly<PermissionRequest>;
  let matches: boolean;
  try {
    request = parsePermissionRequest(prepared.permission_request);
    matches =
      hashPermissionRequest(request) === prepared.request_hash &&
      hashGrantPolicy(prepared.approved_policy) === hashGrantPolicy(request.policy) &&
      hashGrantPolicy(detail.policy) === hashGrantPolicy(request.policy) &&
      sameOperatorCredentialProfile(
        request.operatorCredential,
        parseOperatorCredentialProfile(detail.signer),
      ) &&
      sameOwnerCredentialProfile(
        request.logicalAccount.ownerCredential,
        parseOwnerCredentialProfile(signer.profile),
      ) &&
      sameKernelAccountProfile(request.logicalAccount, parseKernelAccountProfile(account.profile));
  } catch {
    return refuse("request-invalid");
  }
  if (!matches) return refuse("request-mismatch");
  return request;
}

/** A key profile for the account root, signing only through the user's own device. */
export async function rootKey(signer: RememberedSigner, typedData: unknown) {
  const profile = signer.profile;
  if (profile.kind === "ecdsa") {
    const wallet = await findWallet(signer.rdns);
    const accounts = await wallet.provider.request({ method: "eth_requestAccounts" });
    if (
      !Array.isArray(accounts) ||
      !accounts.some((entry) => entry?.toLowerCase?.() === profile.address)
    )
      return refuse("wallet-account-mismatch");
    return kernelKey({
      account: {
        address: profile.address,
        // The wallet signs the typed data whose EIP-712 hash is the approved digest;
        // the key profile recovers the signer before the signature is used.
        sign: () =>
          wallet.provider.request({
            method: "eth_signTypedData_v4",
            params: [profile.address, JSON.stringify(typedData)],
          }),
      },
      validator: ECDSA_VALIDATOR,
    });
  }
  if (profile.kind === "webauthn" && signer.credentialId) {
    return kernelKey({
      kind: "webauthn",
      credential: profile,
      credentialId: signer.credentialId,
      rpId: location.hostname,
      origin: location.origin,
      authenticate: async (request) => {
        const credential = (await navigator.credentials.get({
          publicKey: {
            rpId: request.rpId,
            challenge: bytesFromBase64Url(request.challenge),
            allowCredentials: [
              { type: "public-key", id: bytesFromBase64Url(request.credentialId) },
            ],
            userVerification: "required",
            timeout: 60_000,
          },
        })) as PublicKeyCredential | null;
        if (!credential) return refuse("passkey-cancelled");
        return assertionFields(credential);
      },
    });
  }
  return refuse("root-unsupported");
}

/** The SDK's reads-backed preparation for an imported (existing) account. */
async function prepareImportedAccountApproval(request: Readonly<PermissionRequest>) {
  // Module discovery and chain reads load only when an imported account signs.
  const { IMPORT_CHAIN_ID, importChainReads } = await import("./account-import.js");
  try {
    return await prepareKernelPermissionApproval({
      request,
      chainId: IMPORT_CHAIN_ID,
      reads: importChainReads(`${location.origin}/rpc/${IMPORT_CHAIN_ID}`),
    });
  } catch {
    return refuse("account-unreadable");
  }
}

/**
 * Prepares the approval with the SDK, refuses unless the relay's signing
 * request is identical, then asks the root for its one signature. Returns the
 * decision artifact the relay verifies.
 */
export async function signGrantApproval(input: {
  readonly request: Readonly<PermissionRequest>;
  readonly prepared: PrepareGrantResponse;
  /** Where the SDK reads the pinned deployment; the approval itself is all-chain. */
  readonly chainId: number | undefined;
  readonly signer: RememberedSigner;
  readonly account: Pick<PortalAccount, "address">;
}): Promise<string> {
  const { request, prepared, chainId, signer, account } = input;
  if (chainId === undefined) return refuse("request-mismatch");
  // An imported account is bound on chain first: the SDK proves its root owner
  // through the portal's budgeted read proxy. A derived one needs no read.
  const approval = isKernelExistingAccountProfile(request.logicalAccount)
    ? await prepareImportedAccountApproval(request)
    : prepareDerivedAccountPermissionApproval({
        request,
        chainId,
        account: account.address,
      });
  if (
    approval.signingRequest.expectedDigest !== prepared.signing_request.expectedDigest ||
    hashOwnerSigningRequest(approval.signingRequest) !==
      hashOwnerSigningRequest(prepared.signing_request)
  )
    return refuse("digest-mismatch");
  const key = await rootKey(signer, approval.signingRequest.typedData);
  // The relay stamps `requestedAt` with its clock. A browser clock a second behind, or an
  // approval within the same second, must not date the decision before the request.
  const decision: Readonly<KernelPermissionDecision> = await approval.sign(
    key,
    Math.max(Math.floor(Date.now() / 1_000), request.requestedAt),
  );
  return JSON.stringify(decision);
}
