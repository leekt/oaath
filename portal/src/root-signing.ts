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
  parseGrantPolicy,
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
  grantPermissionPackages,
  type KernelPermissionDecision,
  kernelKey,
  prepareDerivedAccountPermissionApproval,
  prepareExistingAccountPermissionApprovalOffline,
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

/** Whether an imported account's approval must read a chain at all. */
export function needsChainRead(kernelVersion: string, appNonce: string | undefined): boolean {
  return kernelVersion === "0.3.3" && appNonce === undefined;
}

/** Where a grant's approval reads its chain: the app's own RPC, or the portal's. */
export interface GrantReads {
  readonly chainId: number;
  readonly rpcUrl: string;
}

/**
 * Where to read: every chain the app named an RPC for, through the portal's
 * per-request proxy, then the portal's own Arbitrum Sepolia.
 */
function readCandidates(
  transactionId: string | null,
  detail: Pick<GrantDetail, "chains" | "rpc_urls">,
): GrantReads[] {
  const named =
    transactionId === null
      ? []
      : detail.chains
          .filter((chain) => detail.rpc_urls?.[String(chain)] !== undefined)
          .map((chainId) => ({
            chainId,
            rpcUrl: `${location.origin}/rpc/tx/${transactionId}/${chainId}`,
          }));
  return [...named, { chainId: 421_614, rpcUrl: `${location.origin}/rpc/421614` }];
}

/** The first candidate, unread: for an account that needs no chain read. */
export function grantReads(
  transactionId: string | null,
  detail: Pick<GrantDetail, "chains" | "rpc_urls">,
): GrantReads {
  return readCandidates(transactionId, detail)[0]!;
}

async function hasCode(reads: GrantReads, address: string): Promise<boolean> {
  try {
    const response = await fetch(reads.rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_getCode",
        params: [address, "latest"],
      }),
      signal: AbortSignal.timeout(8_000),
    });
    const body = (await response.json()) as { result?: unknown };
    return typeof body.result === "string" && body.result !== "0x";
  } catch {
    return false;
  }
}

/**
 * The first candidate chain where the account is deployed: the Grant covers
 * every chain, so one readable chain is enough and an unreadable one is
 * skipped. Without any, the first candidate, whose read then fails typed.
 */
export async function readableGrantReads(
  transactionId: string | null,
  detail: Pick<GrantDetail, "chains" | "rpc_urls">,
  account: Pick<PortalAccount, "address">,
): Promise<GrantReads> {
  const candidates = readCandidates(transactionId, detail);
  for (const reads of candidates) if (await hasCode(reads, account.address)) return reads;
  return candidates[0]!;
}

/**
 * A Kernel 0.3.3 account's enable nonce for `signer` under `policy`, read
 * on the approval's chain (`grantReads`), for the relay's prepare (which reads no
 * chain). Undefined for any other account. The SDK re-reads it when it
 * prepares the approval, so a moved nonce refuses as `digest-mismatch`.
 */
export async function enableNonce(
  account: Pick<PortalAccount, "address" | "profile">,
  detail: Pick<GrantDetail, "signer" | "policy" | "enable_nonce">,
  reads: GrantReads,
): Promise<string | undefined> {
  if (account.profile.kernelVersion !== "0.3.3") return undefined;
  if (detail.enable_nonce !== undefined) return detail.enable_nonce;
  const { importChainReads } = await import("./account-import.js");
  try {
    const { permissionId } = grantPermissionPackages({
      signer: parseOperatorCredentialProfile(detail.signer),
      policy: parseGrantPolicy(detail.policy),
    });
    const nonce = await importChainReads(reads.rpcUrl, reads.chainId).read({
      type: "kernel_v33_permission_nonce",
      chainId: reads.chainId,
      account: account.address,
      permissionId,
    });
    return String(nonce);
  } catch {
    return refuse("account-unreadable");
  }
}

/** The SDK's reads-backed preparation for an imported (existing) account. */
async function prepareImportedAccountApproval(
  request: Readonly<PermissionRequest>,
  reads: GrantReads,
) {
  // Module discovery and chain reads load only when an imported account signs.
  const { importChainReads } = await import("./account-import.js");
  try {
    return await prepareKernelPermissionApproval({
      request,
      chainId: reads.chainId,
      reads: importChainReads(reads.rpcUrl, reads.chainId),
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
  /** Where an imported account's approval reads its chain (`grantReads`). */
  readonly reads: GrantReads;
  /** The app's Kernel 0.3.3 enable nonce: the approval then reads no chain. */
  readonly enableNonce?: string;
}): Promise<string> {
  const { request, prepared, chainId, signer, account, reads } = input;
  if (chainId === undefined) return refuse("request-mismatch");
  // An imported account reads no chain when it needs nothing read: Kernel
  // 0.4.0, or 0.3.3 with the app's nonce. Otherwise the SDK binds it on chain
  // through the portal's budgeted read proxy. A derived one needs no read.
  const approval = isKernelExistingAccountProfile(request.logicalAccount)
    ? needsChainRead(request.logicalAccount.kernelVersion, input.enableNonce)
      ? await prepareImportedAccountApproval(request, reads)
      : prepareExistingAccountPermissionApprovalOffline({
          request,
          chainId,
          ...(input.enableNonce === undefined ? {} : { enableNonce: input.enableNonce }),
        })
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
