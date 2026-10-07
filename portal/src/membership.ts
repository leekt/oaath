/**
 * The account root's one signature that adds a signer: an OAAth membership
 * approval (EIP-712) for a login-only member, or, with a policy template, the
 * member's Kernel enable (`signMemberGrant`). Never a chain transaction.
 *
 * The portal rebuilds the typed data from what the owner is shown (the
 * account, the new signer's profile, the link) and signs only if the relay's
 * digest is the same.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  hashGrantPolicy,
  hashOwnerCredentialProfile,
  hashPermissionRequest,
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  type OwnerCredentialProfile,
  type PermissionRequest,
  parseKernelAccountProfile,
  parseOperatorCredentialProfile,
  parseOwnerCredentialProfile,
  parsePermissionRequest,
  sameKernelAccountProfile,
  sameOperatorCredentialProfile,
  sameOwnerCredentialProfile,
} from "@oaath/protocol";
import { hashTypedData } from "cetane/utils";
import type {
  MembershipApprovalTypedData,
  PolicyTemplate,
  PortalAccount,
  PortalLink,
  PrepareGrantResponse,
} from "./api.js";
import { RootSigningError, rootKey, signGrantApproval } from "./root-signing.js";
import type { RememberedSigner } from "./signers.js";

const TYPES = {
  EIP712Domain: [
    { name: "name", type: "string" },
    { name: "version", type: "string" },
  ],
  MembershipApproval: [
    { name: "account", type: "address" },
    { name: "signerProfileHash", type: "bytes32" },
    { name: "role", type: "string" },
    { name: "issuedAt", type: "uint64" },
    { name: "expiresAt", type: "uint64" },
    { name: "nonce", type: "string" },
  ],
} as const;

function refuse(code: string): never {
  throw new RootSigningError(code);
}

/** The approval for exactly this link, or a refusal if the relay's differs. */
export function reviewedMembership(link: PortalLink, linkId: string): MembershipApprovalTypedData {
  let typedData: MembershipApprovalTypedData;
  let digest: `0x${string}`;
  try {
    const issuedAt = link.typed_data.message.issuedAt;
    if (!Number.isSafeInteger(issuedAt) || issuedAt < 0 || issuedAt >= link.expires_at)
      return refuse("link-mismatch");
    typedData = {
      types: TYPES,
      primaryType: "MembershipApproval",
      domain: { name: "OAAth", version: "1" },
      message: {
        account: link.address,
        signerProfileHash: hashOwnerCredentialProfile(
          parseOwnerCredentialProfile(link.signer.profile),
        ),
        role: "permission",
        issuedAt,
        expiresAt: link.expires_at,
        nonce: linkId,
      },
    };
    digest = hashTypedData({
      domain: typedData.domain,
      types: { MembershipApproval: TYPES.MembershipApproval },
      primaryType: "MembershipApproval",
      message: {
        ...typedData.message,
        issuedAt: BigInt(typedData.message.issuedAt),
        expiresAt: BigInt(typedData.message.expiresAt),
      },
    });
  } catch (error) {
    if (error instanceof RootSigningError) throw error;
    return refuse("link-invalid");
  }
  if (digest !== link.digest || link.link_id !== linkId) return refuse("link-mismatch");
  return typedData;
}

/** The root's signature over the reviewed membership approval. */
export async function signMembershipApproval(
  link: PortalLink,
  linkId: string,
  signer: RememberedSigner,
): Promise<`0x${string}`> {
  const typedData = reviewedMembership(link, linkId);
  const key = await rootKey(signer, typedData);
  return key.sign(link.digest);
}

/** The SDK reads pinned deployments for this chain; the approval is all-chain. */
const PORTAL_CHAIN_ID = 421_614;

/**
 * The root's enable for a member grant from a template, signed only if the
 * relay's prepared request is exactly: the member's own key as operator, the
 * template's calls and limit for its lifetime, this account and root, and
 * the portal as the application.
 */
export async function signMemberGrant(input: {
  readonly prepared: PrepareGrantResponse;
  readonly member: OwnerCredentialProfile;
  readonly template: PolicyTemplate;
  readonly account: PortalAccount;
  readonly signer: RememberedSigner;
}): Promise<string> {
  const { prepared, member, template, account, signer } = input;
  let request: Readonly<PermissionRequest>;
  let matches: boolean;
  try {
    request = parsePermissionRequest(prepared.permission_request);
    const { policy } = request;
    const calls = policy.calls.map((call) => ({
      target: call.target,
      selector: call.selector,
      valueLimit: call.valueLimit,
      argumentEquals: call.argumentEquals.length,
    }));
    matches =
      hashPermissionRequest(request) === prepared.request_hash &&
      hashGrantPolicy(prepared.approved_policy) === hashGrantPolicy(policy) &&
      member.kind !== "p256" &&
      sameOperatorCredentialProfile(
        request.operatorCredential,
        parseOperatorCredentialProfile({
          ...member,
          version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
        }),
      ) &&
      JSON.stringify(calls) ===
        JSON.stringify(template.policy.calls.map((call) => ({ ...call, argumentEquals: 0 }))) &&
      policy.perChainOperationLimit.count === template.policy.perChainOperationLimit.count &&
      policy.perChainOperationLimit.intervalSeconds ===
        template.policy.perChainOperationLimit.intervalSeconds &&
      policy.validUntil !== null &&
      policy.validUntil - policy.validAfter === template.lifetime_seconds &&
      sameKernelAccountProfile(
        request.logicalAccount,
        parseKernelAccountProfile(account.profile),
      ) &&
      sameOwnerCredentialProfile(
        request.logicalAccount.ownerCredential,
        parseOwnerCredentialProfile(signer.profile),
      ) &&
      request.application.origin === location.origin;
  } catch {
    return refuse("grant-invalid");
  }
  if (!matches) return refuse("grant-mismatch");
  return signGrantApproval({
    request,
    prepared,
    chainId: PORTAL_CHAIN_ID,
    signer,
    account,
  });
}
