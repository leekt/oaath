/**
 * The account root's one signature that adds a login-only signer: an OAAth
 * membership approval (EIP-712), never a chain transaction.
 *
 * The portal rebuilds the typed data from what the owner is shown (the
 * account, the new signer's profile, the link) and signs only if the relay's
 * digest is the same.
 *
 * @author taek <leekt216@gmail.com>
 */
import { hashOwnerCredentialProfile, parseOwnerCredentialProfile } from "@oaath/protocol";
import { hashTypedData } from "cetane/utils";
import type { MembershipApprovalTypedData, PortalLink } from "./api.js";
import { RootSigningError, rootKey } from "./root-signing.js";
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
