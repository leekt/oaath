/**
 * Deterministic root owners of the three kinds a portal account can have, and
 * the permission request a dapp's session asks them to approve. Shared by the
 * local Anvil proof and the Rust verifier fixtures, so both see the same keys.
 */
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha256";
import {
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  type OwnerCredentialProfile,
  type PermissionRequest,
  parsePermissionRequest,
} from "@oaath/protocol";
import { privateKeyToAccount } from "cetane/accounts";
import { bytesToHex, concatHex, hexToBytes, keccak256, toHex } from "cetane/utils";
import { ECDSA_VALIDATOR } from "../../src/kernel/deployment/v33.js";
import { ecdsaKey } from "../../src/kernel/key/ecdsa.js";
import { p256Key } from "../../src/kernel/key/p256.js";
import { base64UrlFromBytes, webauthnKey } from "../../src/kernel/key/webauthn.js";
import type { KeyProfile } from "../../src/kernel/types.js";

export type PortalRootKind = "ecdsa" | "p256" | "webauthn";

/** The portal's WebAuthn relying party: assertions bind this RP ID and origin. */
export const PORTAL_RP_ID = "oaath.taek.tech";
export const PORTAL_ORIGIN = "https://oaath.taek.tech";

export interface PortalRoot {
  readonly kind: PortalRootKind;
  readonly credential: OwnerCredentialProfile;
  /** A signing key profile for the credential, as the portal's signer would hold it. */
  readonly key: Readonly<KeyProfile>;
  /** ECDSA roots bind the deployment's caller-bound validator; others carry null. */
  readonly validator: `0x${string}` | null;
}

function scalar(label: string): Uint8Array {
  return sha256(new TextEncoder().encode(`oaath-portal-root:${label}`));
}

function ecdsaRoot(label: string): PortalRoot {
  const account = privateKeyToAccount(bytesToHex(scalar(label)));
  const address = account.address.toLowerCase() as `0x${string}`;
  return {
    kind: "ecdsa",
    credential: { version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION, kind: "ecdsa", address },
    key: ecdsaKey({ account: { address, sign: account.sign }, validator: ECDSA_VALIDATOR }),
    validator: ECDSA_VALIDATOR,
  };
}

function p256Root(label: string): PortalRoot {
  const secret = scalar(label);
  const credential = {
    version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
    kind: "p256",
    publicKey: bytesToHex(p256.getPublicKey(secret, false)),
  } as const;
  return {
    kind: "p256",
    credential,
    key: p256Key({
      credential,
      sign: async ({ hash }) =>
        bytesToHex(
          p256.sign(hexToBytes(hash), secret, { lowS: true, prehash: false }).toCompactRawBytes(),
        ),
    }),
    validator: null,
  };
}

/** A software authenticator: user present and verified, fixed counter. */
function webauthnRoot(label: string): PortalRoot {
  const secret = scalar(label);
  const rawId = scalar(`${label}:credential`).slice(0, 16);
  const credentialId = base64UrlFromBytes(rawId);
  const credential = {
    version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
    kind: "webauthn",
    publicKey: bytesToHex(p256.getPublicKey(secret, false)),
    authenticatorIdHash: keccak256(toHex(rawId)),
  } as const;
  const rpIdHash = bytesToHex(sha256(new TextEncoder().encode(PORTAL_RP_ID)));
  return {
    kind: "webauthn",
    credential,
    key: webauthnKey({
      credential,
      credentialId,
      rpId: PORTAL_RP_ID,
      origin: PORTAL_ORIGIN,
      authenticate: async (request) => {
        const clientDataJSON = JSON.stringify({
          type: "webauthn.get",
          challenge: request.challenge,
          origin: PORTAL_ORIGIN,
          crossOrigin: false,
        });
        const authenticatorData = concatHex([rpIdHash, "0x0500000001"]);
        const message = sha256(
          new Uint8Array([
            ...hexToBytes(authenticatorData),
            ...sha256(new TextEncoder().encode(clientDataJSON)),
          ]),
        );
        const signature = p256.sign(message, secret, { lowS: true, prehash: false });
        return {
          authenticatorData,
          clientDataJSON,
          responseTypeLocation: String(clientDataJSON.indexOf('"type":"webauthn.get"')),
          r: toHex(signature.r, { size: 32 }),
          s: toHex(signature.s, { size: 32 }),
        };
      },
    }),
    validator: null,
  };
}

/** The private scalar behind `portalRoot(kind, label)`, for fixtures that re-sign variants. */
export function portalSecret(kind: PortalRootKind, label = "root"): Uint8Array {
  return scalar(`${kind}:${label}`);
}

/** The account's root of `kind`; another `label` is a different key of that kind. */
export function portalRoot(kind: PortalRootKind, label = "root"): PortalRoot {
  const name = `${kind}:${label}`;
  if (kind === "ecdsa") return ecdsaRoot(name);
  if (kind === "p256") return p256Root(name);
  return webauthnRoot(name);
}

/** The dapp session's ECDSA key, the operator the request names. */
export function portalSession() {
  const account = privateKeyToAccount(bytesToHex(scalar("session")));
  return Object.freeze({
    address: account.address.toLowerCase() as `0x${string}`,
    sign: account.sign,
  });
}

/** One canonical permission request for a factory-derived account of `root`. */
export function portalPermissionRequest(input: {
  readonly root: PortalRoot;
  readonly target: `0x${string}`;
  readonly requestedAt: number;
}): Readonly<PermissionRequest> {
  const { requestedAt } = input;
  return parsePermissionRequest({
    version: "oaath.permission-request/v1",
    requestId: `portal-${input.root.kind}`,
    context: {
      version: "oaath.workspace-account-context/v1",
      workspaceId: "personal-1",
      workspaceKind: "personal",
      accountId: "account-1",
    },
    application: {
      applicationId: "dapp-1",
      clientId: "client-1",
      origin: "https://dapp.example",
      deviceId: "device-1",
    },
    chainScope: "all",
    logicalAccount: {
      version: "oaath.kernel-account-profile/v1",
      kind: "kernel",
      accountIndex: "0",
      kernelVersion: "0.4.0",
      factoryRoute: "kernel_factory",
      entryPoint: { version: "0.9" },
      ownerCredential: input.root.credential,
    },
    operatorCredential: {
      version: "oaath.operator-credential-profile/v1",
      kind: "ecdsa",
      address: portalSession().address,
    },
    sessionSigner: null,
    policy: {
      version: "oaath.grant-policy/v1",
      calls: [
        { target: input.target, selector: "0x12345678", valueLimit: "500", argumentEquals: [] },
      ],
      validAfter: 0,
      validUntil: requestedAt + 600,
      perChainOperationLimit: { count: 3, intervalSeconds: null },
    },
    requestedAt,
    expiresAt: requestedAt + 601,
  });
}
