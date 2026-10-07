/**
 * Signers this browser remembers, and the two ways to add one.
 *
 * Storage holds public identity only: no key, no secret, no session. Adding a
 * signer never signs anything: a passkey is created (its public key is read
 * from the attestation, not trusted as proof), and a wallet only reveals its
 * address through `eth_requestAccounts`.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  type OwnerCredentialProfile,
  parseOwnerCredentialProfile,
} from "@oaath/protocol";
import { enrolWebAuthnCredential } from "@oaath/sdk/kernel";
import { PortalApiError, portalApi } from "./api.js";

export type SignerKind = "passkey" | "wallet" | "phone";

export interface RememberedSigner {
  readonly signer_id: string;
  readonly kind: SignerKind;
  readonly label: string;
  readonly profile: OwnerCredentialProfile;
  /** Passkey credential ID (base64url), so a later ceremony can name it. */
  readonly credentialId: string | null;
  /** EIP-6963 wallet reverse-DNS identifier. */
  readonly rdns: string | null;
  /** Unix milliseconds of the last sign-in, for ordering only. */
  readonly lastUsedAt: number;
}

const STORAGE_KEY = "oaath.portal.signers/v1";

function readOne(value: unknown): RememberedSigner | null {
  if (!value || typeof value !== "object") return null;
  const entry = value as Record<string, unknown>;
  try {
    if (
      typeof entry.signer_id !== "string" ||
      !["passkey", "wallet", "phone"].includes(entry.kind as string) ||
      typeof entry.label !== "string" ||
      (entry.credentialId !== null && typeof entry.credentialId !== "string") ||
      (entry.rdns !== null && typeof entry.rdns !== "string") ||
      typeof entry.lastUsedAt !== "number"
    )
      return null;
    return {
      signer_id: entry.signer_id,
      kind: entry.kind as SignerKind,
      label: entry.label.slice(0, 64),
      profile: parseOwnerCredentialProfile(entry.profile),
      credentialId: entry.credentialId,
      rdns: entry.rdns,
      lastUsedAt: entry.lastUsedAt,
    };
  } catch {
    return null;
  }
}

/** Remembered signers, most recently used first. Unreadable entries are dropped. */
export function rememberedSigners(): RememberedSigner[] {
  try {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "[]") as unknown;
    if (!Array.isArray(stored)) return [];
    return stored
      .map(readOne)
      .filter((entry): entry is RememberedSigner => entry !== null)
      .sort((left, right) => right.lastUsedAt - left.lastUsedAt);
  } catch {
    return [];
  }
}

/** Inserts or refreshes one signer by `signer_id`. */
export function rememberSigner(signer: RememberedSigner): RememberedSigner[] {
  const next = [signer, ...rememberedSigners().filter((s) => s.signer_id !== signer.signer_id)];
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  } catch {
    // Storage may be unavailable (private mode); the sign-in still proceeds.
  }
  return next;
}

export interface NewSigner {
  readonly kind: SignerKind;
  readonly label: string;
  readonly profile: OwnerCredentialProfile;
  readonly credentialId: string | null;
  readonly rdns: string | null;
  /** Set when the relay already knows the signer; registration is then skipped. */
  readonly signerId?: string;
}

/** Creates a passkey on this device and returns its public owner profile. */
export async function createPasskey(existing: readonly RememberedSigner[]): Promise<NewSigner> {
  const enrolled = await enrolWebAuthnCredential({
    rpId: location.hostname,
    userName: `OAAth passkey ${new Date().toISOString().slice(0, 10)}`,
    excludeCredentialIds: existing.flatMap((s) => (s.credentialId ? [s.credentialId] : [])),
  });
  return {
    kind: "passkey",
    label: "Passkey",
    profile: parseOwnerCredentialProfile({
      version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
      kind: "webauthn",
      publicKey: enrolled.profile.publicKey,
      authenticatorIdHash: enrolled.profile.authenticatorIdHash,
    }),
    credentialId: enrolled.credentialId,
    rdns: null,
  };
}

/**
 * Recognises a passkey this browser has not seen: the authenticator names one
 * of its discoverable credentials and the relay maps that ID to a signer.
 * Identification only: the assertion is discarded and nothing is verified,
 * because login carries no signature. `null` means OAAth does not know it.
 */
export async function identifyPasskey(): Promise<NewSigner | null> {
  if (typeof navigator.credentials?.get !== "function")
    throw Object.assign(new Error("passkeys unavailable"), { code: "unsupported" });
  let credential: Credential | null;
  try {
    credential = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: location.hostname,
        allowCredentials: [],
        userVerification: "preferred",
        timeout: 60_000,
      },
    });
  } catch (error) {
    throw Object.assign(new Error("passkey prompt failed"), {
      code:
        error instanceof DOMException && error.name === "SecurityError"
          ? "rp-mismatch"
          : "cancelled",
    });
  }
  if (!credential || !/^[A-Za-z0-9_-]{1,1366}$/u.test(credential.id))
    throw Object.assign(new Error("no passkey"), { code: "cancelled" });
  let identified: Awaited<ReturnType<typeof portalApi.signerByCredential>>;
  try {
    identified = await portalApi.signerByCredential(credential.id);
  } catch (error) {
    if (error instanceof PortalApiError && error.status === 404) return null;
    throw error;
  }
  return {
    kind: "passkey",
    label: "Passkey",
    profile: parseOwnerCredentialProfile(identified.profile),
    credentialId: credential.id,
    rdns: null,
    signerId: identified.signer_id,
  };
}

/** EIP-1193 provider surface the portal uses: account access only. */
interface Eip1193Provider {
  request(args: { method: "eth_requestAccounts" }): Promise<unknown>;
}

export interface AnnouncedWallet {
  readonly info: { readonly uuid: string; readonly name: string; readonly rdns: string };
  readonly provider: Eip1193Provider;
}

/**
 * EIP-6963 discovery: reports every wallet announced so far and each later
 * announcement, until the returned function stops listening.
 */
export function watchWallets(onChange: (wallets: AnnouncedWallet[]) => void): () => void {
  const wallets = new Map<string, AnnouncedWallet>();
  const listener = (event: Event) => {
    const detail = (event as CustomEvent<AnnouncedWallet>).detail;
    if (
      typeof detail?.info?.uuid === "string" &&
      typeof detail.info.name === "string" &&
      typeof detail.info.rdns === "string" &&
      typeof detail.provider?.request === "function"
    ) {
      wallets.set(detail.info.uuid, detail);
      onChange([...wallets.values()]);
    }
  };
  window.addEventListener("eip6963:announceProvider", listener);
  window.dispatchEvent(new Event("eip6963:requestProvider"));
  return () => window.removeEventListener("eip6963:announceProvider", listener);
}

/** Asks the wallet for its account; no signature is requested. */
export async function connectWallet(wallet: AnnouncedWallet): Promise<NewSigner> {
  const accounts = await wallet.provider.request({ method: "eth_requestAccounts" });
  const address = Array.isArray(accounts) ? accounts[0] : undefined;
  return {
    kind: "wallet",
    label: wallet.info.name.slice(0, 64),
    profile: parseOwnerCredentialProfile({
      version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
      kind: "ecdsa",
      address,
    }),
    credentialId: null,
    rdns: wallet.info.rdns,
  };
}

export function shortAddress(address: string): string {
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

/** A short public identifier to tell signers apart. */
export function signerDetail(profile: OwnerCredentialProfile): string {
  if (profile.kind === "ecdsa") return shortAddress(profile.address);
  return `Key ${profile.publicKey.slice(4, 12)}`;
}
