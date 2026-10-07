/**
 * Signing in: the signer proves control of its credential to the relay, which
 * answers a short-lived HttpOnly session cookie for that signer only. A wallet
 * signs the relay's Sign-In with Ethereum message (`personal_sign`); a passkey
 * asserts over the relay's nonce. Neither approves anything.
 *
 * @author taek <leekt216@gmail.com>
 */
import { p256 } from "@noble/curves/nist.js";
import { parseOwnerCredentialProfile } from "@oaath/protocol";
import { kernelKey } from "@oaath/sdk/kernel";
import { PortalApiError, portalApi } from "./api.js";
import { type AnnouncedWallet, type NewSigner, watchWallets } from "./signers.js";

/** A refusal with a closed code the screen turns into copy. */
export class SignInError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(`sign-in failed: ${code}`);
    this.name = "SignInError";
    this.code = code;
  }
}

function refuse(code: string): never {
  throw new SignInError(code);
}

/** The remembered wallet, once it announces itself again (EIP-6963). */
export function findWallet(rdns: string | null): Promise<AnnouncedWallet> {
  return new Promise((resolve, reject) => {
    let stop = () => {};
    const timer = setTimeout(() => {
      stop();
      reject(new SignInError("wallet-unavailable"));
    }, 3_000);
    stop = watchWallets((wallets) => {
      const wallet = wallets.find((entry) => entry.info.rdns === rdns);
      if (!wallet) return;
      clearTimeout(timer);
      queueMicrotask(() => stop());
      resolve(wallet);
    });
  });
}

function bytesFromHex(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(value.match(/../gu) ?? [], (pair) => Number.parseInt(pair, 16));
}

export function bytesFromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value.replace(/-/gu, "+").replace(/_/gu, "/"));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function hex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function word(value: bigint): `0x${string}` {
  return `0x${value.toString(16).padStart(64, "0")}`;
}

/** One WebAuthn assertion as the SDK's WebAuthn key profile takes it. */
export function assertionFields(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAssertionResponse;
  const signature = p256.Signature.fromDER(new Uint8Array(response.signature));
  const clientDataJSON = new TextDecoder().decode(response.clientDataJSON);
  return {
    authenticatorData: hex(new Uint8Array(response.authenticatorData)),
    clientDataJSON,
    responseTypeLocation: String(clientDataJSON.indexOf('"type":"webauthn.get"')),
    r: word(signature.r),
    s: word(signature.s),
  };
}

async function startSession(signerId: string, nonce: string, signature: string) {
  try {
    await portalApi.signIn({ signer_id: signerId, nonce, signature });
  } catch (error) {
    if (error instanceof PortalApiError && (error.status === 401 || error.status === 410))
      refuse("sign-in-refused");
    throw error;
  }
}

/** Signs a wallet signer in with the relay's SIWE message. */
export async function signInWallet(
  signerId: string,
  address: `0x${string}`,
  wallet: AnnouncedWallet | null,
  rdns: string | null,
): Promise<void> {
  const provider = (wallet ?? (await findWallet(rdns))).provider;
  const accounts = await provider.request({ method: "eth_requestAccounts" });
  if (!Array.isArray(accounts) || !accounts.some((entry) => entry?.toLowerCase?.() === address))
    return refuse("wallet-account-mismatch");
  const challenge = await portalApi.challenge({ signer_id: signerId });
  if (!challenge.message) return refuse("sign-in-refused");
  let signature: unknown;
  try {
    signature = await provider.request({
      method: "personal_sign",
      params: [hex(new TextEncoder().encode(challenge.message)), address],
    });
  } catch {
    return refuse("wallet-declined");
  }
  if (typeof signature !== "string") return refuse("wallet-declined");
  await startSession(signerId, challenge.nonce, signature);
}

async function assertPasskey(nonce: string, credentialId: string | null) {
  let credential: Credential | null;
  try {
    credential = await navigator.credentials.get({
      publicKey: {
        challenge: bytesFromHex(nonce),
        rpId: location.hostname,
        allowCredentials: credentialId
          ? [{ type: "public-key", id: bytesFromBase64Url(credentialId) }]
          : [],
        userVerification: "required",
        timeout: 60_000,
      },
    });
  } catch (error) {
    return refuse(
      error instanceof DOMException && error.name === "SecurityError" ? "rp-mismatch" : "cancelled",
    );
  }
  if (!credential || !/^[A-Za-z0-9_-]{1,1366}$/u.test(credential.id)) return refuse("cancelled");
  return credential as PublicKeyCredential;
}

/** The SDK's WebAuthn key profile signs (and self-verifies) the nonce. */
async function provePasskey(
  signer: Pick<NewSigner, "profile"> & { readonly signerId: string },
  credential: PublicKeyCredential,
  nonce: string,
) {
  if (signer.profile.kind !== "webauthn") return refuse("sign-in-refused");
  const fields = assertionFields(credential);
  const key = kernelKey({
    kind: "webauthn",
    credential: signer.profile,
    credentialId: credential.id,
    rpId: location.hostname,
    origin: location.origin,
    authenticate: async () => fields,
  });
  const signature = await key.sign(`0x${nonce}`);
  await startSession(signer.signerId, nonce, signature);
}

/** Signs a known passkey signer in: one assertion over the relay's nonce. */
export async function signInPasskey(signerId: string, signer: NewSigner): Promise<void> {
  const { nonce } = await portalApi.challenge({});
  const credential = await assertPasskey(nonce, signer.credentialId);
  await provePasskey({ ...signer, signerId }, credential, nonce);
}

/**
 * Recognises and signs in a passkey this browser has not seen, with one
 * assertion: the authenticator names one of its discoverable credentials,
 * the relay maps that ID to a signer, and the same assertion proves it.
 * `null` means OAAth does not know the passkey.
 */
export async function signInUnknownPasskey(): Promise<(NewSigner & { signerId: string }) | null> {
  if (typeof navigator.credentials?.get !== "function") return refuse("unsupported");
  const { nonce } = await portalApi.challenge({});
  const credential = await assertPasskey(nonce, null);
  let identified: Awaited<ReturnType<typeof portalApi.signerByCredential>>;
  try {
    identified = await portalApi.signerByCredential(credential.id);
  } catch (error) {
    if (error instanceof PortalApiError && error.status === 404) return null;
    throw error;
  }
  const signer = {
    kind: "passkey" as const,
    label: "Passkey",
    profile: parseOwnerCredentialProfile(identified.profile),
    credentialId: credential.id,
    rdns: null,
    signerId: identified.signer_id,
  };
  await provePasskey(signer, credential, nonce);
  return signer;
}
