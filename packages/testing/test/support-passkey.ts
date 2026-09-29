import { OAATH_OWNER_CREDENTIAL_PROFILE_VERSION } from "@oaath/protocol";
import type { OaathSession } from "@oaath/sdk";
import { bytesToHex, concat, hexToBytes, keccak256, sha256, stringToBytes } from "viem";

/** A software passkey: WebCrypto P-256 signs exactly what an authenticator signs. */
export async function softwarePasskey(origin: string) {
  const rpId = new URL(origin).hostname;
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
  ]);
  const rawId = crypto.getRandomValues(new Uint8Array(16));
  let assertions = 0;
  const session: OaathSession = {
    kind: "webauthn",
    credential: {
      version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
      kind: "webauthn",
      publicKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))),
      authenticatorIdHash: keccak256(rawId),
    },
    credentialId: Buffer.from(rawId).toString("base64url"),
    rpId,
    origin,
    async authenticate(request) {
      assertions++;
      const clientDataJSON = JSON.stringify({
        type: "webauthn.get",
        challenge: request.challenge,
        origin,
        crossOrigin: false,
      });
      const authenticatorData = concat([sha256(stringToBytes(rpId)), "0x0500000001"]);
      const signed = new Uint8Array(
        hexToBytes(concat([authenticatorData, sha256(stringToBytes(clientDataJSON))])),
      );
      const signature = new Uint8Array(
        await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, signed),
      );
      return {
        authenticatorData,
        clientDataJSON,
        responseTypeLocation: String(clientDataJSON.indexOf('"type":"webauthn.get"')),
        r: bytesToHex(signature.slice(0, 32)),
        s: bytesToHex(signature.slice(32)),
      };
    },
  };
  return {
    session,
    get assertions() {
      return assertions;
    },
  };
}
