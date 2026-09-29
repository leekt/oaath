import { sha256Base64Url } from "../authorization/challenge.js";

/** Bounded base64url match code length. 48 bits is plenty to compare by eye. */
export const NATIVE_DISPLAY_PAYLOAD_LENGTH = 8;
export const NATIVE_DISPLAY_DOMAIN = "oaath.native-display/v1:";

/** One non-secret comparison code for the requesting app, phone, inbox, and push. */
export async function ownerPhoneDisplayPayload(
  ownerSubject: string,
  operationId: string,
): Promise<string> {
  const digest = await sha256Base64Url(`${NATIVE_DISPLAY_DOMAIN}${ownerSubject}:${operationId}`);
  return digest.slice(0, NATIVE_DISPLAY_PAYLOAD_LENGTH);
}
