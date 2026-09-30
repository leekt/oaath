/**
 * Captures one public credential profile for a key. Owns only the version
 * dispatch between owner and operator profiles; neither role changes a key's
 * public material or signing.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type CaptureContext,
  captureRecord,
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  type OperatorCredentialProfile,
  type OwnerCredentialProfile,
  parseOperatorCredentialProfile,
  parseOwnerCredentialProfile,
} from "@oaath/protocol";
import { inputInvalid } from "../internal.js";

/**
 * An owner or operator credential profile, dispatched on its own version. The
 * role a profile names is authority semantics owned by the operator; a key
 * only consumes its public material.
 */
export function parsePublicCredential(
  value: unknown,
  context: CaptureContext,
  label: string,
): Readonly<OwnerCredentialProfile | OperatorCredentialProfile> {
  const captured = captureRecord(value, "public credential", context, inputInvalid);
  try {
    return captured.version === OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION
      ? parseOperatorCredentialProfile(captured)
      : parseOwnerCredentialProfile(captured);
  } catch {
    return inputInvalid(`${label} requires a valid public credential profile`);
  }
}
