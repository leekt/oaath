/**
 * Shared capture errors for the protocol contracts.
 *
 * Each domain keeps its own error class and codes. Capture preserves those
 * structured failures and sanitizes foreign exceptions at the input boundary.
 *
 * @author taek <leekt216@gmail.com>
 */
import { OaathGrantError } from "./grant.js";
import { OaathGrantPolicyError } from "./grant-policy.js";
import { OaathIdentityProfileError } from "./identity-profile.js";
import { OaathOperationError } from "./operation.js";
import { OaathPermissionProtocolError } from "./permission-protocol.js";

/** Codes owned by shared identity, bootstrap, PKCE, and signing contracts. */
export type ProtocolContractErrorCode =
  | "protocol_id_invalid"
  | "client_binding_invalid"
  | "issuer_invalid"
  | "subject_binding_invalid"
  | "authorization_code_verifier_mismatch"
  | "grant_reference_invalid"
  | "service_bootstrap_invalid"
  | "signing_artifact_invalid"
  | "signing_request_invalid";

/** Raised by the shared protocol contract owners. */
export class OaathProtocolError extends Error {
  readonly code: ProtocolContractErrorCode;

  constructor(code: ProtocolContractErrorCode, message: string) {
    super(message);
    this.name = "OaathProtocolError";
    this.code = code;
  }
}

/** Fail-closed capture failure bound to one contract code. */
export function protocolFailure(code: ProtocolContractErrorCode): (message: string) => never {
  return (message) => {
    throw new OaathProtocolError(code, message);
  };
}

function isOwnedProtocolError(error: unknown): boolean {
  return (
    error instanceof OaathProtocolError ||
    error instanceof OaathGrantError ||
    error instanceof OaathGrantPolicyError ||
    error instanceof OaathIdentityProfileError ||
    error instanceof OaathOperationError ||
    error instanceof OaathPermissionProtocolError
  );
}

/**
 * Runs an exact capture so hostile reflection can never surface as a foreign
 * error type or leak a hostile message. Errors already raised by an owning
 * protocol module keep their own code.
 */
export function capturedByProtocol<Value>(
  code: ProtocolContractErrorCode,
  sanitizedMessage: string,
  action: () => Value,
): Value {
  try {
    return action();
  } catch (error) {
    if (isOwnedProtocolError(error)) throw error;
    throw new OaathProtocolError(code, sanitizedMessage);
  }
}
