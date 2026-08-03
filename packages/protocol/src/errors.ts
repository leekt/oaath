/**
 * The one closed machine-readable OAAth protocol error surface.
 *
 * Every owner keeps its own error class and codes; this module organizes those
 * codes into a single documented union plus the runtime set that wire and
 * server boundaries need. Nothing here renames an existing code, and no
 * decision may be made from `Error.message`.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type GrantErrorCode, OaathGrantError } from "./grant.js";
import { type GrantPolicyErrorCode, OaathGrantPolicyError } from "./grant-policy.js";
import { type IdentityProfileErrorCode, OaathIdentityProfileError } from "./identity-profile.js";
import { OaathOperationError, type OperationErrorCode } from "./operation.js";
import {
  OaathPermissionProtocolError,
  type PermissionProtocolErrorCode,
} from "./permission-protocol.js";

/** Codes owned by the runtime-neutral actor, authorization, and wire contracts. */
export type ProtocolContractErrorCode =
  | "protocol_id_invalid"
  | "protocol_time_invalid"
  | "client_binding_invalid"
  | "issuer_invalid"
  | "subject_binding_invalid"
  | "authorization_request_invalid"
  | "authorization_decision_invalid"
  | "authorization_code_invalid"
  | "authorization_code_transition_forbidden"
  | "authorization_code_verifier_mismatch"
  | "wire_envelope_invalid";

/** Every code any `@oaath/protocol` owner may raise. */
export type OaathProtocolErrorCode =
  | ProtocolContractErrorCode
  | GrantErrorCode
  | GrantPolicyErrorCode
  | IdentityProfileErrorCode
  | OperationErrorCode
  | PermissionProtocolErrorCode;

/**
 * Exhaustive closed table. `satisfies` fails the build when a code is added to
 * any owner union without being organized here.
 */
const CODES = {
  protocol_id_invalid: true,
  protocol_time_invalid: true,
  client_binding_invalid: true,
  issuer_invalid: true,
  subject_binding_invalid: true,
  authorization_request_invalid: true,
  authorization_decision_invalid: true,
  authorization_code_invalid: true,
  authorization_code_transition_forbidden: true,
  authorization_code_verifier_mismatch: true,
  wire_envelope_invalid: true,
  grant_input_invalid: true,
  grant_record_invalid: true,
  grant_transition_invalid: true,
  grant_identity_mismatch: true,
  grant_transition_forbidden: true,
  grant_revision_exhausted: true,
  grant_policy_invalid: true,
  grant_policy_attenuation_input_invalid: true,
  grant_policy_coverage_input_invalid: true,
  owner_credential_profile_invalid: true,
  operator_credential_profile_invalid: true,
  kernel_account_profile_invalid: true,
  kernel_account_action_input_invalid: true,
  operation_input_invalid: true,
  operation_record_invalid: true,
  operation_transition_invalid: true,
  operation_identity_mismatch: true,
  operation_transition_forbidden: true,
  operation_revision_exhausted: true,
  permission_request_invalid: true,
  permission_decision_invalid: true,
  permission_protocol_input_invalid: true,
  permission_request_binding_mismatch: true,
  permission_decision_binding_mismatch: true,
  permission_decision_conflict: true,
  permission_decision_stale: true,
  permission_policy_widening: true,
} satisfies Record<OaathProtocolErrorCode, true>;

export const OAATH_PROTOCOL_ERROR_CODES: readonly OaathProtocolErrorCode[] = Object.freeze(
  Object.keys(CODES) as OaathProtocolErrorCode[],
);

export function isOaathProtocolErrorCode(value: unknown): value is OaathProtocolErrorCode {
  return typeof value === "string" && Object.hasOwn(CODES, value);
}

/** Raised by the actor, authorization, and wire contract owners. */
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
