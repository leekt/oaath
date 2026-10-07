/**
 * The application-facing failure surface.
 *
 * Every owner underneath this boundary already fails closed with its own
 * structured code: `OaathStoreError`, `OaathOperationRunnerError`,
 * `OaathKernelRuntimeError`, `OaathRoutingError`, `OaathPersistenceError`, and
 * the `@oaath/protocol` errors. An application cannot depend on eight closed
 * vocabularies, and it must never branch on prose, so this module projects them
 * onto one closed client vocabulary and keeps the originating code as a
 * structured `source` field. Message text is diagnostic only.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type CaptureContext,
  type CaptureFailure,
  captureRecord,
  captureValidationGasDiagnostic,
  type ExactRecord,
  exactCapturedRecord,
  type OaathUserOperationError,
  readUserOperationFailure,
  readValidationGasDiagnostic,
  type ValidationGasDiagnostic,
  validationGasDiagnosticMessage,
} from "@oaath/protocol";

export type OaathClientErrorCode =
  /** Application input is not a usable request. */
  | "oaath_client_input_invalid"
  /** A call review names a contract version this client does not implement. */
  | "oaath_client_review_version_unsupported"
  /** An injected capability is missing, malformed, or returned unusable evidence. */
  | "oaath_client_capability_invalid"
  /** The realm or handle is closed. */
  | "oaath_client_closed"
  /** The application signed out; authority handles no longer act. */
  | "oaath_client_signed_out"
  /** The issuer could not be reached or answered ambiguously. */
  | "oaath_client_issuer_unavailable"
  /** The issuer answered with a structured refusal. */
  | "oaath_client_issuer_rejected"
  /** No terminal owner decision is available yet. */
  | "oaath_client_decision_unavailable"
  /** The owner rejected the permission request. */
  | "oaath_client_permission_rejected"
  /** The Grant is not active, or is expired, revoking, or revoked. */
  | "oaath_client_grant_inactive"
  /** The calls are not conclusively covered by the approved Grant scope. */
  | "oaath_client_scope_denied"
  /** Local durable state disagrees with itself, or another writer won. */
  | "oaath_client_state_conflict"
  /** Durable local storage is unavailable or its commit is unverifiable. */
  | "oaath_client_store_unavailable"
  /** A required runtime, module, or materialization capability is not available. */
  | "oaath_client_capability_unsupported"
  /** No safe submission route exists before signing. */
  | "oaath_client_route_unavailable"
  /** Preparing the exact operation identity failed before any send. */
  | "oaath_client_preparation_failed"
  /** The authority credential could not sign. */
  | "oaath_client_signing_failed"
  /** A send was attempted and its outcome is unknown; never resubmit. */
  | "oaath_client_submission_uncertain"
  /** Observation could not conclude; retry observation, never submission. */
  | "oaath_client_observation_unavailable"
  /** The user cancelled sign-in (OAuth `access_denied`) or closed its window. */
  | "oaath_client_access_denied"
  /** The browser blocked the sign-in popup; call login from a user gesture. */
  | "oaath_client_popup_blocked"
  /** Sign-in did not finish in time. */
  | "oaath_client_login_timeout"
  /** The authorization response names another issuer (RFC 9207). */
  | "oaath_client_issuer_mismatch"
  /** The authorization response belongs to another login. */
  | "oaath_client_state_mismatch"
  /** The id_token failed signature, issuer, audience, nonce, or claim checks. */
  | "oaath_client_identity_invalid"
  /** An internal invariant failed; nothing about authority may be inferred. */
  | "oaath_client_internal";

export class OaathClientError extends Error {
  readonly code: OaathClientErrorCode;
  /** The structured code of the owner that failed, never prose. */
  readonly source: string | null;
  readonly failure: Readonly<OaathUserOperationError> | null;
  readonly diagnostic: Readonly<ValidationGasDiagnostic> | null;

  constructor(
    code: OaathClientErrorCode,
    message: string,
    source: string | null = null,
    diagnostic: Readonly<ValidationGasDiagnostic> | null = null,
    options?: ErrorOptions,
  ) {
    const captured = captureValidationGasDiagnostic(diagnostic);
    super(captured === null ? message : validationGasDiagnosticMessage(captured), options);
    this.name = "OaathClientError";
    this.code = code;
    this.source = source;
    this.failure = readUserOperationFailure(options?.cause);
    this.diagnostic = captured;
  }
}

export function clientFail(
  code: OaathClientErrorCode,
  message: string,
  source: string | null = null,
  diagnostic: Readonly<ValidationGasDiagnostic> | null = null,
  options?: ErrorOptions,
): never {
  throw new OaathClientError(code, message, source, diagnostic, options);
}

export function clientFailure(code: OaathClientErrorCode): CaptureFailure {
  return (message) => clientFail(code, message);
}

/** Exact capture at the application boundary: unknown or missing keys fail closed. */
export function exactClientRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
  context: CaptureContext,
  code: OaathClientErrorCode = "oaath_client_input_invalid",
): ExactRecord {
  const fail = clientFailure(code);
  return exactCapturedRecord(captureRecord(value, label, context, fail), keys, label, fail);
}

export function clientCapability<Capability>(value: unknown, label: string): Capability {
  if (typeof value !== "function") {
    return clientFail("oaath_client_capability_invalid", `${label} must be a function capability`);
  }
  return value as Capability;
}

const STORE_CONFLICTS: readonly string[] = Object.freeze([
  "store_key_mismatch",
  "store_identity_mismatch",
  "store_lane_occupied",
  "store_record_invalid",
  "store_input_invalid",
  "store_revision_exhausted",
]);

const RUNNER_CODES: Readonly<Record<string, OaathClientErrorCode>> = Object.freeze({
  operation_runner_input_invalid: "oaath_client_input_invalid",
  operation_runner_capability_invalid: "oaath_client_capability_invalid",
  operation_runner_preparation_failed: "oaath_client_preparation_failed",
  operation_runner_identity_mismatch: "oaath_client_state_conflict",
  operation_runner_state_conflict: "oaath_client_state_conflict",
  operation_runner_store_unavailable: "oaath_client_store_unavailable",
  operation_runner_store_uncertain: "oaath_client_store_unavailable",
  operation_runner_closed: "oaath_client_closed",
  operation_runner_close_failed: "oaath_client_internal",
});

const KERNEL_CODES: Readonly<Record<string, OaathClientErrorCode>> = Object.freeze({
  kernel_runtime_input_invalid: "oaath_client_input_invalid",
  kernel_runtime_chain_unsupported: "oaath_client_capability_unsupported",
  kernel_runtime_evidence_invalid: "oaath_client_capability_unsupported",
  kernel_runtime_validator_unavailable: "oaath_client_capability_unsupported",
  kernel_runtime_signer_unavailable: "oaath_client_capability_unsupported",
  kernel_runtime_policy_unavailable: "oaath_client_capability_unsupported",
  kernel_runtime_signing_failed: "oaath_client_signing_failed",
  kernel_runtime_signature_invalid: "oaath_client_signing_failed",
  kernel_runtime_binding_mismatch: "oaath_client_state_conflict",
  kernel_runtime_deployment_mismatch: "oaath_client_state_conflict",
  kernel_runtime_nonce_mismatch: "oaath_client_state_conflict",
  kernel_runtime_call_forbidden: "oaath_client_scope_denied",
});

const BY_NAME: Readonly<Record<string, OaathClientErrorCode>> = Object.freeze({
  OaathStoreError: "oaath_client_store_unavailable",
  OaathPersistenceError: "oaath_client_store_unavailable",
  OaathOperationObserverError: "oaath_client_observation_unavailable",
  OaathRoutingError: "oaath_client_capability_invalid",
  OaathGrantError: "oaath_client_state_conflict",
  OaathOperationError: "oaath_client_state_conflict",
  OaathGrantPolicyError: "oaath_client_input_invalid",
  OaathIdentityProfileError: "oaath_client_input_invalid",
  OaathPermissionProtocolError: "oaath_client_state_conflict",
  OaathProtocolError: "oaath_client_input_invalid",
  OaathPreparedUserOperationError: "oaath_client_preparation_failed",
  OaathRpcError: "oaath_client_preparation_failed",
});

function structured(error: unknown): Readonly<{ name: string; code: string | null }> {
  if (!(error instanceof Error)) return { name: "", code: null };
  const code = (error as { readonly code?: unknown }).code;
  return { name: error.name, code: typeof code === "string" ? code : null };
}

/**
 * Projects an internal failure onto the client vocabulary. An unrecognized
 * failure becomes `oaath_client_internal` rather than being guessed into an
 * authority, submission, or observation claim.
 */
export function mapClientFailure(error: unknown, fallbackMessage: string): never {
  if (error instanceof OaathClientError) throw error;
  const { name, code } = structured(error);
  const diagnostic = readValidationGasDiagnostic(error);
  if (name === "OaathOperationRunnerError" && code !== null && code in RUNNER_CODES) {
    clientFail(RUNNER_CODES[code] ?? "oaath_client_internal", fallbackMessage, code, diagnostic, {
      cause: error,
    });
  }
  if (name === "OaathKernelRuntimeError" && code !== null && code in KERNEL_CODES) {
    // Forward the capability's own failure (e.g. EIP-1193 4001) so `error.cause.code` reads it directly.
    const cause = (error as Error).cause;
    clientFail(
      KERNEL_CODES[code] ?? "oaath_client_internal",
      fallbackMessage,
      code,
      null,
      cause === undefined ? undefined : { cause },
    );
  }
  if (name === "OaathStoreError" && code !== null) {
    clientFail(
      code === "store_closed"
        ? "oaath_client_closed"
        : STORE_CONFLICTS.includes(code)
          ? "oaath_client_state_conflict"
          : "oaath_client_store_unavailable",
      fallbackMessage,
      code,
    );
  }
  clientFail(BY_NAME[name] ?? "oaath_client_internal", fallbackMessage, code, diagnostic, {
    cause: error,
  });
}
