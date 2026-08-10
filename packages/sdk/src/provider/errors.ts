/**
 * The numeric error surface owned by the OAAth EIP-1193 provider.
 *
 * Callers select only a structured code. Messages come from this closed table,
 * so descriptor failures, adapters, and execution owners cannot leak internal
 * exception text through the wallet RPC boundary.
 *
 * @author taek <leekt216@gmail.com>
 */
import { OaathClientError, type OaathClientErrorCode } from "../client/errors.js";

export const CONTRACT_CREATION_UNSUPPORTED = -32000;
export const INVALID_PARAMS = -32602;
export const INTERNAL_ERROR = -32603;
export const USER_REJECTED_REQUEST = 4001;
export const UNAUTHORIZED = 4100;
export const UNSUPPORTED_METHOD = 4200;
export const UNSUPPORTED_CAPABILITY = 5700;
export const UNSUPPORTED_CHAIN = 5710;
export const DUPLICATE_ID = 5720;
export const UNKNOWN_BUNDLE_ID = 5730;
export const BUNDLE_TOO_LARGE = 5740;
export const ATOMIC_UPGRADE_REJECTED = 5750;
export const ATOMICITY_UNSUPPORTED = 5760;

export type OaathProviderErrorCode =
  | typeof CONTRACT_CREATION_UNSUPPORTED
  | typeof INVALID_PARAMS
  | typeof INTERNAL_ERROR
  | typeof USER_REJECTED_REQUEST
  | typeof UNAUTHORIZED
  | typeof UNSUPPORTED_METHOD
  | typeof UNSUPPORTED_CAPABILITY
  | typeof UNSUPPORTED_CHAIN
  | typeof DUPLICATE_ID
  | typeof UNKNOWN_BUNDLE_ID
  | typeof BUNDLE_TOO_LARGE
  | typeof ATOMIC_UPGRADE_REJECTED
  | typeof ATOMICITY_UNSUPPORTED;

const PROVIDER_ERROR_MESSAGE_RECORD: Record<OaathProviderErrorCode, string> = {
  [-32000]: "Contract creation is not supported",
  [-32602]: "Invalid params",
  [-32603]: "Internal error",
  4001: "User Rejected Request",
  4100: "Unauthorized",
  4200: "Unsupported Method",
  5700: "Unsupported non-optional capability",
  5710: "Unsupported chain id",
  5720: "Duplicate ID",
  5730: "Unknown bundle id",
  5740: "Bundle too large",
  5750: "Atomic-ready wallet rejected upgrade",
  5760: "Atomicity not supported",
};

/** The only messages an OAAth provider error may expose. */
export const OAATH_PROVIDER_ERROR_MESSAGES = Object.freeze(PROVIDER_ERROR_MESSAGE_RECORD);

export class OaathProviderRpcError extends Error {
  readonly code: OaathProviderErrorCode;

  constructor(code: OaathProviderErrorCode) {
    super(OAATH_PROVIDER_ERROR_MESSAGES[code]);
    this.name = "OaathProviderRpcError";
    this.code = code;
  }
}

/**
 * Throws a provider error whose message is selected only by its numeric code.
 * Optional owner diagnostics are accepted for call-site context and discarded.
 */
export function rpcFail(code: OaathProviderErrorCode, _ownerDiagnostic?: string): never {
  throw new OaathProviderRpcError(code);
}

/** Capture-failure callback that deliberately discards protocol diagnostic prose. */
export function invalidProviderParams(): never {
  return rpcFail(INVALID_PARAMS);
}

const UNAUTHORIZED_CLIENT_ERRORS: readonly OaathClientErrorCode[] = Object.freeze([
  "oaath_client_closed",
  "oaath_client_signed_out",
  "oaath_client_grant_inactive",
  "oaath_client_scope_denied",
]);

/**
 * Projects the SDK's structured client failures onto the fixed provider table.
 * Only the outer request envelope can opt an input failure into `-32602`; all
 * input passed to lower owners has already been captured and is an invariant
 * failure if those owners reject it.
 */
export function mapProviderFailure(error: unknown, appOwnedInput = false): never {
  if (error instanceof OaathProviderRpcError) throw error;
  if (error instanceof OaathClientError) {
    if (error.code === "oaath_client_input_invalid" && appOwnedInput) {
      return rpcFail(INVALID_PARAMS);
    }
    if (
      error.code === "oaath_client_capability_unsupported" &&
      error.source === "chain_not_configured"
    ) {
      return rpcFail(UNSUPPORTED_CHAIN);
    }
    if (UNAUTHORIZED_CLIENT_ERRORS.includes(error.code)) return rpcFail(UNAUTHORIZED);
    if (error.code === "oaath_client_permission_rejected") {
      return rpcFail(USER_REJECTED_REQUEST);
    }
  }
  return rpcFail(INTERNAL_ERROR);
}

/**
 * Refuses an otherwise syntactically valid request without claiming malformed
 * params. In particular, OAAth uses this for contract-creation calls: EIP-5792
 * permits an omitted `to`, but OAAth has no deployment policy that can authorize
 * executing it. The generic fixed message reveals no execution-owner details.
 */
export function refuseProviderExecution(): never {
  return rpcFail(CONTRACT_CREATION_UNSUPPORTED);
}
