/**
 * Owner operation approval through the issuer's portal popup.
 *
 * ```text
 * requestOwnerOperationApproval()  opens a blank popup at once (inside the click)
 *                                  PAR authorization_details
 *                                  [{ type: "oaath_operation", request }]
 *                                  popup -> the account root reviews and signs
 *                                  the exact UserOperation hash
 *                                  token -> [{ type: "oaath_operation", signed }]
 *                                  the signed request must be exactly ours;
 *                                  verifyOwnerOperation checks the account
 *                                  binding and the root's signature
 * ```
 *
 * OAAth never submits: the caller sends the verified `userOperation` through
 * its own bundler.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type OwnerOperationRequest, parseOwnerOperationRequest } from "@oaath/protocol";
import {
  type VerifiedOwnerOperation,
  verifyOwnerOperation,
} from "../kernel/operator/owner-operation.js";
import { clientFail, exactClientRecord, mapClientFailure } from "./errors.js";
import {
  authorizeThroughPopup,
  type OaathLoginOptions,
  openAuthorizationPopup,
} from "./oauth-login.js";

export interface OaathOwnerOperationApprovalOptions extends OaathLoginOptions {
  /** The exact unsigned owner operation, for example from `prepareOwnerOperation`. */
  readonly request: Readonly<OwnerOperationRequest>;
}

/**
 * Asks the account root to approve one owner operation in the issuer's portal
 * and returns it verified, ready to submit. Call it directly from a user
 * gesture: the popup opens before anything is awaited. A signed operation for
 * any other request fails with `oaath_client_state_conflict`.
 */
export async function requestOwnerOperationApproval(
  value: OaathOwnerOperationApprovalOptions,
): Promise<Readonly<VerifiedOwnerOperation>> {
  const popup = openAuthorizationPopup();
  try {
    if (!value || typeof value !== "object")
      return clientFail("oaath_client_input_invalid", "approval options are required");
    const { request: requestValue, ...options } = value;
    let request: Readonly<OwnerOperationRequest>;
    try {
      request = parseOwnerOperationRequest(requestValue);
    } catch (error) {
      return mapClientFailure(error, "the owner operation request is invalid");
    }
    const { released } = await authorizeThroughPopup(popup, options, {
      authorization_details: JSON.stringify([{ type: "oaath_operation", request }]),
    });
    // An owner operation is decided by the root in the popup; it never waits.
    if (released === null)
      return clientFail("oaath_client_issuer_rejected", "the issuer left the operation pending");
    const mismatch = (): never =>
      clientFail(
        "oaath_client_state_conflict",
        "the signed operation is not the one this application requested",
        "oauth_operation_mismatch",
      );
    const details = released.token.authorization_details;
    if (!Array.isArray(details) || details.length !== 1) return mismatch();
    const detail = exactClientRecord(
      details[0],
      ["type", "signed"],
      "OAuth operation detail",
      new WeakSet(),
      "oaath_client_issuer_unavailable",
    );
    if (detail.type !== "oaath_operation") return mismatch();
    const signed = detail.signed as { request?: unknown } | null;
    if (JSON.stringify(signed?.request) !== JSON.stringify(request)) return mismatch();
    // A WebAuthn root asserts for the issuer's own relying party.
    const issuer = new URL(options.issuer);
    try {
      return await verifyOwnerOperation(signed, { rpId: issuer.hostname, origin: issuer.origin });
    } catch (error) {
      return mapClientFailure(error, "the signed owner operation does not verify");
    }
  } finally {
    popup.close();
  }
}
