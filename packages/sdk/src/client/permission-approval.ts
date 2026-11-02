/**
 * A root-approved permission for a caller-held session credential, through
 * the issuer's portal popup, with no realm, session custody or journal.
 *
 * ```text
 * requestPermissionApproval()  opens a blank popup at once (inside the click)
 *                              PAR authorization_details
 *                              [{ type: "oaath_grant", signer, policy, chains,
 *                                 expires_at, device_id }]
 *                              popup -> the account root reviews and signs
 *                              the Kernel enable
 *                              token -> [{ type: "oaath_grant", grant_id,
 *                                          permission_request, decision, enable }]
 *                              the request must be exactly ours, the decision
 *                              must bind it, and the approval must install
 *                              exactly the signer's packages under the policy;
 *                              a Kernel 0.3.3 approval's root signature is
 *                              checked offline
 * ```
 *
 * The caller keeps the session key and executes with the returned decision's
 * `installApproval` (`materializeKernelPermission`). A Kernel 0.4.0 approval's
 * root signature is verified by Kernel on chain at install, as in the realm.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type GrantPolicy,
  hashPermissionRequest,
  OAATH_PERMISSION_DECISION_VERSION,
  type OperatorCredentialProfile,
  type PermissionRequest,
  parseGrantPolicy,
  parseOperatorCredentialProfile,
  parsePermissionRequest,
} from "@oaath/protocol";
import {
  kernelGrantCapabilityHash,
  parseVersionedKernelGrantApproval,
  verifyKernelPermissionApproval,
} from "../kernel/permission/approval.js";
import { grantPermissionPackages } from "../kernel/permission/grant-packages.js";
import type { KernelPermissionDecision } from "../kernel/permission/prepare-approval.js";
import { OAATH_KERNEL_V33_APPROVAL_VERSION } from "../kernel/permission/v33.js";
import { clientFail, exactClientRecord, mapClientFailure } from "./errors.js";
import {
  authorizeThroughPopup,
  authorizeWithLauncher,
  type OaathAuthorizationLauncher,
  type OaathLogin,
  type OaathLoginOptions,
  openAuthorizationPopup,
} from "./oauth-login.js";

export interface OaathPermissionApprovalOptions extends OaathLoginOptions {
  /** The session credential the permission installs; the caller holds its key. */
  readonly signer: Readonly<OperatorCredentialProfile>;
  /** The exact policy; the root approves it unchanged. */
  readonly policy: Readonly<GrantPolicy>;
  /** Chain IDs shown to the root; the approval itself covers every chain. */
  readonly chains: readonly number[];
  /** Unix seconds after which the request can no longer be approved. */
  readonly expiresAt: number;
  /** The caller's stable identifier for the device holding the session key. */
  readonly deviceId: string;
  /**
   * A popup the caller opened synchronously in the user's gesture (with
   * `openAuthorizationPopup`), for a caller that must await before asking.
   * The redirect page runs `completeOAAthLogin`. Closed when this settles.
   */
  readonly popup?: Window;
  /** Opens the portal somewhere other than a popup and resolves with the redirect URL. */
  readonly launch?: OaathAuthorizationLauncher;
}

export interface OaathApprovedPermission {
  readonly request: Readonly<PermissionRequest>;
  /** The decision with its `installApproval`, as `materializeKernelPermission` consumes it. */
  readonly decision: Readonly<KernelPermissionDecision>;
  /** The signed-in root and the account it chose. */
  readonly login: Readonly<OaathLogin>;
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

/**
 * Asks the account root to approve one permission for `signer` under `policy`
 * in the issuer's portal and returns it verified. Call it directly from a
 * user gesture, or pass the `popup` opened in one: the popup opens before
 * anything is awaited. Only the account root decides in the popup.
 *
 * Fails with `oaath_client_popup_blocked`; `oaath_client_access_denied` when
 * the user cancels or the root denies; `oaath_client_issuer_rejected` with
 * source `oauth_permission_pending` when a member's request awaits the root,
 * or without it when the issuer refuses; and `oaath_client_state_conflict`
 * with source `oauth_grant_mismatch` for any approval other than the one asked.
 */
export async function requestPermissionApproval(
  value: OaathPermissionApprovalOptions,
): Promise<Readonly<OaathApprovedPermission>> {
  if (!value || typeof value !== "object")
    return clientFail("oaath_client_input_invalid", "approval options are required");
  const {
    signer: signerValue,
    policy: policyValue,
    chains,
    expiresAt,
    deviceId,
    popup: given,
    launch,
    ...options
  } = value;
  if (launch !== undefined && typeof launch !== "function")
    return clientFail("oaath_client_capability_invalid", "launch must be a function");
  if (launch !== undefined && given !== undefined)
    return clientFail("oaath_client_input_invalid", "pass a popup or a launcher, not both");
  // Open inside the user's gesture, before anything is awaited.
  const popup = launch ? null : (given ?? openAuthorizationPopup());
  try {
    let signer: Readonly<OperatorCredentialProfile>;
    let policy: Readonly<GrantPolicy>;
    try {
      signer = parseOperatorCredentialProfile(signerValue);
      policy = parseGrantPolicy(policyValue);
    } catch (error) {
      return mapClientFailure(error, "the permission signer or policy is invalid");
    }
    if (
      !Array.isArray(chains) ||
      chains.length === 0 ||
      !chains.every((chain) => Number.isSafeInteger(chain) && chain > 0) ||
      !Number.isSafeInteger(expiresAt) ||
      typeof deviceId !== "string" ||
      deviceId === ""
    )
      return clientFail("oaath_client_input_invalid", "chains, expiresAt or deviceId is invalid");
    const detail = {
      type: "oaath_grant",
      signer,
      policy,
      chains,
      expires_at: expiresAt,
      device_id: deviceId,
    };
    const extra = { authorization_details: JSON.stringify([detail]) };
    const { released } = popup
      ? await authorizeThroughPopup(popup, options, extra)
      : await authorizeWithLauncher(launch as OaathAuthorizationLauncher, options, extra);
    if (released === null)
      return clientFail(
        "oaath_client_issuer_rejected",
        "the request awaits the account root",
        "oauth_permission_pending",
      );
    const { token, login } = released;
    const mismatch = (): never =>
      clientFail(
        "oaath_client_state_conflict",
        "the approved permission is not the one this application requested",
        "oauth_grant_mismatch",
      );
    const details = token.authorization_details;
    if (!Array.isArray(details) || details.length !== 1) return mismatch();
    const granted = exactClientRecord(
      details[0],
      ["type", "grant_id", "permission_request", "decision", "enable"],
      "OAuth grant detail",
      new WeakSet(),
      "oaath_client_issuer_unavailable",
    );
    let request: Readonly<PermissionRequest>;
    try {
      request = parsePermissionRequest(granted.permission_request);
    } catch (error) {
      return mapClientFailure(error, "the approved permission request is invalid");
    }
    if (
      granted.type !== "oaath_grant" ||
      granted.grant_id !== request.requestId ||
      !same(request.operatorCredential, signer) ||
      !same(request.application, {
        applicationId: options.clientId,
        clientId: options.clientId,
        origin: new URL(options.redirectUri).origin,
        deviceId,
      }) ||
      !same(request.policy, policy) ||
      request.expiresAt !== expiresAt ||
      request.chainScope !== "all" ||
      request.sessionSigner !== null ||
      !same(request.logicalAccount, login.accountProfile) ||
      request.context.accountId !== login.account
    )
      return mismatch();

    // The decision binds this request, approves its policy unchanged, and
    // commits to this exact approval.
    const decision = exactClientRecord(
      granted.decision,
      [
        "version",
        "kind",
        "requestId",
        "requestHash",
        "decidedAt",
        "approvedPolicy",
        "capabilityHash",
      ],
      "OAuth grant decision",
      new WeakSet(),
      "oaath_client_issuer_unavailable",
    );
    let approval: ReturnType<typeof parseVersionedKernelGrantApproval>;
    try {
      approval = parseVersionedKernelGrantApproval(granted.enable);
    } catch {
      return mismatch();
    }
    if (
      decision.version !== OAATH_PERMISSION_DECISION_VERSION ||
      decision.kind !== "approve" ||
      decision.requestId !== request.requestId ||
      decision.requestHash !== hashPermissionRequest(request) ||
      !same(decision.approvedPolicy, policy) ||
      decision.capabilityHash !== kernelGrantCapabilityHash(approval) ||
      approval.account !== login.account
    )
      return mismatch();

    // The approval installs exactly `signer` under `policy`.
    const { permissionId, packages, sessionKey } = grantPermissionPackages({ signer, policy });
    if (!same(approval.packages, packages)) return mismatch();
    if (approval.version === OAATH_KERNEL_V33_APPROVAL_VERSION) {
      const owner = request.logicalAccount.ownerCredential;
      if (owner.kind !== "ecdsa" || approval.permissionId !== permissionId) return mismatch();
      const verified = await verifyKernelPermissionApproval({
        approval,
        expected: {
          owner: owner.address,
          account: login.account,
          permissionId,
          sessionKey,
          packages,
        },
      });
      if (verified.status !== "verified") return mismatch();
    }
    return Object.freeze({
      request,
      decision: Object.freeze({
        ...(decision as unknown as KernelPermissionDecision),
        installApproval: approval,
      }),
      login,
    });
  } finally {
    popup?.close();
  }
}
