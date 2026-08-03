/**
 * Connect/consent envelope.
 *
 * This is a thin wrapper: the scoped authority request itself stays owned by
 * `permission-protocol.ts`, including its hashes. The envelope only adds the
 * actors and proves they agree with the permission request's own application
 * binding, so an issuer never renders consent for a mismatched client, origin,
 * or device.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type ClientBinding, captureClientBinding } from "../actors/client.js";
import { captureIssuerIdentity, type IssuerIdentity } from "../actors/issuer.js";
import { captureSubjectBinding, type SubjectBinding } from "../actors/subject.js";
import { capturedByProtocol, protocolFailure } from "../errors.js";
import { type CaptureContext, type CaptureFailure, exactRecord } from "../internal/exact-record.js";
import { type PermissionRequest, parsePermissionRequest } from "../permission-protocol.js";

export const OAATH_AUTHORIZATION_REQUEST_VERSION = "oaath.authorization-request/v1" as const;

export interface AuthorizationRequest {
  readonly version: typeof OAATH_AUTHORIZATION_REQUEST_VERSION;
  readonly issuer: Readonly<IssuerIdentity>;
  readonly client: Readonly<ClientBinding>;
  readonly subject: Readonly<SubjectBinding>;
  /** The unmodified scoped authority request owned by `permission-protocol.ts`. */
  readonly permission: Readonly<PermissionRequest>;
}

export function captureAuthorizationRequest(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<AuthorizationRequest> {
  const record = exactRecord(
    value,
    ["version", "issuer", "client", "subject", "permission"],
    "authorization request",
    context,
    fail,
  );
  if (record.version !== OAATH_AUTHORIZATION_REQUEST_VERSION) {
    return fail("authorization request version is unsupported");
  }
  const issuer = captureIssuerIdentity(record.issuer, context, fail);
  const client = captureClientBinding(record.client, context, fail);
  const subject = captureSubjectBinding(record.subject, context, fail);
  const permission = parsePermissionRequest(record.permission);
  if (subject.issuer !== issuer.url) {
    return fail("authorization request subject belongs to another issuer");
  }
  if (subject.clientId !== client.clientId) {
    return fail("authorization request subject belongs to another client");
  }
  if (permission.application.clientId !== client.clientId) {
    return fail("authorization request permission belongs to another client");
  }
  if (permission.application.origin !== client.origin) {
    return fail("authorization request permission belongs to another origin");
  }
  if (permission.application.deviceId !== subject.deviceId) {
    return fail("authorization request permission belongs to another device");
  }
  return Object.freeze({
    version: OAATH_AUTHORIZATION_REQUEST_VERSION,
    issuer,
    client,
    subject,
    permission,
  });
}

export function parseAuthorizationRequest(value: unknown): Readonly<AuthorizationRequest> {
  return capturedByProtocol(
    "authorization_request_invalid",
    "authorization request could not be captured safely",
    () =>
      captureAuthorizationRequest(
        value,
        new WeakSet(),
        protocolFailure("authorization_request_invalid"),
      ),
  );
}
