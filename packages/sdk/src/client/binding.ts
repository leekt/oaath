/**
 * Issuer, client, origin, device, subject, and logical account, captured once.
 *
 * Everything downstream — the wire envelopes, the permission request, the Grant
 * identity, the persisted realm key — reads this one immutable record instead of
 * re-validating application input. The actor rules themselves stay in
 * `@oaath/protocol`: this module composes `captureIssuerIdentity`,
 * `parseClientBinding`, `createSubjectBinding`, and the identity profiles, and
 * owns exactly one new fact, the binding id.
 *
 * The binding id names one realm: one issuer, application, client, origin,
 * device, pairwise subject, and account index. A realm holds at most one active
 * Grant in `0.1.0`, which is why an application never handles a grantId.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type ApplicationBinding,
  type CaptureContext,
  type ClientBinding,
  createSubjectBinding,
  type IssuerIdentity,
  type KernelAccountProfile,
  OAATH_CLIENT_BINDING_VERSION,
  OAATH_ISSUER_VERSION,
  type OperatorCredentialProfile,
  parseClientBinding,
  parseClientId,
  parseIssuerIdentity,
  parseKernelAccountProfile,
  parseOperatorCredentialProfile,
  type SubjectBinding,
} from "@oaath/protocol";
import { encodeAbiParameters, keccak256 } from "viem";
import { clientFail, clientFailure, exactClientRecord, mapClientFailure } from "./errors.js";

export const OAATH_BINDING_VERSION = "oaath.client-realm-binding/v1" as const;
export const OAATH_BINDING_HASH_DOMAIN = "@oaath/sdk:client-realm-binding" as const;

export interface OaathBindingInput {
  /** Canonical https issuer URL. */
  readonly issuer: string;
  readonly applicationId: string;
  readonly applicationName: string;
  readonly clientId: string;
  /** Canonical https web origin of the application. */
  readonly origin: string;
  /** Exact same-origin https redirect target the issuer may return a code to. */
  readonly redirectUri: string;
  readonly deviceId: string;
  /** Opaque issuer-scoped user handle; never persisted outside the subject binding. */
  readonly userHandle: string;
  /** Logical Kernel account profile, including the owner credential. */
  readonly account: unknown;
  /** Operator/session credential summary the Grant authorizes. */
  readonly operatorCredential: unknown;
}

export interface OaathBinding {
  readonly version: typeof OAATH_BINDING_VERSION;
  readonly bindingId: `0x${string}`;
  readonly issuer: Readonly<IssuerIdentity>;
  readonly client: Readonly<ClientBinding>;
  readonly application: Readonly<ApplicationBinding>;
  readonly subject: Readonly<SubjectBinding>;
  readonly redirectUri: string;
  readonly account: Readonly<KernelAccountProfile>;
  readonly operatorCredential: Readonly<OperatorCredentialProfile>;
}

const INPUT_KEYS: readonly string[] = Object.freeze([
  "issuer",
  "applicationId",
  "applicationName",
  "clientId",
  "origin",
  "redirectUri",
  "deviceId",
  "userHandle",
  "account",
  "operatorCredential",
]);

function deriveBindingId(input: {
  readonly issuer: string;
  readonly applicationId: string;
  readonly clientId: string;
  readonly origin: string;
  readonly deviceId: string;
  readonly subjectId: string;
  readonly accountIndex: string;
}): `0x${string}` {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "string", name: "domain" },
        { type: "string", name: "version" },
        { type: "string", name: "issuer" },
        { type: "string", name: "applicationId" },
        { type: "string", name: "clientId" },
        { type: "string", name: "origin" },
        { type: "string", name: "deviceId" },
        { type: "bytes32", name: "subjectId" },
        { type: "uint256", name: "accountIndex" },
      ],
      [
        OAATH_BINDING_HASH_DOMAIN,
        OAATH_BINDING_VERSION,
        input.issuer,
        input.applicationId,
        input.clientId,
        input.origin,
        input.deviceId,
        input.subjectId as `0x${string}`,
        BigInt(input.accountIndex),
      ],
    ),
  );
}

/** Captures the whole binding once, or fails closed without a partial realm. */
export function captureOaathBinding(value: unknown): Readonly<OaathBinding> {
  const context: CaptureContext = new WeakSet();
  const record = exactClientRecord(value, INPUT_KEYS, "OAAth binding", context);
  try {
    const issuer = parseIssuerIdentity({
      version: OAATH_ISSUER_VERSION,
      url: record.issuer,
    });
    const client = parseClientBinding({
      version: OAATH_CLIENT_BINDING_VERSION,
      clientId: record.clientId,
      origin: record.origin,
      redirectUris: [record.redirectUri],
      applicationName: record.applicationName,
    });
    const subject = createSubjectBinding({
      issuer: issuer.url,
      clientId: client.clientId,
      userHandle: record.userHandle,
      deviceId: record.deviceId,
    });
    const account = parseKernelAccountProfile(record.account);
    const operatorCredential = parseOperatorCredentialProfile(record.operatorCredential);
    const redirectUri = client.redirectUris[0];
    if (redirectUri === undefined) {
      return clientFail("oaath_client_input_invalid", "binding redirect URI is missing");
    }
    const application = Object.freeze({
      // Every canonical OAAth identifier shares one shape, owned by
      // `@oaath/protocol`'s ids module; applicationId is checked through it
      // rather than restating the pattern here.
      applicationId: parseClientId(
        record.applicationId,
        clientFailure("oaath_client_input_invalid"),
      ),
      clientId: client.clientId,
      origin: client.origin,
      deviceId: subject.deviceId,
    });
    return Object.freeze({
      version: OAATH_BINDING_VERSION,
      bindingId: deriveBindingId({
        issuer: issuer.url,
        applicationId: application.applicationId,
        clientId: application.clientId,
        origin: application.origin,
        deviceId: application.deviceId,
        subjectId: subject.subjectId,
        accountIndex: account.accountIndex,
      }),
      issuer,
      client,
      application,
      subject,
      redirectUri,
      account,
      operatorCredential,
    });
  } catch (error) {
    return mapClientFailure(error, "OAAth binding is invalid");
  }
}
