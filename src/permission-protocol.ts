import { encodeAbiParameters, type Hex, keccak256 } from "viem";
import {
  type ApplicationBinding,
  advanceGrant,
  createGrant,
  type Grant,
  parseGrant,
  type RequestedGrant,
  sameGrantIdentity,
} from "./grant.js";
import {
  type GrantPolicy,
  hashGrantPolicy,
  isGrantPolicyAttenuation,
  parseGrantPolicy,
} from "./grant-policy.js";
import type {
  KernelAccountProfile,
  OperatorCredentialProfile,
  OwnerCredentialProfile,
} from "./identity-profile.js";
import {
  type CaptureContext,
  captureRecord,
  exactCapturedRecord,
  exactRecord,
} from "./internal/exact-record.js";

export const OGP_PERMISSION_REQUEST_VERSION = "ogp.permission-request/v1" as const;
export const OGP_PERMISSION_DECISION_VERSION = "ogp.permission-decision/v1" as const;
export const OGP_PERMISSION_REQUEST_HASH_DOMAIN = "@leekt/ogp:permission-request" as const;
export const OGP_PERMISSION_DECISION_HASH_DOMAIN = "@leekt/ogp:permission-decision" as const;

const OWNER_PROFILE_HASH_DOMAIN = "@leekt/ogp:owner-credential-profile";
const OPERATOR_PROFILE_HASH_DOMAIN = "@leekt/ogp:operator-credential-profile";
const KERNEL_PROFILE_HASH_DOMAIN = "@leekt/ogp:kernel-account-profile";
const HASH = /^0x[0-9a-f]{64}$/u;
const ZERO_HASH = `0x${"00".repeat(32)}`;
const MAX_UINT48 = 2 ** 48 - 1;
const MAX_REQUEST_ID_LENGTH = 256;

export type PermissionProtocolErrorCode =
  | "permission_request_invalid"
  | "permission_decision_invalid"
  | "permission_protocol_input_invalid"
  | "permission_request_binding_mismatch"
  | "permission_decision_binding_mismatch"
  | "permission_decision_conflict"
  | "permission_decision_stale"
  | "permission_policy_widening";

export class OgpPermissionProtocolError extends Error {
  readonly code: PermissionProtocolErrorCode;

  constructor(code: PermissionProtocolErrorCode, message: string) {
    super(message);
    this.name = "OgpPermissionProtocolError";
    this.code = code;
  }
}

export interface PermissionRequest {
  readonly version: typeof OGP_PERMISSION_REQUEST_VERSION;
  /** The requested Grant uses this exact identifier as grantId. */
  readonly requestId: string;
  readonly application: Readonly<ApplicationBinding>;
  readonly chainScope: "all";
  readonly logicalAccount: Readonly<KernelAccountProfile>;
  readonly operatorCredential: Readonly<OperatorCredentialProfile>;
  readonly policy: Readonly<GrantPolicy>;
  readonly requestedAt: number;
  /** Exclusive Grant expiry. The inclusive policy expiry must be earlier. */
  readonly expiresAt: number;
}

interface PermissionDecisionCommon {
  readonly version: typeof OGP_PERMISSION_DECISION_VERSION;
  readonly requestId: string;
  readonly requestHash: `0x${string}`;
  readonly decidedAt: number;
}

export interface RejectPermissionDecision extends PermissionDecisionCommon {
  readonly kind: "reject";
}

export interface ApprovePermissionDecision extends PermissionDecisionCommon {
  readonly kind: "approve";
  readonly approvedPolicy: Readonly<GrantPolicy>;
  /** Commitment to the separately owned replayable approval/recovery capability. */
  readonly capabilityHash: `0x${string}`;
}

export type PermissionDecision = RejectPermissionDecision | ApprovePermissionDecision;

export type PermissionDecisionObservation =
  | Readonly<{ status: "available"; decision: PermissionDecision }>
  | Readonly<{
      status: "unavailable";
      reason: "missing" | "timeout" | "unreadable";
    }>;

export interface ApplyPermissionDecisionInput {
  readonly request: PermissionRequest;
  readonly grant: Grant;
  readonly observation: PermissionDecisionObservation;
  readonly evaluatedAt: number;
}

export type ApplyPermissionDecisionResult =
  | Readonly<{
      status: "pending";
      reason: "missing" | "timeout" | "unreadable";
      grant: Grant;
    }>
  | Readonly<{
      status: "applied" | "replayed";
      decisionHash: `0x${string}`;
      grant: Grant;
    }>;

function invalid(code: PermissionProtocolErrorCode, message: string): never {
  throw new OgpPermissionProtocolError(code, message);
}

function failFor(code: PermissionProtocolErrorCode): (message: string) => never {
  return (message) => invalid(code, message);
}

function captureFailure<Value>(code: PermissionProtocolErrorCode, action: () => Value): Value {
  try {
    return action();
  } catch (error) {
    if (error instanceof OgpPermissionProtocolError) throw error;
    return invalid(code, "permission protocol input could not be captured safely");
  }
}

function safeUint48(value: unknown, label: string, code: PermissionProtocolErrorCode): number {
  if (
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    (value as number) < 0 ||
    (value as number) > MAX_UINT48
  ) {
    return invalid(code, `${label} must be a nonnegative uint48 safe integer`);
  }
  return value as number;
}

function requestId(value: unknown, code: PermissionProtocolErrorCode): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_REQUEST_ID_LENGTH ||
    value !== value.trim()
  ) {
    return invalid(code, "permission requestId must be a bounded canonical string");
  }
  return value;
}

function hash(
  value: unknown,
  label: string,
  code: PermissionProtocolErrorCode,
  allowZero = true,
): `0x${string}` {
  if (typeof value !== "string" || !HASH.test(value) || (!allowZero && value === ZERO_HASH)) {
    return invalid(code, `${label} must be a${allowZero ? "" : " nonzero"} lowercase hash`);
  }
  return value as `0x${string}`;
}

function captureRequest(
  value: unknown,
  code: PermissionProtocolErrorCode,
  context: CaptureContext,
): Readonly<PermissionRequest> {
  const record = exactRecord(
    value,
    [
      "version",
      "requestId",
      "application",
      "chainScope",
      "logicalAccount",
      "operatorCredential",
      "policy",
      "requestedAt",
      "expiresAt",
    ],
    "permission request",
    context,
    failFor(code),
  );
  if (record.version !== OGP_PERMISSION_REQUEST_VERSION) {
    return invalid(code, "permission request version is unsupported");
  }
  if (record.chainScope !== "all") {
    return invalid(code, "permission request chainScope must be all");
  }
  const policy = parseGrantPolicy(record.policy);
  const requestedAt = safeUint48(record.requestedAt, "permission request requestedAt", code);
  const expiresAt = safeUint48(record.expiresAt, "permission request expiresAt", code);
  if (expiresAt <= requestedAt) {
    return invalid(code, "permission request expiresAt must follow requestedAt");
  }
  if (
    policy.validUntil === null ||
    policy.validUntil < requestedAt ||
    policy.validUntil >= expiresAt
  ) {
    return invalid(
      code,
      "permission policy must have a finite inclusive expiry within the Grant lifetime",
    );
  }
  const grant = createGrant({
    identity: {
      grantId: requestId(record.requestId, code),
      application: record.application,
      chainScope: "all",
      logicalAccount: record.logicalAccount,
      operatorCredential: record.operatorCredential,
      policyHash: hashGrantPolicy(policy),
    },
    requestedAt,
    expiresAt,
  });
  return Object.freeze({
    version: OGP_PERMISSION_REQUEST_VERSION,
    requestId: grant.identity.grantId,
    application: grant.identity.application,
    chainScope: "all",
    logicalAccount: grant.identity.logicalAccount,
    operatorCredential: grant.identity.operatorCredential,
    policy,
    requestedAt,
    expiresAt,
  });
}

export function parsePermissionRequest(value: unknown): Readonly<PermissionRequest> {
  return captureFailure("permission_request_invalid", () =>
    captureRequest(value, "permission_request_invalid", new WeakSet()),
  );
}

function encodeOwnerCredential(profile: OwnerCredentialProfile): Hex {
  if (profile.kind === "ecdsa") {
    return encodeAbiParameters(
      [{ type: "string" }, { type: "string" }, { type: "string" }, { type: "address" }],
      [OWNER_PROFILE_HASH_DOMAIN, profile.version, profile.kind, profile.address],
    );
  }
  if (profile.kind === "p256") {
    return encodeAbiParameters(
      [{ type: "string" }, { type: "string" }, { type: "string" }, { type: "bytes" }],
      [OWNER_PROFILE_HASH_DOMAIN, profile.version, profile.kind, profile.publicKey],
    );
  }
  return encodeAbiParameters(
    [
      { type: "string" },
      { type: "string" },
      { type: "string" },
      { type: "bytes" },
      { type: "bytes32" },
    ],
    [
      OWNER_PROFILE_HASH_DOMAIN,
      profile.version,
      profile.kind,
      profile.publicKey,
      profile.authenticatorIdHash,
    ],
  );
}

function hashKernelAccountProfile(profile: KernelAccountProfile): `0x${string}` {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "string" },
        { type: "string" },
        { type: "string" },
        { type: "uint256" },
        { type: "string" },
        { type: "string" },
        { type: "string" },
        { type: "bytes32" },
      ],
      [
        KERNEL_PROFILE_HASH_DOMAIN,
        profile.version,
        profile.kind,
        BigInt(profile.accountIndex),
        profile.kernelVersion,
        profile.factoryRoute,
        profile.entryPoint.version,
        keccak256(encodeOwnerCredential(profile.ownerCredential)),
      ],
    ),
  );
}

function hashOperatorCredential(profile: OperatorCredentialProfile): `0x${string}` {
  if (profile.kind === "ecdsa") {
    return keccak256(
      encodeAbiParameters(
        [{ type: "string" }, { type: "string" }, { type: "string" }, { type: "address" }],
        [OPERATOR_PROFILE_HASH_DOMAIN, profile.version, profile.kind, profile.address],
      ),
    );
  }
  return keccak256(
    encodeAbiParameters(
      [
        { type: "string" },
        { type: "string" },
        { type: "string" },
        { type: "bytes" },
        { type: "bytes32" },
      ],
      [
        OPERATOR_PROFILE_HASH_DOMAIN,
        profile.version,
        profile.kind,
        profile.publicKey,
        profile.authenticatorIdHash,
      ],
    ),
  );
}

function encodeCapturedPermissionRequest(request: PermissionRequest): Hex {
  return encodeAbiParameters(
    [
      { type: "string", name: "domain" },
      { type: "string", name: "version" },
      { type: "string", name: "requestId" },
      { type: "string", name: "chainScope" },
      {
        type: "tuple",
        name: "application",
        components: [
          { type: "string", name: "applicationId" },
          { type: "string", name: "clientId" },
          { type: "string", name: "origin" },
          { type: "string", name: "deviceId" },
        ],
      },
      { type: "bytes32", name: "logicalAccountHash" },
      { type: "bytes32", name: "operatorCredentialHash" },
      { type: "bytes32", name: "policyHash" },
      { type: "uint48", name: "requestedAt" },
      { type: "uint48", name: "expiresAt" },
    ],
    [
      OGP_PERMISSION_REQUEST_HASH_DOMAIN,
      request.version,
      request.requestId,
      request.chainScope,
      request.application,
      hashKernelAccountProfile(request.logicalAccount),
      hashOperatorCredential(request.operatorCredential),
      hashGrantPolicy(request.policy),
      request.requestedAt,
      request.expiresAt,
    ],
  );
}

export function encodePermissionRequest(value: unknown): Hex {
  return encodeCapturedPermissionRequest(parsePermissionRequest(value));
}

export function hashPermissionRequest(value: unknown): `0x${string}` {
  return keccak256(encodePermissionRequest(value));
}

function grantFromCapturedRequest(request: PermissionRequest): RequestedGrant {
  return createGrant({
    identity: {
      grantId: request.requestId,
      application: request.application,
      chainScope: "all",
      logicalAccount: request.logicalAccount,
      operatorCredential: request.operatorCredential,
      policyHash: hashGrantPolicy(request.policy),
    },
    requestedAt: request.requestedAt,
    expiresAt: request.expiresAt,
  });
}

export function createGrantFromPermissionRequest(value: unknown): RequestedGrant {
  return grantFromCapturedRequest(parsePermissionRequest(value));
}

function captureDecision(
  value: unknown,
  code: PermissionProtocolErrorCode,
  context: CaptureContext,
): Readonly<PermissionDecision> {
  const captured = captureRecord(value, "permission decision", context, failFor(code));
  if (captured.kind === "reject") {
    const record = exactCapturedRecord(
      captured,
      ["version", "kind", "requestId", "requestHash", "decidedAt"],
      "reject permission decision",
      failFor(code),
    );
    if (record.version !== OGP_PERMISSION_DECISION_VERSION) {
      return invalid(code, "permission decision version is unsupported");
    }
    return Object.freeze({
      version: OGP_PERMISSION_DECISION_VERSION,
      kind: "reject",
      requestId: requestId(record.requestId, code),
      requestHash: hash(record.requestHash, "permission decision requestHash", code),
      decidedAt: safeUint48(record.decidedAt, "permission decision decidedAt", code),
    });
  }
  if (captured.kind === "approve") {
    const record = exactCapturedRecord(
      captured,
      [
        "version",
        "kind",
        "requestId",
        "requestHash",
        "decidedAt",
        "approvedPolicy",
        "capabilityHash",
      ],
      "approve permission decision",
      failFor(code),
    );
    if (record.version !== OGP_PERMISSION_DECISION_VERSION) {
      return invalid(code, "permission decision version is unsupported");
    }
    return Object.freeze({
      version: OGP_PERMISSION_DECISION_VERSION,
      kind: "approve",
      requestId: requestId(record.requestId, code),
      requestHash: hash(record.requestHash, "permission decision requestHash", code),
      decidedAt: safeUint48(record.decidedAt, "permission decision decidedAt", code),
      approvedPolicy: parseGrantPolicy(record.approvedPolicy),
      capabilityHash: hash(
        record.capabilityHash,
        "permission decision capabilityHash",
        code,
        false,
      ),
    });
  }
  return invalid(code, "permission decision kind is unsupported");
}

export function parsePermissionDecision(value: unknown): Readonly<PermissionDecision> {
  return captureFailure("permission_decision_invalid", () =>
    captureDecision(value, "permission_decision_invalid", new WeakSet()),
  );
}

function encodeCapturedPermissionDecision(decision: PermissionDecision): Hex {
  if (decision.kind === "reject") {
    return encodeAbiParameters(
      [
        { type: "string", name: "domain" },
        { type: "string", name: "version" },
        { type: "string", name: "kind" },
        { type: "string", name: "requestId" },
        { type: "bytes32", name: "requestHash" },
        { type: "uint48", name: "decidedAt" },
      ],
      [
        OGP_PERMISSION_DECISION_HASH_DOMAIN,
        decision.version,
        decision.kind,
        decision.requestId,
        decision.requestHash,
        decision.decidedAt,
      ],
    );
  }
  return encodeAbiParameters(
    [
      { type: "string", name: "domain" },
      { type: "string", name: "version" },
      { type: "string", name: "kind" },
      { type: "string", name: "requestId" },
      { type: "bytes32", name: "requestHash" },
      { type: "uint48", name: "decidedAt" },
      { type: "bytes32", name: "approvedPolicyHash" },
      { type: "bytes32", name: "capabilityHash" },
    ],
    [
      OGP_PERMISSION_DECISION_HASH_DOMAIN,
      decision.version,
      decision.kind,
      decision.requestId,
      decision.requestHash,
      decision.decidedAt,
      hashGrantPolicy(decision.approvedPolicy),
      decision.capabilityHash,
    ],
  );
}

export function encodePermissionDecision(value: unknown): Hex {
  return encodeCapturedPermissionDecision(parsePermissionDecision(value));
}

export function hashPermissionDecision(value: unknown): `0x${string}` {
  return keccak256(encodePermissionDecision(value));
}

function captureObservation(
  value: unknown,
  code: PermissionProtocolErrorCode,
  context: CaptureContext,
): Readonly<PermissionDecisionObservation> {
  const captured = captureRecord(value, "permission decision observation", context, failFor(code));
  if (captured.status === "available") {
    const record = exactCapturedRecord(
      captured,
      ["status", "decision"],
      "available permission decision observation",
      failFor(code),
    );
    return Object.freeze({
      status: "available",
      decision: captureDecision(record.decision, code, context),
    });
  }
  const record = exactCapturedRecord(
    captured,
    ["status", "reason"],
    "unavailable permission decision observation",
    failFor(code),
  );
  if (record.status !== "unavailable") {
    return invalid(code, "permission decision observation status is unsupported");
  }
  if (
    record.reason !== "missing" &&
    record.reason !== "timeout" &&
    record.reason !== "unreadable"
  ) {
    return invalid(code, "permission decision observation reason is unsupported");
  }
  return Object.freeze({ status: "unavailable", reason: record.reason });
}

function requireRequestGrantBinding(request: PermissionRequest, grant: Grant): void {
  const expected = grantFromCapturedRequest(request);
  if (
    !sameGrantIdentity(expected.identity, grant.identity) ||
    expected.requestedAt !== grant.requestedAt ||
    expected.expiresAt !== grant.expiresAt
  ) {
    invalid("permission_request_binding_mismatch", "permission request does not match the Grant");
  }
}

function requireDecisionRequestBinding(
  request: PermissionRequest,
  decision: PermissionDecision,
): void {
  if (
    decision.requestId !== request.requestId ||
    decision.requestHash !== keccak256(encodeCapturedPermissionRequest(request))
  ) {
    invalid(
      "permission_decision_binding_mismatch",
      "permission decision does not match the request",
    );
  }
  if (decision.decidedAt < request.requestedAt || decision.decidedAt >= request.expiresAt) {
    invalid("permission_decision_stale", "permission decision time is outside the request");
  }
  if (
    decision.kind === "approve" &&
    !isGrantPolicyAttenuation(request.policy, decision.approvedPolicy)
  ) {
    invalid("permission_policy_widening", "approved policy does not attenuate the request");
  }
}

function replayMatches(
  grant: Grant,
  decision: PermissionDecision,
  decisionHash: `0x${string}`,
): boolean {
  if (decision.kind === "reject") {
    return (
      grant.state === "rejected" &&
      grant.terminal.kind === "rejected" &&
      grant.terminal.recordedAt === decision.decidedAt
    );
  }
  return (
    grant.approval !== null &&
    grant.approval.approvalHash === decisionHash &&
    grant.approval.capabilityHash === decision.capabilityHash &&
    grant.approval.approvedAt === decision.decidedAt
  );
}

export function applyPermissionDecision(value: unknown): ApplyPermissionDecisionResult {
  return captureFailure("permission_protocol_input_invalid", () => {
    const code = "permission_protocol_input_invalid" as const;
    const context: CaptureContext = new WeakSet();
    const record = exactRecord(
      value,
      ["request", "grant", "observation", "evaluatedAt"],
      "apply permission decision input",
      context,
      failFor(code),
    );
    const request = captureRequest(record.request, code, context);
    const grant = parseGrant(record.grant);
    const observation = captureObservation(record.observation, code, context);
    const evaluatedAt = safeUint48(record.evaluatedAt, "permission decision evaluatedAt", code);
    requireRequestGrantBinding(request, grant);

    if (observation.status === "unavailable") {
      return Object.freeze({
        status: "pending",
        reason: observation.reason,
        grant,
      });
    }

    const decision = observation.decision;
    requireDecisionRequestBinding(request, decision);
    const decisionHash = keccak256(encodeCapturedPermissionDecision(decision));
    if (replayMatches(grant, decision, decisionHash)) {
      return Object.freeze({ status: "replayed", decisionHash, grant });
    }
    if (grant.state !== "requested") {
      return invalid("permission_decision_conflict", "a different decision already won");
    }
    if (decision.decidedAt > evaluatedAt || evaluatedAt >= request.expiresAt) {
      return invalid("permission_decision_stale", "permission decision is not currently usable");
    }
    if (
      decision.kind === "approve" &&
      decision.approvedPolicy.validUntil !== null &&
      evaluatedAt > decision.approvedPolicy.validUntil
    ) {
      return invalid("permission_decision_stale", "approved policy is already expired");
    }

    const nextGrant =
      decision.kind === "reject"
        ? advanceGrant(grant, {
            type: "reject",
            identity: grant.identity,
            rejectedAt: decision.decidedAt,
          })
        : advanceGrant(grant, {
            type: "approve",
            identity: grant.identity,
            approval: {
              approvalHash: decisionHash,
              capabilityHash: decision.capabilityHash,
              approvedAt: decision.decidedAt,
            },
          });
    return Object.freeze({ status: "applied", decisionHash, grant: nextGrant });
  });
}
