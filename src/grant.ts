import {
  type CaptureContext,
  captureDenseArray,
  captureRecord as captureExactRecord,
  type ExactRecord,
  exactCapturedRecord as exactCapturedRecordValue,
  exactRecord as exactRecordValue,
} from "./internal/exact-record.js";

export const OGP_GRANT_RECORD_VERSION = "ogp.grant/v1" as const;

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const PERMISSION_ID = /^0x[0-9a-f]{8}$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const IDENTIFIER = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_GRANT_ID_LENGTH = 256;

export type GrantErrorCode = "grant_input_invalid" | "grant_record_invalid";

export class OgpGrantError extends Error {
  readonly code: GrantErrorCode;

  constructor(code: GrantErrorCode, message: string) {
    super(message);
    this.name = "OgpGrantError";
    this.code = code;
  }
}

export type CredentialKind = "ecdsa" | "p256" | "webauthn";

export interface CredentialBinding {
  readonly kind: CredentialKind;
  readonly publicIdentityHash: `0x${string}`;
}

export interface GrantLogicalAccountProfile {
  readonly kind: "kernel";
  readonly accountIndex: string;
  readonly kernelVersion: string;
  readonly factoryRoute: "kernel_factory" | "meta_factory";
  readonly ownerCredential: Readonly<CredentialBinding>;
}

export interface GrantIdentity {
  readonly grantId: string;
  readonly chainScope: "all";
  readonly logicalAccount: Readonly<GrantLogicalAccountProfile>;
  readonly operatorCredential: Readonly<CredentialBinding>;
  readonly policyHash: `0x${string}`;
}

export interface ChainBinding {
  readonly chainId: number;
  readonly account: `0x${string}`;
  readonly permissionId: `0x${string}`;
}

export interface ChainPermissionEvidence extends ChainBinding {
  readonly kind: "permission_present" | "permission_absent";
  readonly blockNumber: string;
  readonly blockHash: `0x${string}`;
  readonly observedAt: number;
}

export type MaterializationUnsupportedReason =
  | "runtime_unsupported"
  | "account_profile_unsupported"
  | "policy_unsupported";

export type MaterializationUnreadableReason =
  | "provider_unavailable"
  | "state_invalid"
  | "canonicality_unproven";

export interface UnsupportedMaterialization {
  readonly state: "unsupported";
  readonly chainId: number;
  readonly updatedAt: number;
  readonly reason: MaterializationUnsupportedReason;
}

interface BoundMaterialization extends ChainBinding {
  readonly updatedAt: number;
}

export interface UnmaterializedMaterialization extends BoundMaterialization {
  readonly state: "unmaterialized";
}

export interface InstallingMaterialization extends BoundMaterialization {
  readonly state: "installing";
  readonly startedAt: number;
}

export interface InstalledMaterialization extends BoundMaterialization {
  readonly state: "installed";
  readonly installation: Readonly<ChainPermissionEvidence>;
}

export interface RevokingMaterialization extends BoundMaterialization {
  readonly state: "revoking";
  readonly installation: Readonly<ChainPermissionEvidence> | null;
  readonly startedAt: number;
}

export interface RevokedMaterialization extends BoundMaterialization {
  readonly state: "revoked";
  readonly installation: Readonly<ChainPermissionEvidence>;
  readonly removal: Readonly<ChainPermissionEvidence>;
}

export interface UnreadableMaterialization extends BoundMaterialization {
  readonly state: "unreadable";
  readonly priorState: "installing" | "installed" | "revoking";
  readonly installation: Readonly<ChainPermissionEvidence> | null;
  readonly reason: MaterializationUnreadableReason;
}

export type ChainMaterialization =
  | UnsupportedMaterialization
  | UnmaterializedMaterialization
  | InstallingMaterialization
  | InstalledMaterialization
  | RevokingMaterialization
  | RevokedMaterialization
  | UnreadableMaterialization;

export interface GrantApproval {
  readonly approvalHash: `0x${string}`;
  readonly capabilityHash: `0x${string}`;
  readonly approvedAt: number;
}

export interface GrantCapabilityInvalidation {
  readonly kind: "approval_capability_invalidated";
  readonly capabilityHash: `0x${string}`;
  readonly evidenceHash: `0x${string}`;
  readonly invalidatedAt: number;
}

export type GrantState =
  | "requested"
  | "rejected"
  | "approved"
  | "active"
  | "revoking"
  | "revoked"
  | "expired";

export type GrantTerminal =
  | Readonly<{ kind: "rejected"; recordedAt: number }>
  | Readonly<{ kind: "revoked"; recordedAt: number }>
  | Readonly<{
      kind: "expired";
      from: "requested" | "approved" | "active" | "revoking";
      recordedAt: number;
    }>;

interface GrantCommon {
  readonly version: typeof OGP_GRANT_RECORD_VERSION;
  readonly identity: Readonly<GrantIdentity>;
  readonly revision: number;
  readonly state: GrantState;
  readonly requestedAt: number;
  readonly expiresAt: number;
  readonly updatedAt: number;
  readonly approval: Readonly<GrantApproval> | null;
  readonly activatedAt: number | null;
  readonly revocationStartedAt: number | null;
  readonly capabilityInvalidation: Readonly<GrantCapabilityInvalidation> | null;
  readonly terminal: GrantTerminal | null;
  readonly materializations: readonly ChainMaterialization[];
}

export interface RequestedGrant extends GrantCommon {
  readonly state: "requested";
  readonly approval: null;
  readonly activatedAt: null;
  readonly revocationStartedAt: null;
  readonly capabilityInvalidation: null;
  readonly terminal: null;
}

export interface RejectedGrant extends GrantCommon {
  readonly state: "rejected";
  readonly approval: null;
  readonly activatedAt: null;
  readonly revocationStartedAt: null;
  readonly capabilityInvalidation: null;
  readonly terminal: Readonly<{ kind: "rejected"; recordedAt: number }>;
}

export interface ApprovedGrant extends GrantCommon {
  readonly state: "approved";
  readonly approval: Readonly<GrantApproval>;
  readonly activatedAt: null;
  readonly revocationStartedAt: null;
  readonly capabilityInvalidation: null;
  readonly terminal: null;
}

export interface ActiveGrant extends GrantCommon {
  readonly state: "active";
  readonly approval: Readonly<GrantApproval>;
  readonly activatedAt: number;
  readonly revocationStartedAt: null;
  readonly capabilityInvalidation: null;
  readonly terminal: null;
}

export interface RevokingGrant extends GrantCommon {
  readonly state: "revoking";
  readonly approval: Readonly<GrantApproval>;
  readonly activatedAt: number;
  readonly revocationStartedAt: number;
  readonly terminal: null;
}

export interface RevokedGrant extends GrantCommon {
  readonly state: "revoked";
  readonly approval: Readonly<GrantApproval>;
  readonly activatedAt: number;
  readonly revocationStartedAt: number;
  readonly capabilityInvalidation: Readonly<GrantCapabilityInvalidation>;
  readonly terminal: Readonly<{ kind: "revoked"; recordedAt: number }>;
}

export interface ExpiredGrant extends GrantCommon {
  readonly state: "expired";
  readonly terminal: Readonly<{
    kind: "expired";
    from: "requested" | "approved" | "active" | "revoking";
    recordedAt: number;
  }>;
}

export type Grant =
  | RequestedGrant
  | RejectedGrant
  | ApprovedGrant
  | ActiveGrant
  | RevokingGrant
  | RevokedGrant
  | ExpiredGrant;

type PlainRecord = ExactRecord;

function invalid(code: GrantErrorCode, message: string): never {
  throw new OgpGrantError(code, message);
}

function captureFailure(code: GrantErrorCode): (message: string) => never {
  return (message) => invalid(code, message);
}

function captureRecord(
  value: unknown,
  label: string,
  code: GrantErrorCode,
  context: CaptureContext,
): PlainRecord {
  return captureExactRecord(value, label, context, captureFailure(code));
}

function exactCapturedRecord(
  captured: PlainRecord,
  keys: readonly string[],
  label: string,
  code: GrantErrorCode,
): PlainRecord {
  return exactCapturedRecordValue(captured, keys, label, captureFailure(code));
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
  code: GrantErrorCode,
  context: CaptureContext,
): PlainRecord {
  return exactRecordValue(value, keys, label, context, captureFailure(code));
}

function safeInteger(value: unknown, label: string, code: GrantErrorCode, minimum = 0): number {
  if (!Number.isSafeInteger(value) || Object.is(value, -0) || (value as number) < minimum) {
    return invalid(code, `${label} must be a safe integer at least ${minimum}`);
  }
  return value as number;
}

function canonicalGrantId(value: unknown, code: GrantErrorCode): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_GRANT_ID_LENGTH ||
    value !== value.trim()
  ) {
    return invalid(code, "grantId must be a bounded canonical string");
  }
  return value;
}

function address(value: unknown, label: string, code: GrantErrorCode): `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value) || value === ZERO_ADDRESS) {
    return invalid(code, `${label} must be a nonzero lowercase 20-byte address`);
  }
  return value as `0x${string}`;
}

function hash(value: unknown, label: string, code: GrantErrorCode): `0x${string}` {
  if (typeof value !== "string" || !HASH.test(value)) {
    return invalid(code, `${label} must be a lowercase 32-byte hash`);
  }
  return value as `0x${string}`;
}

function permissionId(value: unknown, label: string, code: GrantErrorCode): `0x${string}` {
  if (typeof value !== "string" || !PERMISSION_ID.test(value)) {
    return invalid(code, `${label} must be a lowercase 4-byte permission ID`);
  }
  return value as `0x${string}`;
}

function uint256(value: unknown, label: string, code: GrantErrorCode): string {
  if (typeof value !== "string" || !DECIMAL_UINT.test(value) || BigInt(value) > MAX_UINT256) {
    return invalid(code, `${label} must be a canonical decimal uint256 string`);
  }
  return value;
}

function identifier(value: unknown, label: string, code: GrantErrorCode): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    return invalid(code, `${label} must be a bounded canonical identifier`);
  }
  return value;
}

function parseCredential(
  value: unknown,
  label: string,
  code: GrantErrorCode,
  context: CaptureContext,
): Readonly<CredentialBinding> {
  const record = exactRecord(value, ["kind", "publicIdentityHash"], label, code, context);
  if (record.kind !== "ecdsa" && record.kind !== "p256" && record.kind !== "webauthn") {
    return invalid(code, `${label} kind is unsupported`);
  }
  return Object.freeze({
    kind: record.kind,
    publicIdentityHash: hash(record.publicIdentityHash, `${label} publicIdentityHash`, code),
  });
}

function parseLogicalAccount(
  value: unknown,
  code: GrantErrorCode,
  context: CaptureContext,
): Readonly<GrantLogicalAccountProfile> {
  const record = exactRecord(
    value,
    ["kind", "accountIndex", "kernelVersion", "factoryRoute", "ownerCredential"],
    "grant logical account",
    code,
    context,
  );
  if (record.kind !== "kernel") return invalid(code, "logical account kind is unsupported");
  if (record.factoryRoute !== "kernel_factory" && record.factoryRoute !== "meta_factory") {
    return invalid(code, "logical account factory route is unsupported");
  }
  return Object.freeze({
    kind: record.kind,
    accountIndex: uint256(record.accountIndex, "logical account index", code),
    kernelVersion: identifier(record.kernelVersion, "logical account kernelVersion", code),
    factoryRoute: record.factoryRoute,
    ownerCredential: parseCredential(record.ownerCredential, "owner credential", code, context),
  });
}

function parseIdentity(
  value: unknown,
  code: GrantErrorCode,
  context: CaptureContext,
): Readonly<GrantIdentity> {
  const record = exactRecord(
    value,
    ["grantId", "chainScope", "logicalAccount", "operatorCredential", "policyHash"],
    "grant identity",
    code,
    context,
  );
  if (record.chainScope !== "all") return invalid(code, "grant chainScope must be all");
  return Object.freeze({
    grantId: canonicalGrantId(record.grantId, code),
    chainScope: "all",
    logicalAccount: parseLogicalAccount(record.logicalAccount, code, context),
    operatorCredential: parseCredential(
      record.operatorCredential,
      "operator credential",
      code,
      context,
    ),
    policyHash: hash(record.policyHash, "grant policyHash", code),
  });
}

function parsePermissionEvidence(
  value: unknown,
  expectedKind: ChainPermissionEvidence["kind"],
  code: GrantErrorCode,
  context: CaptureContext,
): Readonly<ChainPermissionEvidence> {
  const record = exactRecord(
    value,
    ["kind", "chainId", "account", "permissionId", "blockNumber", "blockHash", "observedAt"],
    "chain permission evidence",
    code,
    context,
  );
  if (record.kind !== expectedKind) {
    return invalid(code, `chain permission evidence must be ${expectedKind}`);
  }
  return Object.freeze({
    kind: expectedKind,
    chainId: safeInteger(record.chainId, "permission evidence chainId", code, 1),
    account: address(record.account, "permission evidence account", code),
    permissionId: permissionId(record.permissionId, "permission evidence permissionId", code),
    blockNumber: uint256(record.blockNumber, "permission evidence blockNumber", code),
    blockHash: hash(record.blockHash, "permission evidence blockHash", code),
    observedAt: safeInteger(record.observedAt, "permission evidence observedAt", code),
  });
}

function parseApproval(
  value: unknown,
  code: GrantErrorCode,
  context: CaptureContext,
): Readonly<GrantApproval> | null {
  if (value === null) return null;
  const record = exactRecord(
    value,
    ["approvalHash", "capabilityHash", "approvedAt"],
    "grant approval",
    code,
    context,
  );
  return Object.freeze({
    approvalHash: hash(record.approvalHash, "grant approvalHash", code),
    capabilityHash: hash(record.capabilityHash, "grant capabilityHash", code),
    approvedAt: safeInteger(record.approvedAt, "grant approvedAt", code),
  });
}

function parseInvalidation(
  value: unknown,
  code: GrantErrorCode,
  context: CaptureContext,
): Readonly<GrantCapabilityInvalidation> | null {
  if (value === null) return null;
  const record = exactRecord(
    value,
    ["kind", "capabilityHash", "evidenceHash", "invalidatedAt"],
    "grant capability invalidation",
    code,
    context,
  );
  if (record.kind !== "approval_capability_invalidated") {
    return invalid(code, "grant capability invalidation kind is unsupported");
  }
  return Object.freeze({
    kind: record.kind,
    capabilityHash: hash(record.capabilityHash, "invalidation capabilityHash", code),
    evidenceHash: hash(record.evidenceHash, "invalidation evidenceHash", code),
    invalidatedAt: safeInteger(record.invalidatedAt, "grant invalidatedAt", code),
  });
}

function parseTerminal(
  value: unknown,
  code: GrantErrorCode,
  context: CaptureContext,
): GrantTerminal | null {
  if (value === null) return null;
  const captured = captureRecord(value, "grant terminal", code, context);
  if (captured.kind === "rejected" || captured.kind === "revoked") {
    const record = exactCapturedRecord(captured, ["kind", "recordedAt"], "grant terminal", code);
    return Object.freeze({
      kind: captured.kind,
      recordedAt: safeInteger(record.recordedAt, "grant terminal recordedAt", code),
    });
  }
  if (captured.kind === "expired") {
    const record = exactCapturedRecord(
      captured,
      ["kind", "from", "recordedAt"],
      "grant terminal",
      code,
    );
    if (
      record.from !== "requested" &&
      record.from !== "approved" &&
      record.from !== "active" &&
      record.from !== "revoking"
    ) {
      return invalid(code, "expired grant source state is unsupported");
    }
    return Object.freeze({
      kind: "expired",
      from: record.from,
      recordedAt: safeInteger(record.recordedAt, "grant terminal recordedAt", code),
    });
  }
  return invalid(code, "grant terminal kind is unsupported");
}

function bindingFields(record: PlainRecord, code: GrantErrorCode): ChainBinding {
  return {
    chainId: safeInteger(record.chainId, "materialization chainId", code, 1),
    account: address(record.account, "materialization account", code),
    permissionId: permissionId(record.permissionId, "materialization permissionId", code),
  };
}

function evidenceMatchesBinding(evidence: ChainPermissionEvidence, binding: ChainBinding): boolean {
  return (
    evidence.chainId === binding.chainId &&
    evidence.account === binding.account &&
    evidence.permissionId === binding.permissionId
  );
}

function parseNullableInstallation(
  value: unknown,
  code: GrantErrorCode,
  context: CaptureContext,
): Readonly<ChainPermissionEvidence> | null {
  return value === null
    ? null
    : parsePermissionEvidence(value, "permission_present", code, context);
}

function parseMaterialization(
  value: unknown,
  code: GrantErrorCode,
  context: CaptureContext,
): ChainMaterialization {
  const captured = captureRecord(value, "chain materialization", code, context);
  const state = captured.state;

  if (state === "unsupported") {
    const record = exactCapturedRecord(
      captured,
      ["state", "chainId", "updatedAt", "reason"],
      "unsupported materialization",
      code,
    );
    if (
      record.reason !== "runtime_unsupported" &&
      record.reason !== "account_profile_unsupported" &&
      record.reason !== "policy_unsupported"
    ) {
      return invalid(code, "unsupported materialization reason is unsupported");
    }
    return Object.freeze({
      state,
      chainId: safeInteger(record.chainId, "materialization chainId", code, 1),
      updatedAt: safeInteger(record.updatedAt, "materialization updatedAt", code),
      reason: record.reason,
    });
  }

  const common = ["state", "chainId", "account", "permissionId", "updatedAt"] as const;
  if (state === "unmaterialized") {
    const record = exactCapturedRecord(captured, common, "unmaterialized materialization", code);
    return Object.freeze({
      state,
      ...bindingFields(record, code),
      updatedAt: safeInteger(record.updatedAt, "materialization updatedAt", code),
    });
  }

  if (state === "installing") {
    const record = exactCapturedRecord(
      captured,
      [...common, "startedAt"],
      "installing materialization",
      code,
    );
    const binding = bindingFields(record, code);
    const updatedAt = safeInteger(record.updatedAt, "materialization updatedAt", code);
    const startedAt = safeInteger(record.startedAt, "materialization startedAt", code);
    if (startedAt !== updatedAt) return invalid(code, "installing materialization time conflicts");
    return Object.freeze({ state, ...binding, updatedAt, startedAt });
  }

  if (state === "installed") {
    const record = exactCapturedRecord(
      captured,
      [...common, "installation"],
      "installed materialization",
      code,
    );
    const binding = bindingFields(record, code);
    const installation = parsePermissionEvidence(
      record.installation,
      "permission_present",
      code,
      context,
    );
    const updatedAt = safeInteger(record.updatedAt, "materialization updatedAt", code);
    if (!evidenceMatchesBinding(installation, binding) || installation.observedAt !== updatedAt) {
      return invalid(code, "installed materialization evidence conflicts");
    }
    return Object.freeze({ state, ...binding, updatedAt, installation });
  }

  if (state === "revoking") {
    const record = exactCapturedRecord(
      captured,
      [...common, "installation", "startedAt"],
      "revoking materialization",
      code,
    );
    const binding = bindingFields(record, code);
    const installation = parseNullableInstallation(record.installation, code, context);
    const updatedAt = safeInteger(record.updatedAt, "materialization updatedAt", code);
    const startedAt = safeInteger(record.startedAt, "materialization startedAt", code);
    if (
      (installation && !evidenceMatchesBinding(installation, binding)) ||
      (installation && installation.observedAt > updatedAt) ||
      startedAt > updatedAt
    ) {
      return invalid(code, "revoking materialization evidence conflicts");
    }
    return Object.freeze({ state, ...binding, updatedAt, installation, startedAt });
  }

  if (state === "revoked") {
    const record = exactCapturedRecord(
      captured,
      [...common, "installation", "removal"],
      "revoked materialization",
      code,
    );
    const binding = bindingFields(record, code);
    const installation = parsePermissionEvidence(
      record.installation,
      "permission_present",
      code,
      context,
    );
    const removal = parsePermissionEvidence(record.removal, "permission_absent", code, context);
    const updatedAt = safeInteger(record.updatedAt, "materialization updatedAt", code);
    if (
      !evidenceMatchesBinding(removal, binding) ||
      removal.observedAt !== updatedAt ||
      !evidenceMatchesBinding(installation, binding) ||
      installation.observedAt > removal.observedAt ||
      BigInt(installation.blockNumber) >= BigInt(removal.blockNumber)
    ) {
      return invalid(code, "revoked materialization evidence conflicts");
    }
    return Object.freeze({ state, ...binding, updatedAt, installation, removal });
  }

  if (state === "unreadable") {
    const record = exactCapturedRecord(
      captured,
      [...common, "priorState", "installation", "reason"],
      "unreadable materialization",
      code,
    );
    if (
      record.priorState !== "installing" &&
      record.priorState !== "installed" &&
      record.priorState !== "revoking"
    ) {
      return invalid(code, "unreadable materialization prior state is unsupported");
    }
    if (
      record.reason !== "provider_unavailable" &&
      record.reason !== "state_invalid" &&
      record.reason !== "canonicality_unproven"
    ) {
      return invalid(code, "unreadable materialization reason is unsupported");
    }
    const binding = bindingFields(record, code);
    const installation = parseNullableInstallation(record.installation, code, context);
    const updatedAt = safeInteger(record.updatedAt, "materialization updatedAt", code);
    if (
      (record.priorState === "installed" && installation === null) ||
      (record.priorState === "installing" && installation !== null) ||
      (installation && !evidenceMatchesBinding(installation, binding)) ||
      (installation && installation.observedAt > updatedAt)
    ) {
      return invalid(code, "unreadable materialization evidence conflicts");
    }
    return Object.freeze({
      state,
      ...binding,
      updatedAt,
      priorState: record.priorState,
      installation,
      reason: record.reason,
    });
  }

  return invalid(code, "chain materialization state is unsupported");
}

function parseMaterializations(
  value: unknown,
  code: GrantErrorCode,
  context: CaptureContext,
): readonly ChainMaterialization[] {
  const values = captureDenseArray(value, "grant materializations", context, captureFailure(code));
  const materializations = values.map((entry) => parseMaterialization(entry, code, context));
  let previousChainId = 0;
  for (const materialization of materializations) {
    if (materialization.chainId <= previousChainId) {
      return invalid(code, "grant materializations must be strictly sorted by chainId");
    }
    previousChainId = materialization.chainId;
  }
  return Object.freeze(materializations);
}

function activeChildCost(materialization: ChainMaterialization, code: GrantErrorCode): number {
  switch (materialization.state) {
    case "unsupported":
    case "unmaterialized":
      return 1;
    case "installing":
      return 2;
    case "installed":
      return 3;
    case "unreadable":
      if (materialization.priorState === "revoking") {
        return invalid(code, "active grant cannot contain revocation evidence");
      }
      return materialization.installation === null ? 3 : 4;
    default:
      return invalid(code, "active grant contains a revocation-only materialization");
  }
}

function revokingChildCost(materialization: ChainMaterialization, code: GrantErrorCode): number {
  switch (materialization.state) {
    case "unsupported":
    case "unmaterialized":
      return 1;
    case "installing":
      return 2;
    case "installed":
      return 3;
    case "revoking":
      return materialization.installation === null ? 3 : 4;
    case "revoked":
      return 5;
    case "unreadable":
      return materialization.installation === null
        ? materialization.priorState === "revoking"
          ? 4
          : 3
        : materialization.priorState === "revoking"
          ? 5
          : 4;
    default:
      return invalid(code, "revoking grant contains installation authority state");
  }
}

function sumChildCosts(
  materializations: readonly ChainMaterialization[],
  cost: (entry: ChainMaterialization, code: GrantErrorCode) => number,
  code: GrantErrorCode,
): number {
  return materializations.reduce((sum, entry) => sum + cost(entry, code), 0);
}

function latestGrantTime(input: {
  requestedAt: number;
  approval: Readonly<GrantApproval> | null;
  activatedAt: number | null;
  revocationStartedAt: number | null;
  capabilityInvalidation: Readonly<GrantCapabilityInvalidation> | null;
  terminal: GrantTerminal | null;
  materializations: readonly ChainMaterialization[];
}): number {
  let latest = Math.max(
    input.requestedAt,
    input.approval?.approvedAt ?? 0,
    input.activatedAt ?? 0,
    input.revocationStartedAt ?? 0,
    input.capabilityInvalidation?.invalidatedAt ?? 0,
    input.terminal?.recordedAt ?? 0,
  );
  for (const materialization of input.materializations) {
    latest = Math.max(latest, materialization.updatedAt);
  }
  return latest;
}

function materializationChronologyValid(
  materializations: readonly ChainMaterialization[],
  activatedAt: number | null,
  revocationStartedAt: number | null,
  terminal: GrantTerminal | null,
): boolean {
  if (materializations.length > 0 && activatedAt === null) return false;

  for (const materialization of materializations) {
    if (
      (activatedAt !== null && materialization.updatedAt < activatedAt) ||
      (terminal !== null && materialization.updatedAt > terminal.recordedAt)
    ) {
      return false;
    }
    if (
      activatedAt !== null &&
      "installation" in materialization &&
      materialization.installation !== null &&
      materialization.installation.observedAt < activatedAt
    ) {
      return false;
    }
    if (materialization.state === "revoking") {
      if (revocationStartedAt === null || materialization.startedAt < revocationStartedAt) {
        return false;
      }
    }
    if (
      (materialization.state === "revoked" ||
        (materialization.state === "unreadable" && materialization.priorState === "revoking")) &&
      (revocationStartedAt === null || materialization.updatedAt < revocationStartedAt)
    ) {
      return false;
    }
  }
  return true;
}

function chronologyValid(input: {
  requestedAt: number;
  expiresAt: number;
  approval: Readonly<GrantApproval> | null;
  activatedAt: number | null;
  revocationStartedAt: number | null;
  capabilityInvalidation: Readonly<GrantCapabilityInvalidation> | null;
  terminal: GrantTerminal | null;
  materializations: readonly ChainMaterialization[];
}): boolean {
  const approvedAt = input.approval?.approvedAt ?? null;
  return (
    input.expiresAt > input.requestedAt &&
    (approvedAt === null || (approvedAt >= input.requestedAt && approvedAt < input.expiresAt)) &&
    (input.activatedAt === null ||
      (approvedAt !== null &&
        input.activatedAt >= approvedAt &&
        input.activatedAt < input.expiresAt)) &&
    (input.revocationStartedAt === null ||
      (input.activatedAt !== null &&
        input.revocationStartedAt >= input.activatedAt &&
        input.revocationStartedAt < input.expiresAt)) &&
    (input.capabilityInvalidation === null ||
      (input.revocationStartedAt !== null &&
        input.capabilityInvalidation.invalidatedAt >= input.revocationStartedAt)) &&
    (input.terminal === null || input.terminal.recordedAt >= input.requestedAt) &&
    (input.terminal?.kind !== "rejected" || input.terminal.recordedAt < input.expiresAt) &&
    (input.terminal?.kind !== "revoked" ||
      (input.revocationStartedAt !== null &&
        input.terminal.recordedAt >= input.revocationStartedAt)) &&
    (input.terminal?.kind !== "expired" || input.terminal.recordedAt >= input.expiresAt) &&
    (input.terminal === null ||
      input.capabilityInvalidation === null ||
      input.terminal.recordedAt >= input.capabilityInvalidation.invalidatedAt) &&
    materializationChronologyValid(
      input.materializations,
      input.activatedAt,
      input.revocationStartedAt,
      input.terminal,
    )
  );
}

function parseGrantUnsafe(value: unknown): Grant {
  const code = "grant_record_invalid" as const;
  const context: CaptureContext = new WeakSet();
  const record = exactRecord(
    value,
    [
      "version",
      "identity",
      "revision",
      "state",
      "requestedAt",
      "expiresAt",
      "updatedAt",
      "approval",
      "activatedAt",
      "revocationStartedAt",
      "capabilityInvalidation",
      "terminal",
      "materializations",
    ],
    "grant record",
    code,
    context,
  );
  if (record.version !== OGP_GRANT_RECORD_VERSION) {
    return invalid(code, "grant record version is unsupported");
  }
  const identity = parseIdentity(record.identity, code, context);
  const revision = safeInteger(record.revision, "grant revision", code);
  const requestedAt = safeInteger(record.requestedAt, "grant requestedAt", code);
  const expiresAt = safeInteger(record.expiresAt, "grant expiresAt", code);
  const updatedAt = safeInteger(record.updatedAt, "grant updatedAt", code);
  const approval = parseApproval(record.approval, code, context);
  const activatedAt =
    record.activatedAt === null ? null : safeInteger(record.activatedAt, "grant activatedAt", code);
  const revocationStartedAt =
    record.revocationStartedAt === null
      ? null
      : safeInteger(record.revocationStartedAt, "grant revocationStartedAt", code);
  const capabilityInvalidation = parseInvalidation(record.capabilityInvalidation, code, context);
  const terminal = parseTerminal(record.terminal, code, context);
  const materializations = parseMaterializations(record.materializations, code, context);
  const base = {
    version: OGP_GRANT_RECORD_VERSION,
    identity,
    revision,
    requestedAt,
    expiresAt,
    updatedAt,
    approval,
    activatedAt,
    revocationStartedAt,
    capabilityInvalidation,
    terminal,
    materializations,
  } as const;

  if (
    !chronologyValid(base) ||
    latestGrantTime(base) !== updatedAt ||
    (capabilityInvalidation !== null &&
      approval?.capabilityHash !== capabilityInvalidation.capabilityHash)
  ) {
    return invalid(code, "grant record evidence is contradictory");
  }

  if (record.state === "requested") {
    if (
      revision !== 0 ||
      approval !== null ||
      activatedAt !== null ||
      revocationStartedAt !== null ||
      capabilityInvalidation !== null ||
      terminal !== null ||
      materializations.length !== 0
    ) {
      return invalid(code, "requested grant record is contradictory");
    }
    return Object.freeze({
      ...base,
      state: "requested",
      approval: null,
      activatedAt: null,
      revocationStartedAt: null,
      capabilityInvalidation: null,
      terminal: null,
    });
  }

  if (record.state === "rejected") {
    if (
      revision !== 1 ||
      approval !== null ||
      activatedAt !== null ||
      revocationStartedAt !== null ||
      capabilityInvalidation !== null ||
      terminal?.kind !== "rejected" ||
      materializations.length !== 0
    ) {
      return invalid(code, "rejected grant record is contradictory");
    }
    return Object.freeze({
      ...base,
      state: "rejected",
      approval: null,
      activatedAt: null,
      revocationStartedAt: null,
      capabilityInvalidation: null,
      terminal,
    });
  }

  if (record.state === "approved") {
    if (
      revision !== 1 ||
      approval === null ||
      approval.approvedAt >= expiresAt ||
      activatedAt !== null ||
      revocationStartedAt !== null ||
      capabilityInvalidation !== null ||
      terminal !== null ||
      materializations.length !== 0
    ) {
      return invalid(code, "approved grant record is contradictory");
    }
    return Object.freeze({
      ...base,
      state: "approved",
      approval,
      activatedAt: null,
      revocationStartedAt: null,
      capabilityInvalidation: null,
      terminal: null,
    });
  }

  if (record.state === "active") {
    if (
      approval === null ||
      activatedAt === null ||
      activatedAt >= expiresAt ||
      revocationStartedAt !== null ||
      capabilityInvalidation !== null ||
      terminal !== null ||
      materializations.some((entry) => entry.updatedAt >= expiresAt)
    ) {
      return invalid(code, "active grant record is contradictory");
    }
    const minimumRevision = 2 + sumChildCosts(materializations, activeChildCost, code);
    if (revision < minimumRevision) return invalid(code, "active grant revision is unreachable");
    return Object.freeze({
      ...base,
      state: "active",
      approval,
      activatedAt,
      revocationStartedAt: null,
      capabilityInvalidation: null,
      terminal: null,
    });
  }

  if (record.state === "revoking" || record.state === "revoked") {
    if (
      approval === null ||
      activatedAt === null ||
      revocationStartedAt === null ||
      terminal?.kind === "rejected" ||
      terminal?.kind === "expired"
    ) {
      return invalid(code, `${record.state} grant record is contradictory`);
    }
    const childCost = sumChildCosts(materializations, revokingChildCost, code);
    const revokingMinimum = 3 + childCost + (capabilityInvalidation === null ? 0 : 1);
    if (record.state === "revoking") {
      if (terminal !== null || revision < revokingMinimum) {
        return invalid(code, "revoking grant record is contradictory");
      }
      return Object.freeze({
        ...base,
        state: "revoking",
        approval,
        activatedAt,
        revocationStartedAt,
        terminal: null,
      });
    }
    if (
      terminal?.kind !== "revoked" ||
      capabilityInvalidation === null ||
      revision < revokingMinimum + 1 ||
      materializations.some(
        (entry) =>
          entry.state !== "unsupported" &&
          entry.state !== "unmaterialized" &&
          entry.state !== "revoked",
      )
    ) {
      return invalid(code, "revoked grant record is contradictory");
    }
    return Object.freeze({
      ...base,
      state: "revoked",
      approval,
      activatedAt,
      revocationStartedAt,
      capabilityInvalidation,
      terminal,
    });
  }

  if (record.state === "expired") {
    if (terminal?.kind !== "expired" || (capabilityInvalidation !== null && approval === null)) {
      return invalid(code, "expired grant record is contradictory");
    }
    let minimumRevision: number;
    if (terminal.from === "requested") {
      if (
        approval !== null ||
        activatedAt !== null ||
        revocationStartedAt !== null ||
        capabilityInvalidation !== null ||
        materializations.length !== 0
      ) {
        return invalid(code, "requested grant expiry is contradictory");
      }
      minimumRevision = 1;
    } else if (terminal.from === "approved") {
      if (
        approval === null ||
        activatedAt !== null ||
        revocationStartedAt !== null ||
        capabilityInvalidation !== null ||
        materializations.length !== 0
      ) {
        return invalid(code, "approved grant expiry is contradictory");
      }
      minimumRevision = 2;
    } else if (terminal.from === "active") {
      if (
        approval === null ||
        activatedAt === null ||
        revocationStartedAt !== null ||
        capabilityInvalidation !== null ||
        materializations.some((entry) => entry.updatedAt >= expiresAt)
      ) {
        return invalid(code, "active grant expiry is contradictory");
      }
      minimumRevision = 3 + sumChildCosts(materializations, activeChildCost, code);
    } else {
      if (approval === null || activatedAt === null || revocationStartedAt === null) {
        return invalid(code, "revoking grant expiry is contradictory");
      }
      minimumRevision =
        4 +
        sumChildCosts(materializations, revokingChildCost, code) +
        (capabilityInvalidation === null ? 0 : 1);
    }
    if (revision < minimumRevision) return invalid(code, "expired grant revision is unreachable");
    return Object.freeze({ ...base, state: "expired", terminal });
  }

  return invalid(code, "grant state is unsupported");
}

export function parseGrant(value: unknown): Grant {
  try {
    return parseGrantUnsafe(value);
  } catch {
    throw new OgpGrantError("grant_record_invalid", "grant record could not be captured safely");
  }
}

export function createGrant(value: unknown): RequestedGrant {
  try {
    const code = "grant_input_invalid" as const;
    const context: CaptureContext = new WeakSet();
    const record = exactRecord(
      value,
      ["identity", "requestedAt", "expiresAt"],
      "grant request",
      code,
      context,
    );
    const identity = parseIdentity(record.identity, code, context);
    const requestedAt = safeInteger(record.requestedAt, "grant requestedAt", code);
    const expiresAt = safeInteger(record.expiresAt, "grant expiresAt", code);
    if (expiresAt <= requestedAt) return invalid(code, "grant expiresAt must follow requestedAt");
    return Object.freeze({
      version: OGP_GRANT_RECORD_VERSION,
      identity,
      revision: 0,
      state: "requested",
      requestedAt,
      expiresAt,
      updatedAt: requestedAt,
      approval: null,
      activatedAt: null,
      revocationStartedAt: null,
      capabilityInvalidation: null,
      terminal: null,
      materializations: Object.freeze([]),
    });
  } catch {
    throw new OgpGrantError("grant_input_invalid", "grant request could not be captured safely");
  }
}
