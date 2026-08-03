/**
 * Browser persistence contracts.
 *
 * The Grant and Operation aggregates already have exactly one durable contract:
 * `GrantStoreAdapter` and `OperationStoreAdapter` in `../store.ts`, wrapped by
 * `GrantStore` and `OperationStore`, which own compare-and-swap, revision, and
 * record capture. Nothing here forks them; a browser backend implements those
 * adapters and this module adds only the facts they do not own:
 *
 * ```text
 * key custody          non-exportable CryptoKey handles by id, no export path
 * cleanup checkpoints  which destructive effects a crash left unfinished
 * client context       the exact reviewed request and approved policy for the
 *                      realm's active Grant, so a reload can evaluate coverage
 *                      without asking the application for identifiers
 * ```
 *
 * Every store hands back `unknown`. The fact's owner captures it: `GrantStore`
 * and `OperationStore` for aggregates, `parseCleanupCheckpoint` and
 * `parseClientContext` here, `requireNonExtractableKey` for key handles. A
 * backend never validates domain meaning, and no reader accepts an older
 * version: an unsupported version is rejected, not migrated.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type CaptureContext,
  type CaptureFailure,
  captureDenseArray,
  exactRecord,
  type GrantPolicy,
  isGrantPolicyAttenuation,
  type PermissionRequest,
  parseGrantPolicy,
  parsePermissionRequest,
} from "@oaath/protocol";

export const OAATH_CLEANUP_CHECKPOINT_VERSION = "oaath.cleanup-checkpoint/v1" as const;
export const OAATH_CLIENT_CONTEXT_VERSION = "oaath.client-context/v1" as const;

const HASH = /^0x[0-9a-f]{64}$/u;
const MAX_ID_LENGTH = 256;
const MAX_EFFECTS = 4;

export type PersistenceErrorCode =
  | "persistence_unavailable"
  | "persistence_input_invalid"
  | "persistence_record_invalid"
  | "persistence_key_invalid"
  | "persistence_schema_unusable"
  | "persistence_transaction_failed";

export class OaathPersistenceError extends Error {
  readonly code: PersistenceErrorCode;

  constructor(code: PersistenceErrorCode, message: string) {
    super(message);
    this.name = "OaathPersistenceError";
    this.code = code;
  }
}

export function persistenceFail(code: PersistenceErrorCode, message: string): never {
  throw new OaathPersistenceError(code, message);
}

function failFor(code: PersistenceErrorCode): CaptureFailure {
  return (message) => persistenceFail(code, message);
}

/**
 * Bounded canonical identifier used as a persistence key. A caller outside
 * persistence passes its own failure so the id rule has one owner while each
 * boundary keeps its own error vocabulary.
 */
export function persistenceId(
  value: unknown,
  label: string,
  fail: CaptureFailure = failFor("persistence_input_invalid"),
): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_ID_LENGTH ||
    value !== value.trim()
  ) {
    return fail(`${label} must be a bounded canonical id`);
  }
  return value;
}

function persistenceHash(value: unknown, label: string, code: PersistenceErrorCode): `0x${string}` {
  if (typeof value !== "string" || !HASH.test(value)) {
    return persistenceFail(code, `${label} must be a lowercase 32-byte hash`);
  }
  return value as `0x${string}`;
}

function persistenceTime(value: unknown, label: string, code: PersistenceErrorCode): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    return persistenceFail(code, `${label} must be a nonnegative safe integer`);
  }
  return value;
}

/**
 * Non-exportable key custody. The contract has no export, wrap, or raw-material
 * accessor, and a handle is only accepted while WebCrypto reports it
 * unextractable, so a stored private key can never leave the realm through this
 * owner.
 */
export interface OaathKeyStore {
  readonly store: (input: Readonly<{ keyId: string; key: CryptoKey }>) => Promise<unknown>;
  /** Resolves the stored handle, or `undefined` when the id is unknown. */
  readonly get: (keyId: string) => Promise<unknown>;
  readonly delete: (keyId: string) => Promise<unknown>;
  readonly close: () => Promise<unknown>;
}

/** The one gate for key custody: an extractable or non-CryptoKey handle fails closed. */
export function requireNonExtractableKey(value: unknown): CryptoKey {
  if (typeof CryptoKey === "undefined") {
    return persistenceFail("persistence_unavailable", "WebCrypto CryptoKey is unavailable");
  }
  if (!(value instanceof CryptoKey)) {
    return persistenceFail("persistence_key_invalid", "key handle must be a CryptoKey");
  }
  if (value.extractable) {
    return persistenceFail("persistence_key_invalid", "key handle must be non-extractable");
  }
  return value;
}

/** The destructive effects cleanup owns; also the persisted checkpoint vocabulary. */
export type OaathCleanupEffectName = "close" | "signOut" | "forgetLocal" | "revoke";

const EFFECT_NAMES: readonly OaathCleanupEffectName[] = Object.freeze([
  "close",
  "signOut",
  "forgetLocal",
  "revoke",
]);

export function isCleanupEffectName(value: unknown): value is OaathCleanupEffectName {
  return typeof value === "string" && (EFFECT_NAMES as readonly string[]).includes(value);
}

export interface OaathCleanupCheckpoint {
  readonly version: typeof OAATH_CLEANUP_CHECKPOINT_VERSION;
  readonly cleanupId: string;
  /** Effects proven complete. An effect is recorded only after it succeeded. */
  readonly completed: readonly OaathCleanupEffectName[];
  readonly updatedAt: number;
}

export interface OaathCleanupCheckpointStore {
  readonly read: (cleanupId: string) => Promise<unknown>;
  readonly write: (checkpoint: Readonly<OaathCleanupCheckpoint>) => Promise<unknown>;
  readonly clear: (cleanupId: string) => Promise<unknown>;
  readonly close: () => Promise<unknown>;
}

export function parseCleanupCheckpoint(value: unknown): Readonly<OaathCleanupCheckpoint> {
  const code: PersistenceErrorCode = "persistence_record_invalid";
  const context: CaptureContext = new WeakSet();
  const fail = failFor(code);
  const record = exactRecord(
    value,
    ["version", "cleanupId", "completed", "updatedAt"],
    "cleanup checkpoint",
    context,
    fail,
  );
  if (record.version !== OAATH_CLEANUP_CHECKPOINT_VERSION) {
    return persistenceFail(code, "cleanup checkpoint version is unsupported");
  }
  const entries = captureDenseArray(record.completed, "cleanup checkpoint effects", context, fail);
  if (entries.length > MAX_EFFECTS) {
    return persistenceFail(code, "cleanup checkpoint records too many effects");
  }
  const completed: OaathCleanupEffectName[] = [];
  for (const entry of entries) {
    if (!isCleanupEffectName(entry)) {
      return persistenceFail(code, "cleanup checkpoint effect is unsupported");
    }
    if (completed.includes(entry)) {
      return persistenceFail(code, "cleanup checkpoint repeats an effect");
    }
    completed.push(entry);
  }
  return Object.freeze({
    version: OAATH_CLEANUP_CHECKPOINT_VERSION,
    cleanupId: persistenceId(record.cleanupId, "cleanup checkpoint cleanupId"),
    completed: Object.freeze(completed),
    updatedAt: persistenceTime(record.updatedAt, "cleanup checkpoint updatedAt", code),
  });
}

/**
 * The client-side context for one binding realm's active Grant. The Grant
 * aggregate owns authority state; this record owns the exact request the owner
 * reviewed and the policy the owner approved, which the Grant references only by
 * hash. Without it a reloaded realm could not evaluate call coverage, and an
 * application would have to hand identifiers back to the SDK.
 */
export interface OaathClientContext {
  readonly version: typeof OAATH_CLIENT_CONTEXT_VERSION;
  readonly bindingId: `0x${string}`;
  readonly grantId: string;
  readonly request: Readonly<PermissionRequest>;
  readonly approvedPolicy: Readonly<GrantPolicy>;
  readonly updatedAt: number;
}

export interface OaathContextStore {
  readonly read: (bindingId: string) => Promise<unknown>;
  readonly write: (context: Readonly<OaathClientContext>) => Promise<unknown>;
  readonly clear: (bindingId: string) => Promise<unknown>;
  readonly close: () => Promise<unknown>;
}

/**
 * Captures a persisted client context. The approved policy must still attenuate
 * the reviewed request and the request must still be the one that named this
 * grantId, so tampered or stale local state fails closed instead of widening
 * authority after a reload.
 */
export function parseClientContext(value: unknown): Readonly<OaathClientContext> {
  const code: PersistenceErrorCode = "persistence_record_invalid";
  const context: CaptureContext = new WeakSet();
  const record = exactRecord(
    value,
    ["version", "bindingId", "grantId", "request", "approvedPolicy", "updatedAt"],
    "client context",
    context,
    failFor(code),
  );
  if (record.version !== OAATH_CLIENT_CONTEXT_VERSION) {
    return persistenceFail(code, "client context version is unsupported");
  }
  let request: Readonly<PermissionRequest>;
  let approvedPolicy: Readonly<GrantPolicy>;
  try {
    request = parsePermissionRequest(record.request);
    approvedPolicy = parseGrantPolicy(record.approvedPolicy);
  } catch {
    return persistenceFail(code, "client context permission request or policy is invalid");
  }
  const grantId = persistenceId(record.grantId, "client context grantId");
  if (request.requestId !== grantId) {
    return persistenceFail(code, "client context request does not name this grantId");
  }
  if (!isGrantPolicyAttenuation(request.policy, approvedPolicy)) {
    return persistenceFail(code, "client context approved policy widens the reviewed request");
  }
  return Object.freeze({
    version: OAATH_CLIENT_CONTEXT_VERSION,
    bindingId: persistenceHash(record.bindingId, "client context bindingId", code),
    grantId,
    request,
    approvedPolicy,
    updatedAt: persistenceTime(record.updatedAt, "client context updatedAt", code),
  });
}
