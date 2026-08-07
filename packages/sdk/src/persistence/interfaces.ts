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
 * wallet-call bundles  the provider-scoped EIP-5792 id reservation and exact
 *                      Operation binding used by reload-safe status lookup
 * ```
 *
 * Every store hands back `unknown`. The fact's owner captures it: `GrantStore`
 * and `OperationStore` for aggregates, `WalletCallBundleStore` for wallet-call
 * ids, `parseCleanupCheckpoint` and `parseClientContext` here, and
 * `requireNonExtractableKey` for key handles. A backend never validates domain
 * meaning, and no reader accepts an older version: an unsupported version is
 * rejected, not migrated.
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
  type OperationIdentity,
  type PermissionRequest,
  parseGrantPolicy,
  parseOperationIdentity,
  parsePermissionRequest,
} from "@oaath/protocol";
import type { Address, Hash } from "viem";
import {
  type KernelAllChainApproval,
  parseKernelAllChainApproval,
} from "../kernel/permission/materialize.js";
import type { StoreRecord } from "../store.js";

export const OAATH_CLEANUP_CHECKPOINT_VERSION = "oaath.cleanup-checkpoint/v1" as const;
export const OAATH_CLIENT_CONTEXT_VERSION = "oaath.client-context/v1" as const;
export const OAATH_WALLET_CALL_BUNDLE_VERSION = "oaath.wallet-call-bundle/v3" as const;
export const OAATH_WALLET_CALL_BUNDLE_STORE_RECORD_VERSION =
  "oaath.wallet-call-bundle-store-record/v3" as const;

const HASH = /^0x[0-9a-f]{64}$/u;
const ADDRESS = /^0x[0-9a-f]{40}$/u;
const MAX_ID_LENGTH = 256;
const MAX_WALLET_CALL_BUNDLE_ID_UTF8_BYTES = 4_096;
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

function walletCallBundleSafeInteger(
  value: unknown,
  label: string,
  code: PersistenceErrorCode,
  minimum: 0 | 1,
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < minimum
  ) {
    return persistenceFail(
      code,
      `${label} must be a ${minimum === 0 ? "nonnegative" : "positive"} safe integer`,
    );
  }
  return value;
}

function walletCallBundleId(value: unknown, label: string, code: PersistenceErrorCode): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_WALLET_CALL_BUNDLE_ID_UTF8_BYTES ||
    new TextEncoder().encode(value).byteLength > MAX_WALLET_CALL_BUNDLE_ID_UTF8_BYTES
  ) {
    return persistenceFail(code, `${label} must contain 1 to 4096 UTF-8 bytes`);
  }
  return value;
}

function walletCallBundleAddress(
  value: unknown,
  label: string,
  code: PersistenceErrorCode,
): Address {
  if (typeof value !== "string" || !ADDRESS.test(value)) {
    return persistenceFail(code, `${label} must be a lowercase 20-byte address`);
  }
  return value as Address;
}

function walletCallBundleOperation(
  value: unknown,
  grantId: string,
  chainId: number,
  account: Address,
  context: CaptureContext,
  code: PersistenceErrorCode,
): Readonly<WalletCallBundleOperation> {
  const record = exactRecord(
    value,
    ["identity"],
    "wallet call bundle operation binding",
    context,
    failFor(code),
  );
  let identity: Readonly<OperationIdentity>;
  try {
    identity = parseOperationIdentity(record.identity);
  } catch {
    return persistenceFail(code, "wallet call bundle operation identity is invalid");
  }
  if (
    identity.kind !== "execution" ||
    identity.grantId !== grantId ||
    identity.chainId !== chainId ||
    identity.account !== account ||
    identity.requestHash === null
  ) {
    return persistenceFail(code, "wallet call bundle operation identity contradicts its bundle");
  }
  return Object.freeze({ identity });
}

/** The exact durable uniqueness key. Chain is deliberately not an axis. */
export interface WalletCallBundleKey {
  readonly providerScopeId: Hash;
  readonly grantId: string;
  readonly id: string;
}

export interface WalletCallBundleOperation {
  readonly identity: Readonly<OperationIdentity>;
}

export interface WalletCallBundleRecord {
  readonly version: typeof OAATH_WALLET_CALL_BUNDLE_VERSION;
  readonly providerScopeId: Hash;
  readonly grantId: string;
  readonly generation: Hash;
  readonly id: string;
  readonly account: Address;
  readonly chainId: number;
  readonly createdAt: number;
  /** Earliest time another realm may conclusively abandon pre-submission publication. */
  readonly publicationExpiresAt: number;
  /** Null while the originating sender may still advance pre-submission state. */
  readonly publicationReleasedAt: number | null;
  readonly requestHash: Hash;
  readonly operation: Readonly<WalletCallBundleOperation> | null;
  readonly state: "accepted" | "operation_reserved" | "operation_bound" | "terminal";
  readonly terminalFrom: "accepted" | "operation_reserved" | "operation_bound" | null;
}

export type WalletCallBundleStoreRecord = Readonly<
  StoreRecord<
    Readonly<WalletCallBundleRecord>,
    typeof OAATH_WALLET_CALL_BUNDLE_STORE_RECORD_VERSION
  >
>;

/** Raw persistence capability. Updates match revision and immutable generation atomically. */
export interface WalletCallBundleStoreAdapter {
  get(key: Readonly<WalletCallBundleKey>): Promise<unknown>;
  compareAndSwap(input: {
    readonly key: Readonly<WalletCallBundleKey>;
    readonly expectedStoreRevision: number | null;
    readonly expectedGeneration: Hash | null;
    readonly next: Readonly<StoreRecord<unknown>>;
  }): Promise<unknown>;
  compareAndDelete(input: {
    readonly key: Readonly<WalletCallBundleKey>;
    readonly expectedStoreRevision: number;
    readonly expectedGeneration: Hash;
  }): Promise<unknown>;
  close(): Promise<unknown>;
}

/** Captures one caller-supplied bundle key without normalizing any component. */
export function parseWalletCallBundleKey(value: unknown): Readonly<WalletCallBundleKey> {
  const code: PersistenceErrorCode = "persistence_input_invalid";
  const record = exactRecord(
    value,
    ["providerScopeId", "grantId", "id"],
    "wallet call bundle key",
    new WeakSet(),
    failFor(code),
  );
  return Object.freeze({
    providerScopeId: persistenceHash(
      record.providerScopeId,
      "wallet call bundle providerScopeId",
      code,
    ),
    grantId: persistenceId(record.grantId, "wallet call bundle grantId", failFor(code)),
    id: walletCallBundleId(record.id, "wallet call bundle id", code),
  });
}

/** Captures the one current wallet-call bundle value schema. */
export function parseWalletCallBundleRecord(value: unknown): Readonly<WalletCallBundleRecord> {
  const code: PersistenceErrorCode = "persistence_record_invalid";
  const context: CaptureContext = new WeakSet();
  const record = exactRecord(
    value,
    [
      "version",
      "providerScopeId",
      "grantId",
      "generation",
      "id",
      "account",
      "chainId",
      "createdAt",
      "publicationExpiresAt",
      "publicationReleasedAt",
      "requestHash",
      "operation",
      "state",
      "terminalFrom",
    ],
    "wallet call bundle record",
    context,
    failFor(code),
  );
  if (record.version !== OAATH_WALLET_CALL_BUNDLE_VERSION) {
    return persistenceFail(code, "wallet call bundle version is unsupported");
  }

  const chainId = walletCallBundleSafeInteger(
    record.chainId,
    "wallet call bundle chainId",
    code,
    1,
  );
  const grantId = persistenceId(record.grantId, "wallet call bundle grantId", failFor(code));
  const account = walletCallBundleAddress(record.account, "wallet call bundle account", code);
  const operation =
    record.operation === null
      ? null
      : walletCallBundleOperation(record.operation, grantId, chainId, account, context, code);
  const createdAt = walletCallBundleSafeInteger(
    record.createdAt,
    "wallet call bundle createdAt",
    code,
    0,
  );
  const publicationExpiresAt = walletCallBundleSafeInteger(
    record.publicationExpiresAt,
    "wallet call bundle publicationExpiresAt",
    code,
    1,
  );
  if (publicationExpiresAt <= createdAt) {
    return persistenceFail(code, "wallet call bundle publication lease is invalid");
  }
  const publicationReleasedAt =
    record.publicationReleasedAt === null
      ? null
      : walletCallBundleSafeInteger(
          record.publicationReleasedAt,
          "wallet call bundle publicationReleasedAt",
          code,
          0,
        );
  if (publicationReleasedAt !== null && publicationReleasedAt < createdAt) {
    return persistenceFail(code, "wallet call bundle publication release predates acceptance");
  }
  const state = record.state;
  if (
    state !== "accepted" &&
    state !== "operation_reserved" &&
    state !== "operation_bound" &&
    state !== "terminal"
  ) {
    return persistenceFail(code, "wallet call bundle state is unsupported");
  }
  if (state === "accepted" && operation !== null) {
    return persistenceFail(code, "an accepted wallet call bundle cannot bind an operation");
  }
  if ((state === "accepted" || state === "operation_reserved") && publicationReleasedAt !== null) {
    return persistenceFail(code, "wallet call bundle publication released before binding");
  }
  if ((state === "operation_reserved" || state === "operation_bound") && operation === null) {
    return persistenceFail(
      code,
      "an operation-reserved or bound wallet call bundle requires an operation",
    );
  }
  let terminalFrom: WalletCallBundleRecord["terminalFrom"];
  if (state === "terminal") {
    if (
      record.terminalFrom !== "accepted" &&
      record.terminalFrom !== "operation_reserved" &&
      record.terminalFrom !== "operation_bound"
    ) {
      return persistenceFail(code, "a terminal wallet call bundle requires its prior state");
    }
    terminalFrom = record.terminalFrom;
    if (
      (terminalFrom === "accepted" && operation !== null) ||
      (terminalFrom !== "accepted" && operation === null)
    ) {
      return persistenceFail(code, "wallet call bundle terminal origin contradicts its operation");
    }
    if (terminalFrom !== "operation_bound" && publicationReleasedAt !== null) {
      return persistenceFail(code, "wallet call bundle terminal origin contradicts its release");
    }
  } else {
    if (record.terminalFrom !== null) {
      return persistenceFail(
        code,
        "a nonterminal wallet call bundle cannot have a terminal origin",
      );
    }
    terminalFrom = null;
  }

  return Object.freeze({
    version: OAATH_WALLET_CALL_BUNDLE_VERSION,
    providerScopeId: persistenceHash(
      record.providerScopeId,
      "wallet call bundle providerScopeId",
      code,
    ),
    grantId,
    generation: persistenceHash(record.generation, "wallet call bundle generation", code),
    id: walletCallBundleId(record.id, "wallet call bundle id", code),
    account,
    chainId,
    createdAt,
    publicationExpiresAt,
    publicationReleasedAt,
    requestHash: persistenceHash(record.requestHash, "wallet call bundle requestHash", code),
    operation,
    state,
    terminalFrom,
  });
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
  /**
   * The owner's replayable Kernel install approval, durable beside the Grant
   * so any supported chain can materialize the permission later. Null only
   * for contexts persisted before an approval carried one.
   */
  readonly installApproval: Readonly<KernelAllChainApproval> | null;
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
    [
      "version",
      "bindingId",
      "grantId",
      "request",
      "approvedPolicy",
      "installApproval",
      "updatedAt",
    ],
    "client context",
    context,
    failFor(code),
  );
  if (record.version !== OAATH_CLIENT_CONTEXT_VERSION) {
    return persistenceFail(code, "client context version is unsupported");
  }
  let request: Readonly<PermissionRequest>;
  let approvedPolicy: Readonly<GrantPolicy>;
  let installApproval: Readonly<KernelAllChainApproval> | null;
  try {
    request = parsePermissionRequest(record.request);
    approvedPolicy = parseGrantPolicy(record.approvedPolicy);
    installApproval =
      record.installApproval === null ? null : parseKernelAllChainApproval(record.installApproval);
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
    installApproval,
    updatedAt: persistenceTime(record.updatedAt, "client context updatedAt", code),
  });
}
