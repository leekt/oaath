/** One encrypted journal per realm binding. Winning a durable revision CAS is
 * required before either one-time redemption effect; uncertain effects never retry.
 */
import {
  type PermissionRequest,
  type PermissionSessionSigner,
  parsePermissionRequest,
} from "@oaath/protocol";
import { bytesToHex, hexToBytes, keccak256 } from "cetane/utils";
import {
  type OaathContextStore,
  type OaathKeyStore,
  type OaathPendingAuthorizationEnvelope,
  requireNonExtractableKey,
} from "../persistence/interfaces.js";
import type { OaathBinding } from "./binding.js";
import { clientFail, exactClientRecord } from "./errors.js";

export type PendingPhase =
  | "creating"
  | "pending"
  | "consuming"
  | "claimable"
  | "claiming"
  | "claimed"
  | "settled";
export interface PendingAuthorization {
  readonly phase: PendingPhase;
  readonly request: Readonly<PermissionRequest>;
  readonly redirectUri: string;
  readonly verifier: string;
  readonly matchCode: string | null;
  readonly expiresAt: number;
  readonly artifactId: string | null;
  readonly artifact: string | null;
}
export interface PendingSnapshot {
  readonly envelope: Readonly<OaathPendingAuthorizationEnvelope>;
  readonly value: Readonly<PendingAuthorization>;
}
const VERSION = "oaath.pending-authorization/v1" as const;
const encoder = new TextEncoder();
const phases: readonly unknown[] = [
  "creating",
  "pending",
  "consuming",
  "claimable",
  "claiming",
  "claimed",
  "settled",
];
const fail = (): never =>
  clientFail(
    "oaath_client_state_conflict",
    "pending authorization evidence is invalid",
    "pending_authorization_invalid",
  );

function pendingBindingId(realmBindingId: string): `0x${string}` {
  return keccak256(encoder.encode(`${VERSION}:${realmBindingId}`));
}
function aad(envelope: Readonly<OaathPendingAuthorizationEnvelope>): Uint8Array<ArrayBuffer> {
  return encoder.encode(
    JSON.stringify([VERSION, envelope.bindingId, envelope.storeRevision, envelope.keyId]),
  );
}
function captureEnvelope(
  raw: unknown,
  bindingId: string,
): Readonly<OaathPendingAuthorizationEnvelope> {
  const record = exactClientRecord(
    raw,
    ["version", "bindingId", "storeRevision", "keyId", "iv", "ciphertext"],
    "pending authorization envelope",
    new WeakSet(),
  );
  if (
    record.version !== VERSION ||
    record.bindingId !== bindingId ||
    !Number.isSafeInteger(record.storeRevision) ||
    Number(record.storeRevision) < 1 ||
    typeof record.keyId !== "string" ||
    !/^pending-[a-z0-9-]{36}$/u.test(record.keyId) ||
    typeof record.iv !== "string" ||
    !/^0x[0-9a-f]{24}$/u.test(record.iv) ||
    typeof record.ciphertext !== "string" ||
    !/^0x[0-9a-f]+$/u.test(record.ciphertext) ||
    record.ciphertext.length > 100_000
  )
    fail();
  return Object.freeze({
    ...record,
  }) as unknown as Readonly<OaathPendingAuthorizationEnvelope>;
}
async function openEnvelope(
  envelope: Readonly<OaathPendingAuthorizationEnvelope>,
  key: CryptoKey,
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(hexToBytes(envelope.iv)), additionalData: aad(envelope) },
    key,
    new Uint8Array(hexToBytes(envelope.ciphertext)),
  );
}

/** Deleting custody is retryable even if the prior delete succeeded before its reply.
 * Authenticate the envelope before deleting any still-present named key.
 */
export async function forgetPendingAuthorization(input: {
  readonly bindingId: string;
  readonly keys: OaathKeyStore;
  readonly contexts: OaathContextStore;
}): Promise<void> {
  const bindingId = pendingBindingId(input.bindingId);
  const raw = await input.contexts.read(bindingId);
  if (raw === null || raw === undefined) return;
  const envelope = captureEnvelope(raw, bindingId);
  const key = await input.keys.get(envelope.keyId);
  if (key !== undefined && key !== null) {
    await openEnvelope(envelope, requireNonExtractableKey(key));
    await input.keys.delete(envelope.keyId);
  }
  await input.contexts.clear(bindingId);
}

export function createPendingAuthorizationJournal(input: {
  readonly binding: Readonly<OaathBinding>;
  readonly sessionSigner: Readonly<PermissionSessionSigner> | null;
  readonly contexts: OaathContextStore;
  readonly keys: OaathKeyStore;
}) {
  const bindingId = pendingBindingId(input.binding.bindingId);
  function payload(value: unknown): Readonly<PendingAuthorization> {
    const record = exactClientRecord(
      value,
      [
        "phase",
        "request",
        "redirectUri",
        "verifier",
        "matchCode",
        "expiresAt",
        "artifactId",
        "artifact",
      ],
      "pending authorization",
      new WeakSet(),
    );
    const request = parsePermissionRequest(record.request);
    const binding = input.binding;
    if (
      !phases.includes(record.phase) ||
      record.redirectUri !== binding.redirectUri ||
      typeof record.verifier !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/u.test(record.verifier) ||
      (record.matchCode !== null &&
        (typeof record.matchCode !== "string" || !/^[A-Za-z0-9_-]{8}$/u.test(record.matchCode))) ||
      !Number.isSafeInteger(record.expiresAt) ||
      Number(record.expiresAt) < 0 ||
      (record.artifactId !== null &&
        (typeof record.artifactId !== "string" ||
          !/^[A-Za-z0-9_-]{43}$/u.test(record.artifactId))) ||
      (record.artifact !== null &&
        (typeof record.artifact !== "string" || record.artifact.length > 32_768)) ||
      JSON.stringify([
        request.context,
        request.application,
        request.logicalAccount,
        request.operatorCredential,
        request.sessionSigner,
      ]) !==
        JSON.stringify([
          binding.context,
          binding.application,
          binding.account,
          binding.operatorCredential,
          input.sessionSigner,
        ])
    )
      fail();
    if ((record.phase === "creating") !== (record.matchCode === null)) fail();
    if (
      ["claimable", "claiming", "claimed", "settled"].includes(String(record.phase)) !==
      (record.artifactId !== null)
    )
      fail();
    if (["claimed", "settled"].includes(String(record.phase)) !== (record.artifact !== null))
      fail();
    return Object.freeze({
      phase: record.phase as PendingPhase,
      request,
      redirectUri: binding.redirectUri,
      verifier: record.verifier as string,
      matchCode: record.matchCode as string | null,
      expiresAt: record.expiresAt as number,
      artifactId: record.artifactId as string | null,
      artifact: record.artifact as string | null,
    });
  }
  async function read(): Promise<Readonly<PendingSnapshot> | null> {
    let raw: unknown;
    try {
      raw = await input.contexts.read(bindingId);
    } catch {
      return clientFail(
        "oaath_client_store_unavailable",
        "pending authorization could not be read",
      );
    }
    if (raw === undefined || raw === null) return null;
    try {
      const envelope = captureEnvelope(raw, bindingId);
      const key = requireNonExtractableKey(await input.keys.get(envelope.keyId));
      const plaintext = await openEnvelope(envelope, key);
      return Object.freeze({
        envelope,
        value: payload(JSON.parse(new TextDecoder().decode(plaintext))),
      });
    } catch {
      return fail();
    }
  }
  async function write(
    previous: Readonly<PendingSnapshot> | null,
    value: Readonly<PendingAuthorization>,
  ): Promise<Readonly<PendingSnapshot>> {
    const captured = payload(value);
    const keyId = previous?.envelope.keyId ?? `pending-${crypto.randomUUID()}`;
    const key =
      previous === null
        ? await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
            "encrypt",
            "decrypt",
          ])
        : requireNonExtractableKey(await input.keys.get(keyId));
    if (previous === null) await input.keys.store({ keyId, key });
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const base = {
      version: VERSION,
      bindingId,
      storeRevision: (previous?.envelope.storeRevision ?? 0) + 1,
      keyId,
      iv: bytesToHex(iv),
      ciphertext: "0x" as const,
    };
    const ciphertext = bytesToHex(
      new Uint8Array(
        await crypto.subtle.encrypt(
          { name: "AES-GCM", iv, additionalData: aad(base) },
          key,
          encoder.encode(JSON.stringify(captured)),
        ),
      ),
    );
    const envelope = Object.freeze({ ...base, ciphertext });
    let committed: boolean;
    try {
      committed = await input.contexts.compareAndSwapPending({
        bindingId,
        expectedStoreRevision: previous?.envelope.storeRevision ?? null,
        next: envelope,
      });
    } catch {
      return clientFail(
        "oaath_client_store_unavailable",
        "pending authorization write outcome is unknown",
      );
    }
    if (committed !== true) {
      if (previous === null) await input.keys.delete(keyId).catch(() => undefined);
      return clientFail(
        "oaath_client_state_conflict",
        "another connection advanced this authorization",
        "pending_authorization_conflict",
      );
    }
    return Object.freeze({ envelope, value: captured });
  }
  return Object.freeze({ read, write });
}
