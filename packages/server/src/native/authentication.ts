import { captureRecord, exactCapturedRecord } from "@oaath/protocol";
import { randomIdentifier, sha256Base64Url } from "../authorization/challenge.js";
import type { DirectoryOwnerDevice } from "../directory/records.js";
import type { ServiceDirectory } from "../directory/service.js";
import { relayFailure } from "../relay/errors.js";
import type { RelayAuthentication, RelayCaller } from "../security/authentication.js";
import { canonicalIdentifier } from "../store/records.js";

export const OAATH_OWNER_DEVICE_CREDENTIAL_VERSION = "oaath.owner-device-credential/v1" as const;
export type OwnerDeviceReference = Pick<DirectoryOwnerDevice, "workspaceId" | "ownerDeviceId">;

/** Authentication binding captured at issuance; contains no bearer or owner key. */
export interface OwnerDeviceCredentialRecord extends DirectoryOwnerDevice {
  readonly version: typeof OAATH_OWNER_DEVICE_CREDENTIAL_VERSION;
  readonly credentialHash: string;
  readonly revoked: boolean;
}

export interface OwnerDeviceCredentialStore {
  /** Null means absent. Unreadable or unavailable storage must throw. */
  read(credentialHash: string): Promise<unknown>;
  /** Insert an immutable binding once. Never replace a revoked record. */
  insert(record: Readonly<OwnerDeviceCredentialRecord>): Promise<boolean>;
  /** Atomically revoke all credentials already issued for this device. Idempotent. */
  revoke(device: Readonly<OwnerDeviceReference>): Promise<void>;
}

export interface OwnerDeviceAuthentication extends RelayAuthentication {
  authenticate(request: Request): Promise<Readonly<RelayCaller> | null>;
  /**
   * Deployment administration only, after authenticated pairing/enrollment.
   * Returns a fresh 32-byte base64url bearer after its hash is stored. A lost
   * write response throws; nothing is returned and no write is retried.
   */
  issue(device: Readonly<OwnerDeviceReference>): Promise<string>;
  /** Revokes relay access only. Does not uninstall permissions or delete keys/accounts. */
  revoke(device: Readonly<OwnerDeviceReference>): Promise<void>;
}

const CREDENTIAL = /^[A-Za-z0-9_-]{43}$/u;

function deviceReference(device: Readonly<OwnerDeviceReference>): OwnerDeviceReference {
  return Object.freeze({
    workspaceId: canonicalIdentifier(device.workspaceId, "workspaceId", "relay_request_invalid"),
    ownerDeviceId: canonicalIdentifier(
      device.ownerDeviceId,
      "ownerDeviceId",
      "relay_request_invalid",
    ),
  });
}

function captureCredential(value: unknown): Readonly<OwnerDeviceCredentialRecord> {
  const code = "relay_record_unreadable";
  const fail = (message: string): never => relayFailure(code, message);
  const record = exactCapturedRecord(
    captureRecord(value, "owner device credential", new WeakSet(), fail),
    ["version", "credentialHash", "workspaceId", "ownerDeviceId", "subject", "revoked"],
    "owner device credential",
    fail,
  );
  if (
    record.version !== OAATH_OWNER_DEVICE_CREDENTIAL_VERSION ||
    typeof record.credentialHash !== "string" ||
    !CREDENTIAL.test(record.credentialHash) ||
    typeof record.revoked !== "boolean"
  )
    return fail("owner device credential is invalid");
  return Object.freeze({
    version: OAATH_OWNER_DEVICE_CREDENTIAL_VERSION,
    credentialHash: record.credentialHash,
    workspaceId: canonicalIdentifier(record.workspaceId, "workspaceId", code),
    ownerDeviceId: canonicalIdentifier(record.ownerDeviceId, "ownerDeviceId", code),
    subject: canonicalIdentifier(record.subject, "subject", code),
    revoked: record.revoked,
  });
}

/**
 * One active -> revoked transition per credential hash, separate from account
 * authority. Directory identity is checked at issuance and authentication;
 * an issued credential can never be retargeted to a changed owner subject.
 * No cache, operation lane, retries or owned connections. Recreated instances
 * read the same stores. The deployment owns pool shutdown and pairing delivery.
 * Explicit later issuance creates a new credential; it cannot revive an old one.
 */
export function createOwnerDeviceAuthentication(options: {
  readonly store: OwnerDeviceCredentialStore;
  readonly directory: Pick<ServiceDirectory, "read">;
}): Readonly<OwnerDeviceAuthentication> {
  const { store, directory } = options;
  async function enrolled(reference: OwnerDeviceReference) {
    const snapshot = await directory.read();
    return snapshot?.directory.ownerDevices.find(
      (device) =>
        device.workspaceId === reference.workspaceId &&
        device.ownerDeviceId === reference.ownerDeviceId,
    );
  }
  return Object.freeze({
    async issue(input: Readonly<OwnerDeviceReference>): Promise<string> {
      const reference = deviceReference(input);
      const device = await enrolled(reference);
      if (!device) return relayFailure("relay_not_found", "owner device is not enrolled");
      const subject = canonicalIdentifier(device.subject, "owner subject", "relay_request_invalid");
      const credential = randomIdentifier();
      const record = Object.freeze({
        version: OAATH_OWNER_DEVICE_CREDENTIAL_VERSION,
        credentialHash: await sha256Base64Url(credential),
        ...reference,
        subject,
        revoked: false,
      });
      if ((await store.insert(record)) !== true)
        return relayFailure("relay_internal", "owner device credential was not issued");
      return credential;
    },
    async authenticate(request: Request): Promise<Readonly<RelayCaller> | null> {
      const header = request.headers.get("authorization");
      if (!header?.startsWith("Bearer ")) return null;
      const credential = header.slice(7);
      if (!CREDENTIAL.test(credential)) return null;
      const hash = await sha256Base64Url(credential);
      const stored = await store.read(hash);
      if (stored === null) return null;
      const record = captureCredential(stored);
      if (record.credentialHash !== hash)
        return relayFailure("relay_record_unreadable", "owner device credential binding differs");
      if (record.revoked) return null;
      const device = await enrolled(record);
      if (!device || device.subject !== record.subject) return null;
      return Object.freeze({
        role: "owner",
        clientId: record.ownerDeviceId,
        subject: record.subject,
        redirectUris: Object.freeze([]),
        organizationAudience: null,
      });
    },
    revoke(device: Readonly<OwnerDeviceReference>): Promise<void> {
      return store.revoke(deviceReference(device));
    },
  });
}

/** Ephemeral deployment adapter; the authentication service owns no local cache. */
export function createMemoryOwnerDeviceCredentialStore(): OwnerDeviceCredentialStore {
  const records = new Map<string, Readonly<OwnerDeviceCredentialRecord>>();
  return {
    async read(hash) {
      return records.get(hash) ?? null;
    },
    async insert(record) {
      if (records.has(record.credentialHash)) return false;
      records.set(record.credentialHash, Object.freeze({ ...record }));
      return true;
    },
    async revoke(device) {
      for (const [hash, record] of records) {
        if (
          record.workspaceId === device.workspaceId &&
          record.ownerDeviceId === device.ownerDeviceId &&
          !record.revoked
        )
          records.set(hash, Object.freeze({ ...record, revoked: true }));
      }
    },
  };
}
