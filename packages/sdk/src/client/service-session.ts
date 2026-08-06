/**
 * Durable continuity for the URL-only realm: the device identity and the
 * session key survive a reload, so `resume()` finds a Grant whose operator
 * credential still names a key this realm can use, and the permission
 * materialized on chain stays the permission this session signs for.
 *
 * Custody shape: the secp256k1 session key (the pinned session signer module
 * is ECDSA, which WebCrypto cannot hold non-extractably) is AES-GCM-wrapped
 * under a non-extractable WebCrypto key held by the realm's key store. The
 * private scalar therefore never persists in the clear: the durable record
 * carries ciphertext, and opening it requires the same store's CryptoKey
 * handle, which has no export path. `disconnect` deletes the wrapping key,
 * which durably orphans the ciphertext.
 *
 * None of this is authority. A lost, cleared, or unreadable record simply
 * starts a fresh session that must be approved again; it never fails the
 * realm and never widens anything.
 *
 * @author taek <leekt216@gmail.com>
 */
import { encodeAbiParameters, keccak256 } from "viem";
import { requireNonExtractableKey } from "../persistence/interfaces.js";

export const OAATH_SERVICE_SESSION_VERSION = "oaath.service-session/v1" as const;
const STORAGE_DOMAIN = "@oaath/sdk:service-session" as const;
const PRIVATE_KEY = /^0x[0-9a-f]{64}$/u;
const BYTES = /^0x(?:[0-9a-f]{2})+$/u;
const DEVICE_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/u;

/** The stores this module consumes; structurally the realm's own stores. */
interface ServiceSessionStores {
  readonly context: {
    readonly read: (id: string) => Promise<unknown>;
    readonly write: (value: never) => Promise<unknown>;
  };
  readonly keys: {
    readonly get: (keyId: string) => Promise<unknown>;
    readonly store: (value: Readonly<{ keyId: string; key: CryptoKey }>) => Promise<unknown>;
  };
}

export interface ServiceSessionInput {
  readonly stores: ServiceSessionStores;
  readonly url: string;
  readonly origin: string;
}

export interface PersistedServiceSession {
  readonly deviceId: string;
  /** Lowercase 32-byte secp256k1 private key, opened from the wrapped record. */
  readonly privateKey: `0x${string}`;
}

/** One durable record per (service URL, page origin); the id is its address. */
function storageId(url: string, origin: string): `0x${string}` {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "string", name: "domain" },
        { type: "string", name: "url" },
        { type: "string", name: "origin" },
      ],
      [STORAGE_DOMAIN, url, origin],
    ),
  );
}

/** The wrapping key's id in the key store; listed in `localKeyIds` for cleanup. */
export function serviceSessionKeyId(url: string, origin: string): string {
  return `service-session-${storageId(url, origin).slice(2, 34)}`;
}

function bytesToHex(bytes: Uint8Array): `0x${string}` {
  let hex = "0x";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex as `0x${string}`;
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new ArrayBuffer((hex.length - 2) / 2));
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(2 + index * 2, 4 + index * 2), 16);
  }
  return bytes;
}

/**
 * Opens the persisted session for this (url, origin), or null. Every failure
 * mode — no record, unknown fields, a foreign shape, a deleted or unreadable
 * wrapping key, a ciphertext that does not authenticate — reads as null:
 * local continuity state is never trusted into a failure, only into a fresh
 * session.
 */
export async function loadServiceSession(
  input: Readonly<ServiceSessionInput>,
): Promise<PersistedServiceSession | null> {
  try {
    const raw = await input.stores.context.read(storageId(input.url, input.origin));
    if (raw === null || raw === undefined || typeof raw !== "object") return null;
    const record = raw as Record<string, unknown>;
    if (
      record.version !== OAATH_SERVICE_SESSION_VERSION ||
      Object.keys(record).sort().join(",") !==
        "bindingId,ciphertext,deviceId,iv,keyId,updatedAt,version"
    ) {
      return null;
    }
    const { deviceId, keyId, iv, ciphertext } = record;
    if (
      typeof deviceId !== "string" ||
      !DEVICE_ID.test(deviceId) ||
      keyId !== serviceSessionKeyId(input.url, input.origin) ||
      typeof iv !== "string" ||
      !BYTES.test(iv) ||
      typeof ciphertext !== "string" ||
      !BYTES.test(ciphertext)
    ) {
      return null;
    }
    const key = requireNonExtractableKey(await input.stores.keys.get(keyId));
    const opened = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: hexToBytes(iv) },
        key,
        hexToBytes(ciphertext),
      ),
    );
    const privateKey = bytesToHex(opened);
    if (!PRIVATE_KEY.test(privateKey)) return null;
    return Object.freeze({ deviceId, privateKey: privateKey as `0x${string}` });
  } catch {
    return null;
  }
}

/**
 * Persists one fresh session: a new non-extractable AES-GCM wrapping key into
 * the key store, and the wrapped session key beside the device identity into
 * the context store. Throws on failure; the caller decides whether to run
 * ephemeral instead.
 */
export async function saveServiceSession(
  input: Readonly<
    ServiceSessionInput & { session: Readonly<PersistedServiceSession>; now: () => number }
  >,
): Promise<void> {
  const keyId = serviceSessionKeyId(input.url, input.origin);
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, hexToBytes(input.session.privateKey)),
  );
  await input.stores.keys.store({ keyId, key });
  await input.stores.context.write(
    Object.freeze({
      version: OAATH_SERVICE_SESSION_VERSION,
      bindingId: storageId(input.url, input.origin),
      deviceId: input.session.deviceId,
      keyId,
      iv: bytesToHex(iv),
      ciphertext: bytesToHex(ciphertext),
      updatedAt: input.now(),
    }) as never,
  );
}
