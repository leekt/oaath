/**
 * Canonical OAAth identifier shapes and their exact parsers.
 *
 * One canonical shape per identifier kind:
 *
 * - `clientId`, `deviceId`, `accountId`: bounded lowercase identifier;
 * - `subjectId`: derived 32-byte lowercase hash (see `actors/subject.ts`).
 *
 * @author taek <leekt216@gmail.com>
 */
import { type ProtocolContractErrorCode, protocolFailure } from "./errors.js";
import type { CaptureFailure } from "./internal/exact-record.js";

const IDENTIFIER = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;

const ID_CODE: ProtocolContractErrorCode = "protocol_id_invalid";
const idFailure = protocolFailure(ID_CODE);

declare const idBrand: unique symbol;
type Id<Kind extends string> = string & { readonly [idBrand]: Kind };

export type ClientId = Id<"clientId">;
export type DeviceId = Id<"deviceId">;
export type AccountId = Id<"accountId">;
export type SubjectId = Id<"subjectId">;

function identifier<Parsed extends string>(
  value: unknown,
  label: string,
  fail: CaptureFailure,
): Parsed {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    return fail(`${label} must be a bounded lowercase canonical identifier`);
  }
  return value as Parsed;
}

function hashId<Parsed extends string>(
  value: unknown,
  label: string,
  fail: CaptureFailure,
): Parsed {
  if (typeof value !== "string" || !HASH.test(value)) {
    return fail(`${label} must be a lowercase 32-byte hash`);
  }
  return value as Parsed;
}

export function parseClientId(value: unknown, fail: CaptureFailure = idFailure): ClientId {
  return identifier(value, "clientId", fail);
}

export function parseDeviceId(value: unknown, fail: CaptureFailure = idFailure): DeviceId {
  return identifier(value, "deviceId", fail);
}

export function parseAccountId(value: unknown, fail: CaptureFailure = idFailure): AccountId {
  return identifier(value, "accountId", fail);
}

export function parseSubjectId(value: unknown, fail: CaptureFailure = idFailure): SubjectId {
  return hashId(value, "subjectId", fail);
}
