/**
 * Canonical OAAth identifier shapes and their exact parsers.
 *
 * One canonical shape per identifier kind:
 *
 * - `clientId`, `deviceId`, `accountId`: bounded lowercase identifier;
 * - `grantId`: bounded canonical string (the permission `requestId` becomes the
 *   `grantId` unchanged);
 * - `subjectId`: derived 32-byte lowercase hash (see `actors/subject.ts`);
 * - `operationId`: the exact ERC-4337 UserOperation hash, which already binds
 *   chain and EntryPoint;
 * - `materializationId`: `<grantId>#<chainId>`, the chain-local child of one
 *   Grant.
 *
 * Existing owners keep their own inline checks in this change; new code uses
 * this module so there is one place to consolidate into later.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type ProtocolContractErrorCode, protocolFailure } from "./errors.js";
import type { CaptureFailure } from "./internal/exact-record.js";

const IDENTIFIER = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const CHAIN_ID = /^[1-9][0-9]{0,14}$/u;
const MAX_GRANT_ID_LENGTH = 256;

const ID_CODE: ProtocolContractErrorCode = "protocol_id_invalid";
const idFailure = protocolFailure(ID_CODE);

declare const idBrand: unique symbol;
type Id<Kind extends string> = string & { readonly [idBrand]: Kind };

export type ClientId = Id<"clientId">;
export type DeviceId = Id<"deviceId">;
export type AccountId = Id<"accountId">;
export type GrantId = Id<"grantId">;
export type SubjectId = Id<"subjectId">;
export type OperationId = Id<"operationId">;
export type MaterializationId = Id<"materializationId">;

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

export function parseGrantId(value: unknown, fail: CaptureFailure = idFailure): GrantId {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_GRANT_ID_LENGTH ||
    value !== value.trim()
  ) {
    return fail("grantId must be a bounded canonical string");
  }
  return value as GrantId;
}

export function parseSubjectId(value: unknown, fail: CaptureFailure = idFailure): SubjectId {
  return hashId(value, "subjectId", fail);
}

export function parseOperationId(value: unknown, fail: CaptureFailure = idFailure): OperationId {
  return hashId(value, "operationId", fail);
}

export function parseMaterializationId(
  value: unknown,
  fail: CaptureFailure = idFailure,
): MaterializationId {
  if (typeof value !== "string") return fail("materializationId must be a string");
  const separator = value.lastIndexOf("#");
  if (separator < 1) return fail("materializationId must be <grantId>#<chainId>");
  parseGrantId(value.slice(0, separator), fail);
  if (!CHAIN_ID.test(value.slice(separator + 1))) {
    return fail("materializationId must end in a canonical positive chainId");
  }
  return value as MaterializationId;
}

/** The only owner of the `(grantId, chainId)` materialization identifier. */
export function deriveMaterializationId(
  grantId: unknown,
  chainId: unknown,
  fail: CaptureFailure = idFailure,
): MaterializationId {
  const grant = parseGrantId(grantId, fail);
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
    return fail("materializationId chainId must be a positive safe integer");
  }
  return parseMaterializationId(`${grant}#${chainId}`, fail);
}
