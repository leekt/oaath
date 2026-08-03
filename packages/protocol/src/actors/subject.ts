/**
 * Pairwise subject binding.
 *
 * `subjectId` is derived, never client-supplied: the same person on the same
 * device gets a different `subjectId` for every client, and a parsed binding
 * whose `subjectId` does not equal the derivation is rejected. That makes a
 * stolen or guessed `subjectId` unusable and keeps the raw `userHandle` out of
 * everything keyed by subject.
 *
 * @author taek <leekt216@gmail.com>
 */
import { encodeAbiParameters, keccak256 } from "viem";
import { capturedByProtocol, protocolFailure } from "../errors.js";
import {
  type ClientId,
  type DeviceId,
  parseClientId,
  parseDeviceId,
  parseSubjectId,
  type SubjectId,
} from "../ids.js";
import { type CaptureContext, type CaptureFailure, exactRecord } from "../internal/exact-record.js";
import { captureCanonicalHttpsUrl } from "./issuer.js";

export const OAATH_SUBJECT_VERSION = "oaath.subject/v1" as const;
export const OAATH_SUBJECT_HASH_DOMAIN = "@oaath/protocol:subject" as const;

/** Opaque issuer-scoped handle: bounded printable ASCII without spaces. */
const USER_HANDLE = /^[!-~]{1,255}$/u;

export interface SubjectBinding {
  readonly version: typeof OAATH_SUBJECT_VERSION;
  /** Canonical issuer URL that assigned `userHandle`. */
  readonly issuer: string;
  readonly clientId: ClientId;
  readonly userHandle: string;
  readonly deviceId: DeviceId;
  /** Derived from every other field; see `deriveSubjectId`. */
  readonly subjectId: SubjectId;
}

export interface SubjectBindingInput {
  readonly issuer: string;
  readonly clientId: ClientId;
  readonly userHandle: string;
  readonly deviceId: DeviceId;
}

function captureInput(
  record: Readonly<Record<string, unknown>>,
  fail: CaptureFailure,
): Readonly<SubjectBindingInput> {
  if (typeof record.userHandle !== "string" || !USER_HANDLE.test(record.userHandle)) {
    return fail("subject userHandle must be a bounded printable opaque handle");
  }
  return Object.freeze({
    issuer: captureCanonicalHttpsUrl(record.issuer, "subject issuer", fail, true),
    clientId: parseClientId(record.clientId, fail),
    userHandle: record.userHandle,
    deviceId: parseDeviceId(record.deviceId, fail),
  });
}

/** The only owner of `subjectId`. ABI string encoding keeps every field length-prefixed. */
export function deriveSubjectId(input: Readonly<SubjectBindingInput>): SubjectId {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "string", name: "domain" },
        { type: "string", name: "version" },
        { type: "string", name: "issuer" },
        { type: "string", name: "clientId" },
        { type: "string", name: "userHandle" },
        { type: "string", name: "deviceId" },
      ],
      [
        OAATH_SUBJECT_HASH_DOMAIN,
        OAATH_SUBJECT_VERSION,
        input.issuer,
        input.clientId,
        input.userHandle,
        input.deviceId,
      ],
    ),
  ) as SubjectId;
}

export function captureSubjectBinding(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<SubjectBinding> {
  const record = exactRecord(
    value,
    ["version", "issuer", "clientId", "userHandle", "deviceId", "subjectId"],
    "subject binding",
    context,
    fail,
  );
  if (record.version !== OAATH_SUBJECT_VERSION)
    return fail("subject binding version is unsupported");
  const input = captureInput(record, fail);
  const subjectId = deriveSubjectId(input);
  if (parseSubjectId(record.subjectId, fail) !== subjectId) {
    return fail("subject binding subjectId does not match its derivation");
  }
  return Object.freeze({ version: OAATH_SUBJECT_VERSION, ...input, subjectId });
}

export function parseSubjectBinding(value: unknown): Readonly<SubjectBinding> {
  return capturedByProtocol(
    "subject_binding_invalid",
    "subject binding could not be captured safely",
    () => captureSubjectBinding(value, new WeakSet(), protocolFailure("subject_binding_invalid")),
  );
}

/** Derives the pairwise binding from issuer-side facts. */
export function createSubjectBinding(value: unknown): Readonly<SubjectBinding> {
  return capturedByProtocol(
    "subject_binding_invalid",
    "subject binding could not be captured safely",
    () => {
      const fail = protocolFailure("subject_binding_invalid");
      const record = exactRecord(
        value,
        ["issuer", "clientId", "userHandle", "deviceId"],
        "subject binding input",
        new WeakSet(),
        fail,
      );
      const input = captureInput(record, fail);
      return Object.freeze({
        version: OAATH_SUBJECT_VERSION,
        ...input,
        subjectId: deriveSubjectId(input),
      });
    },
  );
}
