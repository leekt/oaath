import {
  captureRecord,
  type EcdsaOperatorCredentialProfile,
  exactCapturedRecord,
  parseOperatorCredentialProfile,
} from "@oaath/protocol";

export const OAATH_SESSION_SIGNER_BINDING_VERSION = "oaath.session-signer-binding/v1" as const;
export type SessionSignerErrorCode =
  | "session_signer_input_invalid"
  | "session_signer_binding_unavailable"
  | "session_signer_binding_mismatch"
  | "session_signer_custody_unavailable"
  | "session_signer_registry_unavailable";

export class SessionSignerError extends Error {
  readonly code: SessionSignerErrorCode;
  constructor(code: SessionSignerErrorCode) {
    super(code);
    this.code = code;
    this.name = "SessionSignerError";
  }
}

export interface SessionSignerIdentity {
  readonly clientId: string;
  readonly subject: string;
  readonly deviceId: string;
}
export interface SessionSignerBinding {
  readonly version: typeof OAATH_SESSION_SIGNER_BINDING_VERSION;
  readonly identity: Readonly<SessionSignerIdentity>;
  readonly providerId: string;
  readonly credential: Readonly<EcdsaOperatorCredentialProfile>;
  readonly sealedReference: string;
}
/** Immutable bindings. create serializes its producer across all connections,
 * returns an existing winner without invoking the producer, and commits before return.
 * Failed/unknown writes throw; explicit creation retries reconcile the winner.
 */
export interface SessionSignerRegistry {
  readonly read: (identity: string) => Promise<unknown>;
  readonly create: (
    identity: string,
    produce: () => Promise<Readonly<SessionSignerBinding>>,
  ) => Promise<unknown>;
}

function invalid(): never {
  throw new SessionSignerError("session_signer_input_invalid");
}
export function signerText(value: unknown, maximum = 256): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) invalid();
  return value;
}
export function signerRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  return exactCapturedRecord(
    captureRecord(value, "session signer", new WeakSet(), invalid),
    fields,
    "session signer",
    invalid,
  );
}
export function captureSignerIdentity(value: unknown): Readonly<SessionSignerIdentity> {
  const record = signerRecord(value, ["clientId", "subject", "deviceId"]);
  return Object.freeze({
    clientId: signerText(record.clientId),
    subject: signerText(record.subject),
    deviceId: signerText(record.deviceId),
  });
}
export function signerIdentityKey(identity: Readonly<SessionSignerIdentity>): string {
  return JSON.stringify([identity.clientId, identity.subject, identity.deviceId]);
}
export function captureSignerCredential(value: unknown): Readonly<EcdsaOperatorCredentialProfile> {
  try {
    const credential = parseOperatorCredentialProfile(value);
    if (credential.kind !== "ecdsa") return invalid();
    return credential;
  } catch {
    return invalid();
  }
}
export function captureSignerBinding(value: unknown): Readonly<SessionSignerBinding> {
  try {
    const record = signerRecord(value, [
      "version",
      "identity",
      "providerId",
      "credential",
      "sealedReference",
    ]);
    if (record.version !== OAATH_SESSION_SIGNER_BINDING_VERSION) invalid();
    return Object.freeze({
      version: OAATH_SESSION_SIGNER_BINDING_VERSION,
      identity: captureSignerIdentity(record.identity),
      providerId: signerText(record.providerId),
      credential: captureSignerCredential(record.credential),
      sealedReference: signerText(record.sealedReference, 65_536),
    });
  } catch {
    throw new SessionSignerError("session_signer_binding_unavailable");
  }
}

/** Explicit ephemeral backend; use PostgreSQL for restart durability. */
export function createMemorySessionSignerRegistry(): SessionSignerRegistry {
  const bindings = new Map<string, Readonly<SessionSignerBinding>>();
  const creating = new Map<string, Promise<Readonly<SessionSignerBinding>>>();
  return Object.freeze({
    async read(identity: string) {
      return bindings.get(identity) ?? null;
    },
    async create(identity: string, produce: () => Promise<Readonly<SessionSignerBinding>>) {
      const existing = bindings.get(identity);
      if (existing) return existing;
      const pending = creating.get(identity);
      if (pending) return pending;
      const creation = Promise.resolve()
        .then(produce)
        .then(captureSignerBinding)
        .then((binding) => {
          if (signerIdentityKey(binding.identity) !== identity)
            throw new SessionSignerError("session_signer_binding_mismatch");
          bindings.set(identity, binding);
          return binding;
        });
      creating.set(identity, creation);
      try {
        return await creation;
      } finally {
        creating.delete(identity);
      }
    },
  });
}
