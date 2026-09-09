import {
  captureDenseArray,
  captureRecord,
  captureServiceAccount,
  exactCapturedRecord,
  parseAccountId,
  parseClientId,
  type ServiceAccount,
} from "@oaath/protocol";
import { type RelayErrorCode, relayFailure } from "../relay/errors.js";
import { boundedText } from "../store/records.js";

export const OAATH_SERVICE_DIRECTORY_VERSION = "oaath.service-directory/v1" as const;

export interface DirectoryWorkspace {
  readonly workspaceId: string;
  readonly kind: "personal" | "team";
}
export interface DirectoryApplication {
  readonly clientId: string;
  readonly applicationId: string;
  readonly applicationName: string;
}
/** Membership names the authenticated application/user pair, not owner authority. */
export interface DirectoryMembership {
  readonly workspaceId: string;
  readonly clientId: string;
  readonly subject: string;
}
/** Enrollment identity used to route owner work; private key material is never stored here. */
export interface DirectoryOwnerDevice {
  readonly workspaceId: string;
  readonly ownerDeviceId: string;
  readonly subject: string;
}
export interface DirectoryAccount extends ServiceAccount {
  readonly workspaceId: string;
  readonly accountId: string;
  readonly ownerDeviceId: string;
  readonly chainIds: readonly number[];
}
/** A preference; current membership is checked again whenever it is resolved. */
export interface DirectorySelection extends DirectoryMembership {
  readonly accountId: string;
}

export interface ServiceDirectoryDocument {
  readonly version: typeof OAATH_SERVICE_DIRECTORY_VERSION;
  readonly workspaces: readonly Readonly<DirectoryWorkspace>[];
  readonly applications: readonly Readonly<DirectoryApplication>[];
  readonly memberships: readonly Readonly<DirectoryMembership>[];
  readonly ownerDevices: readonly Readonly<DirectoryOwnerDevice>[];
  readonly accounts: readonly Readonly<DirectoryAccount>[];
  readonly selections: readonly Readonly<DirectorySelection>[];
}

/** Captures one configuration or durable-storage boundary, including reference meaning. */
export function parseServiceDirectory(
  value: unknown,
  code: RelayErrorCode,
): Readonly<ServiceDirectoryDocument> {
  const context = new WeakSet<object>();
  const fail = (message: string): never => relayFailure(code, message);
  const record = (entry: unknown, keys: readonly string[]) =>
    exactCapturedRecord(
      captureRecord(entry, "service directory record", context, fail),
      keys,
      "service directory record",
      fail,
    );
  const id = (entry: unknown) => parseClientId(entry, fail);
  const subject = (entry: unknown) => boundedText(entry, 256, "directory subject", code);
  function rows<T>(
    entries: unknown,
    parse: (entry: unknown) => T,
    key: (entry: T) => readonly string[],
  ): readonly Readonly<T>[] {
    const seen = new Set<string>();
    return Object.freeze(
      captureDenseArray(entries, "directory records", context, fail).map((entry) => {
        const parsed = parse(entry);
        const identity = JSON.stringify(key(parsed));
        if (seen.has(identity)) return fail("directory records repeat an identity");
        seen.add(identity);
        return Object.freeze(parsed);
      }),
    );
  }
  try {
    const root = record(value, [
      "version",
      "workspaces",
      "applications",
      "memberships",
      "ownerDevices",
      "accounts",
      "selections",
    ]);
    if (root.version !== OAATH_SERVICE_DIRECTORY_VERSION)
      return fail("service directory version is unsupported");
    const workspaces = rows(
      root.workspaces,
      (value): DirectoryWorkspace => {
        const entry = record(value, ["workspaceId", "kind"]);
        if (entry.kind !== "personal" && entry.kind !== "team")
          return fail("workspace kind is unsupported");
        return { workspaceId: id(entry.workspaceId), kind: entry.kind };
      },
      (entry) => [entry.workspaceId],
    );
    const applications = rows(
      root.applications,
      (value): DirectoryApplication => {
        const entry = record(value, ["clientId", "applicationId", "applicationName"]);
        return {
          clientId: id(entry.clientId),
          applicationId: id(entry.applicationId),
          applicationName: boundedText(entry.applicationName, 256, "application name", code),
        };
      },
      (entry) => [entry.clientId],
    );
    const memberships = rows(
      root.memberships,
      (value): DirectoryMembership => {
        const entry = record(value, ["workspaceId", "clientId", "subject"]);
        return {
          workspaceId: id(entry.workspaceId),
          clientId: id(entry.clientId),
          subject: subject(entry.subject),
        };
      },
      (entry) => [entry.workspaceId, entry.clientId, entry.subject],
    );
    const ownerDevices = rows(
      root.ownerDevices,
      (value): DirectoryOwnerDevice => {
        const entry = record(value, ["workspaceId", "ownerDeviceId", "subject"]);
        return {
          workspaceId: id(entry.workspaceId),
          ownerDeviceId: id(entry.ownerDeviceId),
          subject: subject(entry.subject),
        };
      },
      (entry) => [entry.workspaceId, entry.ownerDeviceId],
    );
    const accounts = rows(
      root.accounts,
      (value): DirectoryAccount => {
        const entry = record(value, [
          "workspaceId",
          "accountId",
          "ownerDeviceId",
          "account",
          "ownerValidator",
          "chainIds",
        ]);
        const chainIds = captureDenseArray(entry.chainIds, "account chains", context, fail).map(
          (chainId) => {
            if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1)
              return fail("account chain must be a positive integer");
            return chainId;
          },
        );
        if (
          chainIds.length < 1 ||
          chainIds.length > 32 ||
          new Set(chainIds).size !== chainIds.length
        )
          return fail("account chains must contain 1 to 32 distinct chains");
        return {
          workspaceId: id(entry.workspaceId),
          accountId: parseAccountId(entry.accountId, fail),
          ownerDeviceId: id(entry.ownerDeviceId),
          ...captureServiceAccount(entry.account, entry.ownerValidator, context, fail),
          chainIds: Object.freeze(chainIds),
        };
      },
      (entry) => [entry.workspaceId, entry.accountId],
    );
    const selections = rows(
      root.selections,
      (value): DirectorySelection => {
        const entry = record(value, ["clientId", "subject", "workspaceId", "accountId"]);
        return {
          clientId: id(entry.clientId),
          subject: subject(entry.subject),
          workspaceId: id(entry.workspaceId),
          accountId: parseAccountId(entry.accountId, fail),
        };
      },
      (entry) => [entry.clientId, entry.subject],
    );

    const workspaceIds = new Set(workspaces.map((entry) => entry.workspaceId));
    const clientIds = new Set(applications.map((entry) => entry.clientId));
    for (const entry of [...memberships, ...ownerDevices, ...accounts]) {
      if (!workspaceIds.has(entry.workspaceId))
        return fail("directory reference names an absent workspace");
    }
    for (const entry of memberships) {
      if (!clientIds.has(entry.clientId)) return fail("membership names an absent application");
    }
    for (const account of accounts) {
      if (
        !ownerDevices.some(
          (owner) =>
            owner.workspaceId === account.workspaceId &&
            owner.ownerDeviceId === account.ownerDeviceId,
        )
      )
        return fail("account names an absent owner device");
    }
    // Selections can outlive membership/account removal. They never confer access.
    return Object.freeze({
      version: OAATH_SERVICE_DIRECTORY_VERSION,
      workspaces,
      applications,
      memberships,
      ownerDevices,
      accounts,
      selections,
    });
  } catch {
    return fail("service directory is invalid");
  }
}
