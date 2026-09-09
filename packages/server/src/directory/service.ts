import {
  captureRecord,
  exactCapturedRecord,
  OAATH_WORKSPACE_ACCOUNT_CONTEXT_VERSION,
  parseAccountId,
  parseClientId,
} from "@oaath/protocol";
import type { RelayOwnerRouting } from "../authorization/request.js";
import { classifyStoredAuthorizationScope } from "../authorization/scope.js";
import { relayFailure } from "../relay/errors.js";
import type { RelayBootstrapConfiguration, RelayBootstrapSelection } from "../relay/handler.js";
import type { RelayCaller } from "../security/authentication.js";
import {
  type DirectoryAccount,
  type DirectoryOwnerDevice,
  parseServiceDirectory,
  type ServiceDirectoryDocument,
} from "./records.js";

export interface ServiceDirectorySnapshot {
  readonly revision: number;
  readonly directory: Readonly<ServiceDirectoryDocument>;
}

/** One atomic row. A failed/ambiguous write is never automatically retried. */
export interface ServiceDirectoryStore {
  read(): Promise<unknown>;
  /** Null expects absence; otherwise replace exactly this revision and advance it by one. */
  compareAndSwap(
    expectedRevision: number | null,
    directory: Readonly<ServiceDirectoryDocument>,
  ): Promise<boolean>;
}

/** Deployment-authenticated pairing result; contains public identity only. */
export interface EnrollOwnerDeviceInput {
  readonly expectedRevision: number;
  readonly device: Readonly<DirectoryOwnerDevice>;
  readonly accounts: readonly Readonly<DirectoryAccount>[];
}

export interface ServiceDirectory extends RelayBootstrapConfiguration, RelayOwnerRouting {
  read(): Promise<Readonly<ServiceDirectorySnapshot> | null>;
  /** Deployment administration capability, never an unauthenticated HTTP endpoint. */
  replace(input: {
    readonly expectedRevision: number | null;
    readonly directory: unknown;
  }): Promise<boolean>;
  /**
   * Atomically enroll a new P-256 phone and its Kernel accounts in one workspace.
   * The deployment authenticates pairing and assigns the owner subject first.
   * No membership, authentication credential, or onchain operation is created.
   * False means the expected revision lost; read before a fresh admin decision.
   */
  enrollOwnerDevice(input: Readonly<EnrollOwnerDeviceInput>): Promise<boolean>;
  /** False means a concurrent directory write won; read current state before choosing again. */
  selectAccount(
    caller: Readonly<RelayCaller>,
    selection: { readonly workspaceId: string; readonly accountId: string },
  ): Promise<boolean>;
}

/**
 * Owns membership/account selection and atomic phone enrollment over one
 * versioned directory document. Enrollment moves absent device/accounts to
 * jointly registered identities; it cannot overwrite them. Its single CAS is
 * the persisted evidence and cleanup owner: a lost response causes no retry,
 * and a recreated reader sees the whole enrollment or none of it.
 * Writes use compare-and-swap; bootstrap/admission reads never reserve resources.
 * A reload reads durable state afresh. Member removal blocks new admission but
 * does not revoke grants or delete operation evidence. The deployment owns store
 * resources and cleanup; this service owns no connections and retries no writes.
 */
export function createServiceDirectory(store: ServiceDirectoryStore): Readonly<ServiceDirectory> {
  async function read(): Promise<Readonly<ServiceDirectorySnapshot> | null> {
    const raw = await store.read();
    if (raw === null) return null;
    try {
      const fail = (message: string): never => relayFailure("relay_record_unreadable", message);
      const snapshot = exactCapturedRecord(
        captureRecord(raw, "directory snapshot", new WeakSet(), fail),
        ["revision", "directory"],
        "directory snapshot",
        fail,
      );
      if (
        typeof snapshot.revision !== "number" ||
        !Number.isSafeInteger(snapshot.revision) ||
        snapshot.revision < 1
      )
        return fail("directory revision is invalid");
      return Object.freeze({
        revision: snapshot.revision,
        directory: parseServiceDirectory(snapshot.directory, "relay_record_unreadable"),
      });
    } catch {
      return relayFailure("relay_record_unreadable", "directory snapshot is unreadable");
    }
  }
  function assigned(
    directory: Readonly<ServiceDirectoryDocument>,
    caller: Readonly<RelayCaller>,
    workspaceId: string,
  ): boolean {
    return (
      caller.role === "client" &&
      directory.memberships.some(
        (member) =>
          member.workspaceId === workspaceId &&
          member.clientId === caller.clientId &&
          member.subject === caller.subject,
      )
    );
  }
  return Object.freeze<ServiceDirectory>({
    read,
    async resolveOwner(caller, input) {
      const scope = classifyStoredAuthorizationScope(input.requestedScope, input.requestId);
      if (scope.kind !== "permission-request") return null;
      const request = scope.request;
      const snapshot = await read();
      if (snapshot === null || !assigned(snapshot.directory, caller, request.context.workspaceId))
        return null;
      const directory = snapshot.directory;
      const workspace = directory.workspaces.find(
        (entry) => entry.workspaceId === request.context.workspaceId,
      );
      const application = directory.applications.find(
        (entry) => entry.clientId === caller.clientId,
      );
      const account = directory.accounts.find(
        (entry) =>
          entry.workspaceId === request.context.workspaceId &&
          entry.accountId === request.context.accountId,
      );
      if (
        !workspace ||
        !application ||
        !account ||
        workspace.kind !== request.context.workspaceKind ||
        application.applicationId !== request.application.applicationId ||
        caller.clientId !== request.application.clientId ||
        JSON.stringify(account.account) !== JSON.stringify(request.logicalAccount)
      )
        return null;
      const device = directory.ownerDevices.find(
        (entry) =>
          entry.workspaceId === workspace.workspaceId &&
          entry.ownerDeviceId === account.ownerDeviceId,
      );
      if (!device) return null;
      return Object.freeze({ ownerDeviceId: device.ownerDeviceId, ownerSubject: device.subject });
    },
    async replace(input): Promise<boolean> {
      if (
        input.expectedRevision !== null &&
        (!Number.isSafeInteger(input.expectedRevision) ||
          input.expectedRevision < 1 ||
          input.expectedRevision === Number.MAX_SAFE_INTEGER)
      ) {
        return relayFailure("relay_request_invalid", "expected directory revision is invalid");
      }
      return store.compareAndSwap(
        input.expectedRevision,
        parseServiceDirectory(input.directory, "relay_request_invalid"),
      );
    },
    async enrollOwnerDevice(input): Promise<boolean> {
      // Configuration is copied before the first await. The directory codec
      // below captures the complete proposed durable document once.
      const enrollment = structuredClone(input);
      if (
        !Number.isSafeInteger(enrollment.expectedRevision) ||
        enrollment.expectedRevision < 1 ||
        enrollment.expectedRevision === Number.MAX_SAFE_INTEGER
      ) {
        return relayFailure("relay_request_invalid", "expected directory revision is invalid");
      }
      const snapshot = await read();
      if (snapshot === null)
        return relayFailure("relay_not_found", "service directory is not initialized");
      if (snapshot.revision !== enrollment.expectedRevision) return false;
      // Appending lets the directory codec reject existing identities instead
      // of silently replacing a phone, account, or another workspace's facts.
      const proposed = parseServiceDirectory(
        {
          ...snapshot.directory,
          ownerDevices: [...snapshot.directory.ownerDevices, enrollment.device],
          accounts: [...snapshot.directory.accounts, ...enrollment.accounts],
        },
        "relay_request_invalid",
      );
      const device = proposed.ownerDevices.at(-1);
      const accounts = proposed.accounts.slice(snapshot.directory.accounts.length);
      const owner = accounts[0]?.account.ownerCredential;
      if (
        !device ||
        owner?.kind !== "p256" ||
        accounts.some(
          (account) =>
            account.workspaceId !== device.workspaceId ||
            account.ownerDeviceId !== device.ownerDeviceId ||
            account.account.factoryRoute !== "kernel_factory" ||
            account.account.ownerCredential.kind !== "p256" ||
            account.account.ownerCredential.publicKey !== owner.publicKey,
        )
      ) {
        return relayFailure(
          "relay_request_invalid",
          "phone accounts must bind one workspace, device, and P-256 owner",
        );
      }
      return store.compareAndSwap(enrollment.expectedRevision, proposed);
    },
    async selectAccount(caller, selection): Promise<boolean> {
      const fail = (message: string): never => relayFailure("relay_request_invalid", message);
      const workspaceId = parseClientId(selection.workspaceId, fail);
      const accountId = parseAccountId(selection.accountId, fail);
      const snapshot = await read();
      if (snapshot === null || !assigned(snapshot.directory, caller, workspaceId))
        return relayFailure("relay_forbidden", "caller is not a member of this workspace");
      if (
        !snapshot.directory.accounts.some(
          (account) => account.workspaceId === workspaceId && account.accountId === accountId,
        )
      )
        return relayFailure("relay_not_found", "account is not registered in this workspace");
      const selections = snapshot.directory.selections.filter(
        (entry) => entry.clientId !== caller.clientId || entry.subject !== caller.subject,
      );
      selections.push(
        Object.freeze({
          clientId: caller.clientId,
          subject: caller.subject,
          workspaceId,
          accountId,
        }),
      );
      return store.compareAndSwap(
        snapshot.revision,
        Object.freeze({ ...snapshot.directory, selections: Object.freeze(selections) }),
      );
    },
    async resolve(caller): Promise<Readonly<RelayBootstrapSelection> | null> {
      const snapshot = await read();
      if (snapshot === null) return null;
      const directory = snapshot.directory;
      const selection = directory.selections.find(
        (entry) => entry.clientId === caller.clientId && entry.subject === caller.subject,
      );
      if (!selection || !assigned(directory, caller, selection.workspaceId)) return null;
      const workspace = directory.workspaces.find(
        (entry) => entry.workspaceId === selection.workspaceId,
      );
      const application = directory.applications.find(
        (entry) => entry.clientId === caller.clientId,
      );
      const account = directory.accounts.find(
        (entry) =>
          entry.workspaceId === selection.workspaceId && entry.accountId === selection.accountId,
      );
      if (!workspace || !application || !account) return null;
      return Object.freeze({
        application: Object.freeze({
          applicationId: application.applicationId,
          applicationName: application.applicationName,
        }),
        context: Object.freeze({
          version: OAATH_WORKSPACE_ACCOUNT_CONTEXT_VERSION,
          workspaceId: workspace.workspaceId,
          workspaceKind: workspace.kind,
          accountId: account.accountId,
        }),
        account: account.account,
        ownerValidator: account.ownerValidator,
        chainIds: account.chainIds,
      });
    },
  });
}

/** Ephemeral deployment/test store; the service captures every read and write boundary. */
export function createMemoryServiceDirectoryStore(): ServiceDirectoryStore {
  let snapshot: ServiceDirectorySnapshot | null = null;
  return {
    async read() {
      return structuredClone(snapshot);
    },
    async compareAndSwap(expectedRevision, directory) {
      if ((snapshot?.revision ?? null) !== expectedRevision) return false;
      snapshot = { revision: (expectedRevision ?? 0) + 1, directory: structuredClone(directory) };
      return true;
    },
  };
}
