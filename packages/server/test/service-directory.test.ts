import { describe, expect, it } from "vitest";
import { createMemoryServiceDirectoryStore, createServiceDirectory } from "../src/index.js";
import {
  CLIENT_TOKEN,
  codeChallenge,
  createHarness,
  expectFailure,
  expectOk,
  get,
  post,
  REDIRECT_URI,
} from "./support.js";
import {
  directoryDocument,
  member,
  permissionScope,
  phoneEnrollment,
  unenrolledDirectory,
} from "./support-directory.js";

describe("service directory", () => {
  it("resolves the requested personal/team account independently of the selection preference", async () => {
    const directory = createServiceDirectory(createMemoryServiceDirectoryStore());
    await directory.replace({ expectedRevision: null, directory: directoryDocument() });
    const personalRequest = { requestId: "personal-request", requestedScope: permissionScope() };
    const teamRequest = { requestId: "team-request", requestedScope: permissionScope("team-1") };
    await directory.selectAccount(member("subject-1"), {
      workspaceId: "team-1",
      accountId: "treasury",
    });
    expect(await directory.resolveOwner(member("subject-1"), personalRequest)).toEqual({
      ownerDeviceId: "phone-1",
      ownerSubject: "phone-subject-1",
    });
    expect(await directory.resolveOwner(member("subject-1"), teamRequest)).toEqual({
      ownerDeviceId: "phone-2",
      ownerSubject: "phone-subject-2",
    });
    expect(await directory.resolveOwner(member("subject-2"), personalRequest)).toBeNull();
    expect(await directory.resolveOwner(member("subject-2"), teamRequest)).not.toBeNull();
  });

  it("refuses context, account, and application substitutions before request creation", async () => {
    const directory = createServiceDirectory(createMemoryServiceDirectoryStore());
    await directory.replace({ expectedRevision: null, directory: directoryDocument() });
    const scope = JSON.parse(permissionScope());
    for (const changed of [
      { ...scope, context: { ...scope.context, workspaceKind: "team" } },
      { ...scope, context: { ...scope.context, accountId: "missing" } },
      { ...scope, logicalAccount: { ...scope.logicalAccount, accountIndex: "99" } },
      { ...scope, application: { ...scope.application, clientId: "other-client" } },
      { ...scope, application: { ...scope.application, applicationId: "other-app" } },
      { ...scope, version: "oaath.permission-request/v1" },
    ]) {
      expect(
        await directory.resolveOwner(member("subject-1"), {
          requestId: "request-1",
          requestedScope: JSON.stringify(changed),
        }),
      ).toBeNull();
    }
    const snapshot = (await directory.read())!;
    await directory.replace({
      expectedRevision: snapshot.revision,
      directory: { ...snapshot.directory, memberships: [] },
    });
    const harness = createHarness({ ownerRouting: directory });
    await expectFailure(
      await harness.handler(
        post("/authorization/requests", CLIENT_TOKEN, {
          redirectUri: REDIRECT_URI,
          codeChallenge: await codeChallenge(),
          requestedScope: permissionScope(),
        }),
      ),
      "relay_forbidden",
    );
  });

  it("resolves personal and team members through authenticated bootstrap", async () => {
    const directory = createServiceDirectory(createMemoryServiceDirectoryStore());
    expect(
      await directory.replace({ expectedRevision: null, directory: directoryDocument() }),
    ).toBe(true);
    const first = await directory.resolve(member("subject-1"));
    const second = await directory.resolve(member("subject-2"));
    expect(first?.context).toMatchObject({ workspaceId: "personal-1", accountId: "account-1" });
    expect(second?.context).toMatchObject({ workspaceId: "team-1", accountId: "treasury" });
    expect(await directory.resolve(member("unassigned"))).toBeNull();
    expect(await directory.resolve({ ...member("subject-1"), clientId: "other-app" })).toBeNull();
    const unused = async () => {
      throw new Error("bootstrap must not access a chain");
    };
    const harness = createHarness({
      bootstrap: directory,
      chains: [
        {
          chainId: 31_337,
          reads: unused,
          observation: unused,
          quote: unused,
          bundler: unused,
          submission: unused,
          usage: null,
          feePayer: null,
          staticPaymasterConfigurationHash: null,
        },
      ],
    });
    const bootstrap = await expectOk<Record<string, unknown>>(
      await harness.handler(get("/bootstrap", CLIENT_TOKEN)),
      200,
    );
    expect(bootstrap).toMatchObject({
      context: first?.context,
      application: { clientId: "client-a" },
      userHandle: "subject-1",
    });
  });

  it("allows a member to select another assigned account and rejects foreign selections", async () => {
    const directory = createServiceDirectory(createMemoryServiceDirectoryStore());
    await directory.replace({ expectedRevision: null, directory: directoryDocument() });
    expect(
      await directory.selectAccount(member("subject-1"), {
        workspaceId: "team-1",
        accountId: "treasury",
      }),
    ).toBe(true);
    expect((await directory.resolve(member("subject-1")))?.context.workspaceId).toBe("team-1");
    await expect(
      directory.selectAccount(member("subject-2"), {
        workspaceId: "personal-1",
        accountId: "account-1",
      }),
    ).rejects.toMatchObject({ code: "relay_forbidden" });
    await expect(
      directory.selectAccount(member("subject-1"), { workspaceId: "team-1", accountId: "missing" }),
    ).rejects.toMatchObject({ code: "relay_not_found" });
  });

  it("rejects stale writers without losing another caller's selection", async () => {
    const store = createMemoryServiceDirectoryStore();
    const first = createServiceDirectory(store);
    const second = createServiceDirectory(store);
    await first.replace({ expectedRevision: null, directory: directoryDocument() });
    const stale = await first.read();
    await second.selectAccount(member("subject-1"), {
      workspaceId: "team-1",
      accountId: "treasury",
    });
    expect(
      await first.replace({ expectedRevision: stale!.revision, directory: stale!.directory }),
    ).toBe(false);
    expect((await first.resolve(member("subject-1")))?.context.workspaceId).toBe("team-1");
  });

  it("removal of membership denies bootstrap even when an old selection remains", async () => {
    const directory = createServiceDirectory(createMemoryServiceDirectoryStore());
    await directory.replace({ expectedRevision: null, directory: directoryDocument() });
    const snapshot = (await directory.read())!;
    await directory.replace({
      expectedRevision: snapshot.revision,
      directory: {
        ...snapshot.directory,
        memberships: snapshot.directory.memberships.filter(
          (entry) => entry.subject !== "subject-1",
        ),
      },
    });
    expect(await directory.resolve(member("subject-1"))).toBeNull();
    expect((await directory.resolve(member("subject-2")))?.context.workspaceId).toBe("team-1");
  });

  it("refuses dangling owner references and unreadable persisted state", async () => {
    const directory = createServiceDirectory(createMemoryServiceDirectoryStore());
    await expect(
      directory.replace({
        expectedRevision: null,
        directory: { ...directoryDocument(), ownerDevices: [] },
      }),
    ).rejects.toMatchObject({ code: "relay_request_invalid" });
    const unreadable = createServiceDirectory({
      read: async () => ({ revision: 1, directory: {} }),
      compareAndSwap: async () => {
        throw new Error("must not write");
      },
    });
    await expect(unreadable.resolve(member("subject-1"))).rejects.toMatchObject({
      code: "relay_record_unreadable",
    });
  });
});

describe("phone enrollment", () => {
  it("registers a phone and its account together before personal/team bootstrap and owner routing", async () => {
    const directory = createServiceDirectory(createMemoryServiceDirectoryStore());
    await directory.replace({ expectedRevision: null, directory: unenrolledDirectory() });
    expect(await directory.resolve(member("subject-1"))).toBeNull();
    for (const [workspaceId, expectedRevision] of [
      ["personal-1", 1],
      ["team-1", 2],
    ] as const) {
      const initial = phoneEnrollment(workspaceId, expectedRevision);
      const additional = structuredClone(initial.accounts[0]!);
      const enrollment = {
        ...initial,
        accounts: [
          ...initial.accounts,
          {
            ...additional,
            accountId: "second-account",
            account: { ...additional.account, accountIndex: "2" },
          },
        ],
      };
      expect(await directory.enrollOwnerDevice(enrollment)).toBe(true);
      const caller = member(workspaceId === "personal-1" ? "subject-1" : "subject-2");
      const resolved = await directory.resolve(caller);
      expect(resolved?.account).toEqual(enrollment.accounts[0]?.account);
      const request = JSON.parse(permissionScope(workspaceId));
      request.logicalAccount = resolved!.account;
      expect(
        await directory.resolveOwner(caller, {
          requestId: "enrolled-request",
          requestedScope: JSON.stringify(request),
        }),
      ).toEqual({
        ownerDeviceId: enrollment.device.ownerDeviceId,
        ownerSubject: enrollment.device.subject,
      });
    }
    expect(await directory.resolve(member("unassigned"))).toBeNull();
    expect((await directory.read())?.directory.memberships).toEqual(
      directoryDocument().memberships,
    );
  });

  it("rejects partial or inconsistent phone registration without changing the directory", async () => {
    const directory = createServiceDirectory(createMemoryServiceDirectoryStore());
    await directory.replace({ expectedRevision: null, directory: unenrolledDirectory() });
    const enrollment = phoneEnrollment();
    const account = enrollment.accounts[0]!;
    const otherKey = phoneEnrollment().accounts[0]!.account.ownerCredential;
    for (const accounts of [
      [],
      [{ ...account, workspaceId: "team-1" }],
      [{ ...account, ownerDeviceId: "other-phone" }],
      [{ ...account, account: { ...account.account, factoryRoute: "meta_factory" } }],
      [
        account,
        {
          ...structuredClone(account),
          accountId: "second",
          account: {
            ...structuredClone(account.account),
            ownerCredential: otherKey,
          },
        },
      ],
      [directoryDocument().accounts[0]!],
    ]) {
      await expect(
        directory.enrollOwnerDevice({ ...enrollment, accounts } as typeof enrollment),
      ).rejects.toMatchObject({ code: "relay_request_invalid" });
      expect((await directory.read())?.revision).toBe(1);
      expect((await directory.read())?.directory.ownerDevices).toEqual([]);
    }
  });

  it("never overwrites an existing phone or account and returns false for stale enrollment", async () => {
    const directory = createServiceDirectory(createMemoryServiceDirectoryStore());
    await directory.replace({ expectedRevision: null, directory: unenrolledDirectory() });
    const enrollment = phoneEnrollment();
    expect(await directory.enrollOwnerDevice(enrollment)).toBe(true);
    expect(await directory.enrollOwnerDevice(phoneEnrollment("team-1", 1))).toBe(false);
    await expect(
      directory.enrollOwnerDevice({ ...enrollment, expectedRevision: 2 }),
    ).rejects.toMatchObject({ code: "relay_request_invalid" });
    await expect(
      directory.enrollOwnerDevice({
        ...enrollment,
        expectedRevision: 2,
        device: { ...enrollment.device, ownerDeviceId: "replacement" },
        accounts: enrollment.accounts.map((account) => ({
          ...account,
          ownerDeviceId: "replacement",
        })),
      }),
    ).rejects.toMatchObject({ code: "relay_request_invalid" });
    const snapshot = (await directory.read())!;
    expect(snapshot.revision).toBe(2);
    expect(snapshot.directory.ownerDevices).toEqual([enrollment.device]);
    expect(snapshot.directory.accounts).toEqual(enrollment.accounts);
  });
});
