import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createServiceDirectory } from "../src/index.js";
import {
  createPostgresServiceDirectorySchema,
  createPostgresServiceDirectoryStore,
} from "../src/postgres.js";
import {
  directoryDocument,
  member,
  permissionScope,
  phoneEnrollment,
  unenrolledDirectory,
} from "./support-directory.js";
import {
  createPostgresFixture,
  type PostgresFixture,
  requirePostgres,
} from "./support-postgres.js";

(requirePostgres ? describe : describe.skip)("PostgreSQL service directory", () => {
  let fixture: PostgresFixture;
  beforeEach(async () => {
    fixture = await createPostgresFixture();
    await createPostgresServiceDirectorySchema(fixture.createPool());
  });
  afterEach(async () => {
    await fixture.end();
  });

  it("restores membership and account selection after every service and connection is recreated", async () => {
    const firstPool = fixture.createPool();
    let first: ReturnType<typeof createServiceDirectory> | null = createServiceDirectory(
      createPostgresServiceDirectoryStore({ pool: firstPool }),
    );
    expect(await first.replace({ expectedRevision: null, directory: directoryDocument() })).toBe(
      true,
    );
    expect(
      await first.selectAccount(member("subject-1"), {
        workspaceId: "team-1",
        accountId: "treasury",
      }),
    ).toBe(true);
    first = null;
    await firstPool.end();

    const restored = createServiceDirectory(
      createPostgresServiceDirectoryStore({ pool: fixture.createPool() }),
    );
    expect((await restored.resolve(member("subject-1")))?.context).toMatchObject({
      workspaceId: "team-1",
      workspaceKind: "team",
      accountId: "treasury",
    });
    expect((await restored.resolve(member("subject-2")))?.context.accountId).toBe("treasury");
    expect(await restored.resolve(member("unassigned"))).toBeNull();
    const snapshot = (await restored.read())!;
    expect(snapshot.revision).toBe(2);
    expect(snapshot.directory.ownerDevices[1]?.subject).toBe("phone-subject-2");
    expect(
      await restored.resolveOwner(member("subject-1"), {
        requestId: "restored-request",
        requestedScope: permissionScope(),
      }),
    ).toEqual({ ownerDeviceId: "phone-1", ownerSubject: "phone-subject-1" });
    expect(
      await restored.resolveOwner(member("subject-2"), {
        requestId: "team-request",
        requestedScope: permissionScope("team-1"),
      }),
    ).toEqual({ ownerDeviceId: "phone-2", ownerSubject: "phone-subject-2" });
  });

  it("accepts exactly one writer at the same revision on independent connections", async () => {
    const one = createServiceDirectory(
      createPostgresServiceDirectoryStore({ pool: fixture.createPool() }),
    );
    const two = createServiceDirectory(
      createPostgresServiceDirectoryStore({ pool: fixture.createPool() }),
    );
    await one.replace({ expectedRevision: null, directory: directoryDocument() });
    const oneDocument = directoryDocument();
    const twoDocument = {
      ...directoryDocument(),
      applications: [{ clientId: "client-a", applicationId: "app-a", applicationName: "Updated" }],
    };
    const results = await Promise.all([
      one.replace({ expectedRevision: 1, directory: oneDocument }),
      two.replace({ expectedRevision: 1, directory: twoDocument }),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
    const reader = createServiceDirectory(
      createPostgresServiceDirectoryStore({ pool: fixture.createPool() }),
    );
    const snapshot = (await reader.read())!;
    expect(snapshot.revision).toBe(2);
    expect(snapshot.directory.applications[0]?.applicationName).toBe(
      results[0] ? "Example" : "Updated",
    );
  });

  it("atomically enrolls one competing phone and restores it after all writers are recreated", async () => {
    const onePool = fixture.createPool();
    const twoPool = fixture.createPool();
    let one: ReturnType<typeof createServiceDirectory> | null = createServiceDirectory(
      createPostgresServiceDirectoryStore({ pool: onePool }),
    );
    let two: ReturnType<typeof createServiceDirectory> | null = createServiceDirectory(
      createPostgresServiceDirectoryStore({ pool: twoPool }),
    );
    await one.replace({ expectedRevision: null, directory: unenrolledDirectory() });
    const candidates = [phoneEnrollment(), phoneEnrollment("team-1")];
    const results = await Promise.all([
      one.enrollOwnerDevice(candidates[0]!),
      two.enrollOwnerDevice(candidates[1]!),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
    const winner = candidates[results[0] ? 0 : 1]!;
    one = null;
    two = null;
    await onePool.end();
    await twoPool.end();
    const restored = createServiceDirectory(
      createPostgresServiceDirectoryStore({ pool: fixture.createPool() }),
    );
    const snapshot = (await restored.read())!;
    expect(snapshot.revision).toBe(2);
    expect(snapshot.directory.ownerDevices).toEqual([winner.device]);
    expect(snapshot.directory.accounts).toEqual(winner.accounts);
    const caller = member(winner.device.workspaceId === "personal-1" ? "subject-1" : "subject-2");
    expect((await restored.resolve(caller))?.account).toEqual(winner.accounts[0]!.account);
    const requestedScope = JSON.parse(permissionScope(winner.device.workspaceId));
    requestedScope.logicalAccount = winner.accounts[0]!.account;
    expect(
      await restored.resolveOwner(caller, {
        requestId: "restored-enrollment",
        requestedScope: JSON.stringify(requestedScope),
      }),
    ).toEqual({ ownerDeviceId: winner.device.ownerDeviceId, ownerSubject: winner.device.subject });
  });

  it("retains a committed enrollment after a lost write response without retrying it", async () => {
    const pool = fixture.createPool();
    const seed = createServiceDirectory(createPostgresServiceDirectoryStore({ pool }));
    await seed.replace({ expectedRevision: null, directory: unenrolledDirectory() });
    let writes = 0;
    const interrupted = new Proxy(pool, {
      get(target, property) {
        if (property !== "query") return Reflect.get(target, property);
        return async (...args: unknown[]) => {
          const result = await Reflect.apply(target.query, target, args);
          if (typeof args[0] === "string" && args[0].startsWith("UPDATE")) {
            writes += 1;
            throw new Error("injected connection loss after enrollment commit");
          }
          return result;
        };
      },
    });
    const writer = createServiceDirectory(
      createPostgresServiceDirectoryStore({ pool: interrupted }),
    );
    const enrollment = phoneEnrollment();
    await expect(writer.enrollOwnerDevice(enrollment)).rejects.toMatchObject({
      code: "relay_state_ambiguous",
    });
    expect(writes).toBe(1);
    const reader = createServiceDirectory(
      createPostgresServiceDirectoryStore({ pool: fixture.createPool() }),
    );
    const snapshot = (await reader.read())!;
    expect(snapshot.directory.ownerDevices).toEqual([enrollment.device]);
    expect(snapshot.directory.accounts).toEqual(enrollment.accounts);
    expect(await reader.enrollOwnerDevice(enrollment)).toBe(false);
  });

  it("observes membership removal from an independently connected resolver", async () => {
    const admin = createServiceDirectory(
      createPostgresServiceDirectoryStore({ pool: fixture.createPool() }),
    );
    const reader = createServiceDirectory(
      createPostgresServiceDirectoryStore({ pool: fixture.createPool() }),
    );
    await admin.replace({ expectedRevision: null, directory: directoryDocument() });
    const request = { requestId: "request-1", requestedScope: permissionScope("team-1") };
    expect(await reader.resolveOwner(member("subject-1"), request)).not.toBeNull();
    expect(await reader.resolve(member("subject-1"))).not.toBeNull();
    const document = directoryDocument();
    await admin.replace({
      expectedRevision: 1,
      directory: {
        ...document,
        memberships: document.memberships.filter((entry) => entry.subject !== "subject-1"),
      },
    });
    expect(await reader.resolve(member("subject-1"))).toBeNull();
    expect(await reader.resolveOwner(member("subject-1"), request)).toBeNull();
    expect(await reader.resolveOwner(member("subject-2"), request)).not.toBeNull();
    expect(await reader.resolve(member("subject-2"))).not.toBeNull();
  });

  it("does not retry a write when the connection fails after the database committed", async () => {
    const pool = fixture.createPool();
    let writes = 0;
    const interrupted = new Proxy(pool, {
      get(target, property) {
        if (property !== "query") return Reflect.get(target, property);
        return async (...args: unknown[]) => {
          writes += 1;
          await Reflect.apply(target.query, target, args);
          throw new Error("injected connection loss after commit");
        };
      },
    });
    const writer = createServiceDirectory(
      createPostgresServiceDirectoryStore({ pool: interrupted }),
    );
    await expect(
      writer.replace({ expectedRevision: null, directory: directoryDocument() }),
    ).rejects.toMatchObject({ code: "relay_state_ambiguous" });
    expect(writes).toBe(1);
    const reader = createServiceDirectory(
      createPostgresServiceDirectoryStore({ pool: fixture.createPool() }),
    );
    expect((await reader.read())?.revision).toBe(1);
    expect((await reader.resolve(member("subject-1")))?.context.workspaceId).toBe("personal-1");
  });
});
