import { describe, expect, it } from "vitest";
import { createMemoryServiceDirectoryStore, createServiceDirectory } from "../src/index.js";
import {
  createMemoryOwnerDeviceCredentialStore,
  createOwnerDeviceAuthentication,
  type OwnerDeviceCredentialRecord,
} from "../src/native.js";
import { get } from "./support.js";
import { phoneEnrollment, unenrolledDirectory } from "./support-directory.js";

const personal = { workspaceId: "personal-1", ownerDeviceId: "phone-1" };
const team = { workspaceId: "team-1", ownerDeviceId: "phone-2" };

async function setup() {
  const directory = createServiceDirectory(createMemoryServiceDirectoryStore());
  await directory.replace({ expectedRevision: null, directory: unenrolledDirectory() });
  await directory.enrollOwnerDevice(phoneEnrollment());
  await directory.enrollOwnerDevice(phoneEnrollment("team-1", 2));
  const store = createMemoryOwnerDeviceCredentialStore();
  return {
    directory,
    store,
    authentication: createOwnerDeviceAuthentication({ directory, store }),
  };
}

describe("owner device relay authentication", () => {
  it("issues current device bindings and terminally revokes only that device's credentials", async () => {
    const { authentication, directory, store } = await setup();
    const first = await authentication.issue(personal);
    const second = await authentication.issue(personal);
    const other = await authentication.issue(team);
    expect(/^[A-Za-z0-9_-]{43}$/u.test(first)).toBe(true);
    expect(first === second).toBe(false);
    expect(await authentication.authenticate(get("/native/inbox", first))).toEqual({
      role: "owner",
      clientId: "phone-1",
      subject: "phone-subject-1",
      redirectUris: [],
      organizationAudience: null,
    });
    await authentication.revoke(personal);
    await authentication.revoke(personal);
    const recreated = createOwnerDeviceAuthentication({ directory, store });
    for (const token of [first, second])
      expect(await recreated.authenticate(get("/native/inbox", token))).toBeNull();
    expect((await recreated.authenticate(get("/native/inbox", other)))?.subject).toBe(
      "phone-subject-2",
    );
    const fresh = await recreated.issue(personal);
    expect(await recreated.authenticate(get("/native/inbox", fresh))).not.toBeNull();
    expect(await recreated.authenticate(get("/native/inbox", first))).toBeNull();
  });

  it("requires existing enrollment and never stores the bearer credential", async () => {
    const { directory, store } = await setup();
    const writes: OwnerDeviceCredentialRecord[] = [];
    const authentication = createOwnerDeviceAuthentication({
      directory,
      store: {
        ...store,
        async insert(record) {
          writes.push(record);
          return store.insert(record);
        },
      },
    });
    await expect(
      authentication.issue({ ...personal, ownerDeviceId: "absent" }),
    ).rejects.toMatchObject({ code: "relay_not_found" });
    expect(writes).toHaveLength(0);
    const token = await authentication.issue(personal);
    expect(writes).toHaveLength(1);
    expect(Object.values(writes[0]!).some((value) => value === token)).toBe(false);
    expect(writes[0]?.version).toBe("oaath.owner-device-credential/v1");
    expect(writes[0]?.revoked).toBe(false);
    for (const credential of [null, "unknown", "x".repeat(43)])
      expect(await authentication.authenticate(get("/native/inbox", credential))).toBeNull();
  });

  it("does not retarget an issued credential when its enrolled subject changes or disappears", async () => {
    const { authentication, directory } = await setup();
    const token = await authentication.issue(personal);
    const snapshot = (await directory.read())!;
    await directory.replace({
      expectedRevision: snapshot.revision,
      directory: {
        ...snapshot.directory,
        ownerDevices: snapshot.directory.ownerDevices.map((device) =>
          device.ownerDeviceId === personal.ownerDeviceId
            ? { ...device, subject: "replacement" }
            : device,
        ),
      },
    });
    expect(await authentication.authenticate(get("/native/inbox", token))).toBeNull();
    const changed = (await directory.read())!;
    await directory.replace({
      expectedRevision: changed.revision,
      directory: {
        ...changed.directory,
        ownerDevices: changed.directory.ownerDevices.filter(
          (device) => device.workspaceId !== personal.workspaceId,
        ),
        accounts: changed.directory.accounts.filter(
          (account) => account.workspaceId !== personal.workspaceId,
        ),
      },
    });
    expect(await authentication.authenticate(get("/native/inbox", token))).toBeNull();
  });

  it("rejects unreadable or mismatched storage evidence without authenticating it", async () => {
    const { authentication, directory, store } = await setup();
    const token = await authentication.issue(personal);
    for (const change of [
      (record: OwnerDeviceCredentialRecord) => ({ ...record, version: "unsupported" }),
      (record: OwnerDeviceCredentialRecord) => ({ ...record, credentialHash: "x".repeat(43) }),
      (record: OwnerDeviceCredentialRecord) => ({ ...record, revoked: null }),
    ]) {
      const reader = createOwnerDeviceAuthentication({
        directory,
        store: {
          ...store,
          async read(hash) {
            return change((await store.read(hash)) as OwnerDeviceCredentialRecord);
          },
        },
      });
      await expect(reader.authenticate(get("/native/inbox", token))).rejects.toMatchObject({
        code: "relay_record_unreadable",
      });
    }
  });
});
