import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createServiceDirectory } from "../src/index.js";
import { createOwnerDeviceAuthentication } from "../src/native.js";
import {
  createPostgresOwnerDeviceCredentialSchema,
  createPostgresOwnerDeviceCredentialStore,
  createPostgresRelayStore,
  createPostgresServiceDirectorySchema,
  createPostgresServiceDirectoryStore,
} from "../src/postgres.js";
import {
  CLIENT_TOKEN,
  createHarness,
  createRequest,
  createTestAuthentication,
  expectOk,
  get,
  post,
} from "./support.js";
import { permissionScope, phoneEnrollment, unenrolledDirectory } from "./support-directory.js";
import {
  createPostgresFixture,
  type PostgresFixture,
  requirePostgres,
} from "./support-postgres.js";

const personal = { workspaceId: "personal-1", ownerDeviceId: "phone-1" };
const team = { workspaceId: "team-1", ownerDeviceId: "phone-2" };

(requirePostgres ? describe : describe.skip)("PostgreSQL owner device credentials", () => {
  let fixture: PostgresFixture;
  beforeEach(async () => {
    fixture = await createPostgresFixture();
    const pool = fixture.createPool();
    await createPostgresServiceDirectorySchema(pool);
    await createPostgresOwnerDeviceCredentialSchema(pool);
    const directory = createServiceDirectory(createPostgresServiceDirectoryStore({ pool }));
    await directory.replace({ expectedRevision: null, directory: unenrolledDirectory() });
    await directory.enrollOwnerDevice(phoneEnrollment());
    await directory.enrollOwnerDevice(phoneEnrollment("team-1", 2));
    await pool.end();
  });
  afterEach(async () => {
    await fixture.end();
  });

  it("restores phone authentication and pending consent with new services, handlers and pools", async () => {
    const open = () => {
      const pool = fixture.createPool();
      const directory = createServiceDirectory(createPostgresServiceDirectoryStore({ pool }));
      const authentication = createOwnerDeviceAuthentication({
        directory,
        store: createPostgresOwnerDeviceCredentialStore({ pool }),
      });
      const clients = createTestAuthentication();
      const harness = createHarness(
        {
          ownerRouting: directory,
          authentication: {
            async authenticate(request) {
              return request.headers.get("authorization") === `Bearer ${CLIENT_TOKEN}`
                ? clients.authenticate(request)
                : authentication.authenticate(request);
            },
          },
        },
        createPostgresRelayStore({ pool }),
      );
      return {
        ...harness,
        directory,
        authentication,
        async close() {
          await harness.store.close();
          await pool.end();
        },
      };
    };
    let first: ReturnType<typeof open> | null = open();
    const tokens = [
      await first.authentication.issue(personal),
      await first.authentication.issue(team),
    ];
    const ids: string[] = [];
    for (const workspace of ["personal-1", "team-1"]) {
      const scope = JSON.parse(permissionScope(workspace));
      scope.logicalAccount = (await first.directory.read())?.directory.accounts.find(
        (account) => account.workspaceId === workspace,
      )?.account;
      ids.push((await createRequest(first, JSON.stringify(scope))).requestId);
    }
    await first.close();
    first = null;
    const restored = open();
    try {
      for (let index = 0; index < tokens.length; index++) {
        const inbox = await expectOk<{ requests: { operationId: string }[] }>(
          await restored.handler(get("/native/inbox", tokens[index]!)),
          200,
        );
        expect(inbox.requests.map((request) => request.operationId)).toEqual([ids[index]]);
      }
      expect(
        (
          await restored.handler(
            post(`/native/decisions/${ids[0]}`, tokens[0]!, { command: "reject" }),
          )
        ).status,
      ).toBe(200);
      const independent = open();
      try {
        await independent.authentication.revoke(personal);
      } finally {
        await independent.close();
      }
      expect((await restored.handler(get("/native/inbox", tokens[0]!))).status).toBe(401);
      expect((await restored.handler(get("/native/inbox", tokens[1]!))).status).toBe(200);
    } finally {
      await restored.close();
    }
  });

  it("reports a lost write response without retrying or returning an unconfirmed credential", async () => {
    const pool = fixture.createPool();
    let writes = 0;
    const interrupted = new Proxy(pool, {
      get(target, property) {
        if (property !== "query") return Reflect.get(target, property);
        return async (...args: unknown[]) => {
          const result = await Reflect.apply(target.query, target, args);
          if (typeof args[0] === "string" && args[0].startsWith("INSERT")) {
            writes += 1;
            throw new Error("injected lost write response");
          }
          return result;
        };
      },
    });
    const authentication = createOwnerDeviceAuthentication({
      directory: createServiceDirectory(createPostgresServiceDirectoryStore({ pool })),
      store: createPostgresOwnerDeviceCredentialStore({ pool: interrupted }),
    });
    await expect(authentication.issue(personal)).rejects.toMatchObject({
      code: "relay_state_ambiguous",
    });
    expect(writes).toBe(1);
    const reader = fixture.createPool();
    const result = await reader.query("SELECT count(*) FROM oaath_owner_device_credentials_v1");
    expect(result.rows[0]?.count).toBe("1");
  });
});
