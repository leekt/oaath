/**
 * The URL-only golden path: one service URL, everything else authenticated
 * service context or locally derived.
 *
 * @author taek <leekt216@gmail.com>
 */

import { p256 } from "@noble/curves/nist.js";
import { OAATH_OWNER_CREDENTIAL_PROFILE_VERSION } from "@oaath/protocol";
import { createKmsSessionSignerProvider } from "@oaath/server";
import { IDBFactory } from "fake-indexeddb";
import { bytesToHex, keccak256 } from "viem";
import { describe, expect, it } from "vitest";
import { createOAAth, type OaathRequestPermissionInput } from "../src/index.js";
import { webauthnKey } from "../src/kernel/key/webauthn.js";
import { createIndexedDbCleanupStore } from "../src/persistence/indexeddb/cleanup-store.js";
import { createIndexedDbContextStore } from "../src/persistence/indexeddb/context-store.js";
import { type OaathDatabase, openOaathDatabase } from "../src/persistence/indexeddb/database.js";
import { createIndexedDbGrantStoreAdapter } from "../src/persistence/indexeddb/grant-store.js";
import { createIndexedDbKeyStore } from "../src/persistence/indexeddb/key-store.js";
import { createIndexedDbOperationStoreAdapter } from "../src/persistence/indexeddb/operation-store.js";
import { createIndexedDbWalletCallBundleStoreAdapter } from "../src/persistence/indexeddb/wallet-call-bundle-store.js";
import { OAATH_INDEXEDDB_NAME } from "../src/persistence.js";

function idbStores(database: OaathDatabase) {
  return {
    grants: createIndexedDbGrantStoreAdapter(database),
    operations: createIndexedDbOperationStoreAdapter(database),
    walletCallBundles: createIndexedDbWalletCallBundleStoreAdapter(database),
    keys: createIndexedDbKeyStore(database),
    cleanup: createIndexedDbCleanupStore(database),
    context: createIndexedDbContextStore(database),
  };
}

import {
  accountProfile,
  CHAIN_ID,
  CLIENT_TOKEN,
  createChainFixture,
  createClock,
  createMemoryStores,
  createRelay,
  createUrlRealm,
  ISSUER_URL,
  ORIGIN,
  OWNER_TOKEN,
  permissionInput,
  relayChainPort,
  relayKms,
  sendCallsInput,
  VALIDATOR,
  workspaceContext,
} from "./support/browser.js";

/** Public passkey material only; approval must never ask it to sign. */
function passkeySession() {
  const { kind: _kind, ...material } = {
    kind: "webauthn" as const,
    credential: {
      version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
      kind: "webauthn" as const,
      publicKey: bytesToHex(p256.getPublicKey(p256.utils.randomPrivateKey(), false)),
      authenticatorIdHash: keccak256("0x000102030405060708090a0b0c0d0e0f"),
    },
    credentialId: "AAECAwQFBgcICQoLDA0ODw",
    rpId: "app.example",
    origin: ORIGIN,
    authenticate: async (): Promise<never> => {
      throw new Error("approval must not use the passkey");
    },
  };
  return { session: { kind: "webauthn" as const, ...material }, key: webauthnKey(material) };
}

describe("URL-only golden path", () => {
  it("binds a caller-supplied passkey session and resumes it after reload", async () => {
    const passkey = passkeySession();
    const factory = new IDBFactory();
    const life = async () => idbStores(await openOaathDatabase({ factory }));
    const first = createUrlRealm({
      session: passkey.session,
      owner: { operatorKey: passkey.key },
      stores: await life(),
    });
    const connection = await first.oaath.connect();
    expect(first.oaath.binding.operatorCredential).toMatchObject({
      kind: "webauthn",
      publicKey: passkey.session.credential.publicKey,
    });
    expect(first.oaath.binding.subject.deviceId).toMatch(/^passkey-[0-9a-f]{32}$/u);
    expect((await connection.requestPermission(permissionInput())).state).toBe("active");
    const identity = first.oaath.binding;
    await connection.close();
    // Reload with the same passkey: the same binding resumes the same Grant.
    const second = createUrlRealm({
      session: passkey.session,
      owner: { operatorKey: passkey.key },
      stores: await life(),
      relay: first.relay,
      clock: first.clock,
      chain: first.chain,
    });
    const reconnected = await second.oaath.connect();
    expect((await reconnected.resume())?.state).toBe("active");
    expect(second.oaath.binding).toEqual(identity);
    await reconnected.close();
  });

  it("refuses a caller-supplied session under remote custody before any signer route", async () => {
    const realm = createUrlRealm({
      session: passkeySession().session,
      sessionSigner: {
        mode: "oaath_hosted",
        providerId: "kms-primary",
        provider: createKmsSessionSignerProvider({ kms: relayKms() }),
      },
    });
    await expect(realm.oaath.connect()).rejects.toMatchObject({
      code: "oaath_client_capability_unsupported",
      source: "session_custody_unsupported",
    });
    expect(realm.fetched).toEqual(["GET /bootstrap"]);
    // A passkey asserting remote custody fails at configuration, before any fetch.
    expect(() =>
      createOAAth({
        approvals: { kind: "service", url: ISSUER_URL },
        session: { ...passkeySession().session, custody: "oaath-hosted" },
      } as never),
    ).toThrow(
      expect.objectContaining({
        code: "oaath_client_capability_unsupported",
        source: "session_custody_unsupported",
      }),
    );
    expect(() =>
      createOAAth({
        approvals: { kind: "service", url: ISSUER_URL },
        session: { custody: "owner-hosted" },
      } as never),
    ).toThrow(expect.objectContaining({ code: "oaath_client_input_invalid" }));
    expect(() =>
      createOAAth({
        approvals: { kind: "service", url: ISSUER_URL },
        session: { kind: "p256" },
      } as never),
    ).toThrow(expect.objectContaining({ code: "oaath_client_input_invalid" }));
  });

  it("exposes the issued match code once before polling for the owner decision", async () => {
    const upstream = createUrlRealm();
    let issued: unknown;
    const realm = createUrlRealm({
      relay: async (request) => {
        const response = await upstream.relay(request);
        if (
          request.method === "POST" &&
          new URL(request.url).pathname === "/authorization/requests"
        ) {
          issued = await response.clone().json();
        }
        return response;
      },
    });
    const displays: Parameters<NonNullable<OaathRequestPermissionInput["onPending"]>>[0][] = [];
    let polledBeforeDisplay = false;
    const onPending: NonNullable<OaathRequestPermissionInput["onPending"]> = (pending) => {
      displays.push(pending);
      polledBeforeDisplay = realm.fetched.some((path) => path.endsWith("/code"));
    };
    const grant = await (await realm.oaath.connect()).requestPermission(
      permissionInput({ onPending }),
    );
    expect(displays).toHaveLength(1);
    expect(displays[0]).toEqual(issued);
    expect(Object.isFrozen(displays[0])).toBe(true);
    expect(polledBeforeDisplay).toBe(false);
    expect(grant.state).toBe("active");
    await realm.oaath.close();
    await upstream.oaath.close();
  });

  it.each([undefined, "short", "123456789", "abcd ef!"])(
    "rejects an invalid issuer match code before display or code redemption (%s)",
    async (matchCode) => {
      const upstream = createUrlRealm();
      const realm = createUrlRealm({
        relay: async (request) => {
          const response = await upstream.relay(request);
          if (
            request.method !== "POST" ||
            new URL(request.url).pathname !== "/authorization/requests"
          )
            return response;
          return new Response(JSON.stringify({ ...(await response.json()), matchCode }), {
            status: 201,
          });
        },
      });
      let displays = 0;
      await expect(
        (await realm.oaath.connect()).requestPermission(
          permissionInput({
            onPending: () => {
              displays += 1;
            },
          }),
        ),
      ).rejects.toMatchObject({ code: "oaath_client_issuer_unavailable" });
      expect(displays).toBe(0);
      expect(
        realm.fetched.some((path) => path.endsWith("/code") || path.endsWith("/consume")),
      ).toBe(false);
      await realm.oaath.close();
      await upstream.oaath.close();
    },
  );

  it.each([
    {
      label: "native rejection",
      authorization: undefined,
      code: "oaath_client_permission_rejected",
    },
    {
      label: "unrecognized callback error",
      authorization: {
        async authorize() {
          throw new Error("the owner rejected the permission request");
        },
      },
      code: "oaath_client_decision_unavailable",
    },
    {
      label: "unrecognized callback object",
      authorization: {
        async authorize() {
          throw { code: "oaath_client_permission_rejected" };
        },
      },
      code: "oaath_client_decision_unavailable",
    },
  ])(
    "reports $label without redeeming a code or creating a grant",
    async ({ authorization, code }) => {
      const clock = createClock();
      const chain = createChainFixture();
      const relay = createRelay(clock, {
        bootstrap: {
          resolve: async () => ({
            application: { applicationId: "app-a", applicationName: "OAAth Example" },
            context: workspaceContext,
            account: accountProfile,
            ownerValidator: VALIDATOR,
            chainIds: [chain.capability.chainId],
          }),
        },
        chains: [relayChainPort(chain)],
      });
      const posts: string[] = [];
      let codePickups = 0;
      const oaath = createOAAth({
        origin: ORIGIN,
        now: clock.now,
        stores: { kind: "memory" },
        approvals: {
          kind: "service",
          url: ISSUER_URL,
          ...(authorization ? { authorization } : {}),
          fetch: async (request: Request) => {
            const path = new URL(request.url).pathname;
            if (request.method === "POST") posts.push(path);
            if (path.endsWith("/code")) codePickups += 1;
            const headers = new Headers(request.headers);
            headers.set("authorization", `Bearer ${CLIENT_TOKEN}`);
            const response = await relay(new Request(request, { headers }));
            if (request.method === "POST" && path === "/authorization/requests") {
              expect(response.status).toBe(201);
              const { requestId } = await response.clone().json();
              const ownerHeaders = { authorization: `Bearer ${OWNER_TOKEN}` };
              const consent = await relay(
                new Request(`${ISSUER_URL}/native/projections/${requestId}`, {
                  headers: ownerHeaders,
                }),
              );
              expect(consent.status).toBe(200);
              const decision = await relay(
                new Request(`${ISSUER_URL}/native/decisions/${requestId}`, {
                  method: "POST",
                  headers: { ...ownerHeaders, "content-type": "application/json" },
                  body: JSON.stringify({ command: "reject" }),
                }),
              );
              expect(decision.status).toBe(200);
              expect((await decision.json()).outcome).toBe("rejected");
            }
            return response;
          },
        },
      });
      try {
        const connection = await oaath.connect();
        await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
          code,
        });
        expect(await connection.resume()).toBeNull();
        expect(posts).toEqual(["/authorization/requests"]);
        expect(codePickups).toBe(authorization ? 0 : 1);
        expect(chain.quotes).toBe(0);
        expect(chain.sends).toHaveLength(0);
        expect(chain.signatures).toHaveLength(0);
      } finally {
        await oaath.close();
      }
    },
  );

  it("requests phone revocation through the URL again after reload without owner quotes or sends", async () => {
    const factory = new IDBFactory();
    const clock = createClock();
    const chain = createChainFixture();
    const upstream = createUrlRealm({ clock, chain });
    const requested: string[] = [];
    const relay = async (request: Request) => {
      const path = new URL(request.url).pathname;
      if (request.method === "POST" && /^\/grants\/[^/]+\/revocations\/[0-9]+$/u.test(path)) {
        expect(await request.json()).toEqual({});
        requested.push(path);
        return new Response(JSON.stringify({ status: "pending" }), { status: 200 });
      }
      return upstream.relay(request);
    };
    const firstDatabase = await openOaathDatabase({ factory });
    const first = createUrlRealm({ clock, chain, relay, stores: idbStores(firstDatabase) });
    const connection = await first.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    expect((await (await grant.sendCalls(sendCallsInput())).wait()).status).toBe("finalized");
    const quotes = chain.quotes;
    await grant.revoke();
    expect(grant.state).toBe("revoking");
    expect(requested).toHaveLength(1);
    expect(chain.quotes).toBe(quotes);
    expect(chain.sends).toHaveLength(1);
    await first.oaath.close();
    await firstDatabase.close();
    const secondDatabase = await openOaathDatabase({ factory });
    const second = createUrlRealm({
      clock: createClock(),
      chain,
      relay,
      stores: idbStores(secondDatabase),
    });
    const restored = await (await second.oaath.connect()).resume();
    if (!restored) throw new Error("missing revoking grant");
    await restored.revoke();
    expect(restored.state).toBe("revoking");
    expect(requested).toEqual([requested[0], requested[0]]);
    expect(chain.quotes).toBe(quotes);
    expect(chain.sends).toHaveLength(1);
    await second.oaath.close();
    await secondDatabase.close();
    await upstream.oaath.close();
  });

  it("attempts every configured phone request even when one enqueue fails", async () => {
    const clock = createClock();
    const chain = createChainFixture();
    const upstream = createUrlRealm({ clock, chain });
    const requested: number[] = [];
    const otherChain = 8453;
    let failFirst = true;
    const relay = async (request: Request) => {
      const path = new URL(request.url).pathname;
      const match = /^\/grants\/[^/]+\/revocations\/([0-9]+)$/u.exec(path);
      if (request.method === "POST" && match) {
        const chainId = Number(match[1]);
        requested.push(chainId);
        return new Response(JSON.stringify({ status: "pending" }), {
          status: chainId === otherChain && failFirst ? 503 : 200,
        });
      }
      return upstream.relay(request);
    };
    const realm = createUrlRealm({
      clock,
      chain,
      relay,
      bootstrap: (document) => ({
        ...document,
        chains: [
          ...(document.chains as readonly unknown[]),
          { ...(document.chains as readonly Record<string, unknown>[])[0], chainId: otherChain },
        ],
      }),
    });
    const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
    await expect(grant.revoke()).rejects.toMatchObject({ code: "oaath_client_issuer_rejected" });
    expect(grant.state).toBe("revoking");
    expect(requested).toEqual([otherChain, CHAIN_ID]);
    failFirst = false;
    await grant.revoke();
    expect(requested).toEqual([otherChain, CHAIN_ID, otherChain, CHAIN_ID]);
    expect(grant.state).toBe("revoking");
    expect(chain.quotes).toBe(0);
    expect(chain.sends).toHaveLength(0);
    await realm.oaath.close();
    await upstream.oaath.close();
  });

  it("recovers a pending public operation after full IndexedDB recreation and grant expiry", async () => {
    const factory = new IDBFactory();
    const clock = createClock();
    let withhold = true;
    const chain = createChainFixture({ withholdReceipt: () => withhold });
    const firstDatabase = await openOaathDatabase({ factory });
    const first = createUrlRealm({ clock, chain, stores: idbStores(firstDatabase) });
    const connection = await first.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    const operation = await grant.sendCalls(sendCallsInput());
    const reference = { chain: operation.chainId, id: operation.id };
    expect((await operation.observe()).status).toBe("pending");
    await first.oaath.close();
    await firstDatabase.close();
    clock.advance(1_801);

    const secondDatabase = await openOaathDatabase({ factory });
    const second = createUrlRealm({
      clock,
      chain,
      relay: first.relay,
      stores: idbStores(secondDatabase),
    });
    const reconnected = await second.oaath.connect();
    const resumed = await reconnected.resume();
    if (resumed === null) throw new Error("missing resumable operation history");
    await expect(resumed.sendCalls(sendCallsInput())).rejects.toMatchObject({
      code: "oaath_client_grant_inactive",
    });
    const recovered = await resumed.getOperation(reference);
    expect(recovered?.id).toBe(reference.id);
    expect((await recovered?.observe())?.status).toBe("pending");
    withhold = false;
    expect((await recovered?.wait())?.status).toBe("finalized");
    expect(chain.quotes).toBe(1);
    expect(chain.signatures).toHaveLength(1);
    expect(chain.sends).toHaveLength(1);
    expect(second.fetched).not.toContain("POST /authorization/requests");
    await second.oaath.close();
    await secondDatabase.close();
  });

  it("isolates selected workspaces across complete IndexedDB recreation", async () => {
    const factory = new IDBFactory();
    let selected = "personal-1";
    const bootstrap = (document: Record<string, unknown>) => ({
      ...document,
      context: {
        version: "oaath.workspace-account-context/v1",
        workspaceId: selected,
        workspaceKind: selected === "personal-1" ? "personal" : "team",
        accountId: "account-1",
      },
    });
    const life = async () => {
      const database = await openOaathDatabase({ factory });
      const realm = createUrlRealm({ stores: idbStores(database), bootstrap });
      const connection = await realm.oaath.connect();
      return {
        realm,
        connection,
        close: async () => {
          await connection.close();
          await database.close();
        },
      };
    };
    const first = await life();
    await first.connection.requestPermission(permissionInput());
    const personalBinding = first.realm.oaath.binding;
    await first.close();

    selected = "team-1";
    const second = await life();
    expect(second.realm.oaath.binding.bindingId).not.toBe(personalBinding.bindingId);
    expect(second.realm.oaath.binding.operatorCredential).not.toEqual(
      personalBinding.operatorCredential,
    );
    expect(await second.connection.resume()).toBeNull();
    await second.realm.oaath.disconnect(null);
    await second.close();

    selected = "personal-1";
    const third = await life();
    expect(third.realm.oaath.binding.bindingId).toBe(personalBinding.bindingId);
    expect(third.realm.oaath.binding.operatorCredential).toEqual(
      personalBinding.operatorCredential,
    );
    expect(await third.connection.resume()).not.toBeNull();
    await third.close();
  });

  it("rejects a service chain that advertises both sponsorship kinds", async () => {
    // The chain sponsorship setting holds one kind; the bootstrap cannot name two.
    const bootstrap = (document: Record<string, unknown>) => ({
      ...document,
      chains: (document.chains as Record<string, unknown>[]).map((chain) => ({
        ...chain,
        paymasterService: { providerId: "sponsor" },
        staticPaymasterConfigurationHash: `0x${"11".repeat(32)}`,
      })),
    });
    const realm = createUrlRealm({ bootstrap });
    await expect(realm.oaath.connect()).rejects.toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_capability_invalid",
    });
    expect(realm.fetched).not.toContain("POST /authorization/requests");
  });

  it("retains revocation when phone preparation is unconfigured and completes from observed effects", async () => {
    // The chain's answer to "is the permission still installed", and how far
    // the chain advanced beyond this realm's own submissions — both flip when
    // the owner's console removes the permission out of band.
    let permissionInstalled: boolean | null = null;
    let blockOffset = 0;
    const realm = createUrlRealm({
      chain: createChainFixture({
        permissionInstalled: () => permissionInstalled,
        blockOffset: () => blockOffset,
      }),
    });
    // No binding exists before the service context does.
    expect(() => realm.oaath.binding).toThrowError(
      expect.objectContaining({ name: "OaathClientError" }),
    );

    const connection = await realm.oaath.connect();
    // The binding is the service's registered identity, not a page assertion.
    expect(realm.oaath.binding.application.clientId).toBe("client-a");
    expect(realm.oaath.binding.account.ownerCredential.kind).toBe("ecdsa");
    // The operator credential is the locally generated session key's identity.
    expect(realm.oaath.binding.operatorCredential.kind).toBe("ecdsa");
    expect(realm.fetched[0]).toBe("GET /bootstrap");

    const grant = await connection.requestPermission(permissionInput());
    expect(grant.state).toBe("active");

    const operation = await grant.sendCalls(sendCallsInput());
    expect((await operation.wait()).status).toBe("finalized");
    // The one submission rode the service relay, session-signed.
    expect(realm.chain.sends).toHaveLength(1);
    expect(
      realm.fetched.filter((entry) => entry === `POST /chains/${CHAIN_ID}/submissions`),
    ).toHaveLength(1);

    await expect(grant.revoke()).rejects.toMatchObject({ code: "oaath_client_issuer_rejected" });
    // This service has no phone preparation port. Admission still stops,
    // and the missing route leaves its revocation obligation recoverable.
    // The capability died through the service, but the installed chain
    // permission awaits owner-signed removal: durably revoking, never a
    // claimed revocation no chain observed. This realm holds no owner
    // authority, so nothing rode the submission route a second time.
    expect(grant.state).toBe("revoking");
    expect(realm.invalidations()).toBe(1);
    expect(realm.chain.sends).toHaveLength(1);

    // The owner's console removes the permission out of band; the chain
    // advances and the signer module reads conclusively absent. The next
    // revoke completes from that finalized-anchored evidence alone — still
    // without this realm ever signing owner work.
    permissionInstalled = false;
    blockOffset = 1;
    await grant.revoke();
    expect(grant.state).toBe("revoked");
    expect(realm.chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("survives a reload: a recreated realm resumes the Grant with the same session", async () => {
    // Durable IndexedDB with fresh adapter handles per life, exactly like a
    // browser reload: the data survives, the handles do not.
    const factory = new IDBFactory();
    const life = async () => idbStores(await openOaathDatabase({ factory }));

    // First life: connect, get authority, execute (which materializes the
    // permission on chain for exactly this session key).
    const first = createUrlRealm({ stores: await life() });
    const connection = await first.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    expect((await (await grant.sendCalls(sendCallsInput())).wait()).status).toBe("finalized");
    const operatorBefore = first.oaath.binding.operatorCredential;
    const deviceBefore = first.oaath.binding.subject.deviceId;
    await connection.close();

    // Second life: same durable data and issuer, a brand-new realm — the
    // reload. The persisted session keeps the device identity and operator
    // key stable, so resume() finds a Grant this realm can still sign for,
    // and the next operation validates through the already-installed
    // permission instead of orphaning it.
    const second = createUrlRealm({
      clock: first.clock,
      chain: first.chain,
      stores: await life(),
      relay: first.relay,
    });
    const reconnected = await second.oaath.connect();
    expect(second.oaath.binding.operatorCredential).toEqual(operatorBefore);
    expect(second.oaath.binding.subject.deviceId).toBe(deviceBefore);
    const resumed = await reconnected.resume();
    expect(resumed).not.toBeNull();
    expect(resumed?.state).toBe("active");
    const operation = await resumed?.sendCalls(sendCallsInput());
    expect((await operation?.wait())?.status).toBe("finalized");
    // Standard permission validation: the reload spent no second approval.
    const nonce = BigInt(first.chain.sends[1]?.userOperation.nonce ?? 0n);
    expect((nonce >> 248n) & 0xffn).toBe(0n);
    await reconnected.close();
  });

  it("completes the golden path over the loopback development URL", async () => {
    // The advertised default is `http://localhost:8787`; this proves a valid
    // loopback bootstrap composes and executes, not merely that an invalid
    // one fails there.
    const realm = createUrlRealm({ url: "http://localhost:8787" });
    const connection = await realm.oaath.connect();
    expect(realm.oaath.binding.issuer.url).toBe("http://localhost:8787");
    const grant = await connection.requestPermission(permissionInput());
    const operation = await grant.sendCalls(sendCallsInput());
    expect((await operation.wait()).status).toBe("finalized");
    expect(realm.chain.sends).toHaveLength(1);
    await connection.close();
  });

  it("defaults to the local development service URL", async () => {
    const seen: string[] = [];
    const oaath = createOAAth({
      approvals: {
        kind: "service",
        fetch: async (request: Request) => {
          seen.push(request.url);
          return new Response("{}", { status: 200 });
        },
      },
      origin: "https://app.example",
      now: () => 1_800_000_000,
    });
    // @ts-expect-error service approvals hold no owner signer, so no owner execution
    expect(oaath.account).toBeUndefined();
    await expect(oaath.connect()).rejects.toMatchObject({ name: "OaathClientError" });
    expect(seen).toEqual(["http://localhost:8787/bootstrap"]);
  });

  it("fails closed without IndexedDB instead of falling back to memory", async () => {
    const previous = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
    Reflect.deleteProperty(globalThis, "indexedDB");
    const clock = createClock();
    const chain = createChainFixture();
    const relay = createRelay(clock, {
      bootstrap: {
        resolve: async () => ({
          application: { applicationId: "app-a", applicationName: "OAAth Example" },
          context: workspaceContext,
          account: accountProfile,
          ownerValidator: VALIDATOR,
          chainIds: [chain.capability.chainId],
        }),
      },
      chains: [relayChainPort(chain)],
    });
    const oaath = createOAAth({
      approvals: {
        kind: "service",
        url: ISSUER_URL,
        fetch: (request: Request) => {
          const headers = new Headers(request.headers);
          headers.set("authorization", `Bearer ${CLIENT_TOKEN}`);
          return relay(new Request(request, { headers }));
        },
      },
      origin: ORIGIN,
      now: clock.now,
    });
    try {
      await expect(oaath.connect()).rejects.toMatchObject({
        code: "oaath_client_store_unavailable",
      });
    } finally {
      await oaath.close();
      if (previous !== undefined) Object.defineProperty(globalThis, "indexedDB", previous);
    }
  });

  it("closes the default IndexedDB connection after URL disconnect", async () => {
    const factory = new IDBFactory();
    const previous = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: factory });
    const clock = createClock();
    const chain = createChainFixture();
    const relay = createRelay(clock, {
      bootstrap: {
        resolve: async () => ({
          application: { applicationId: "app-a", applicationName: "OAAth Example" },
          context: workspaceContext,
          account: accountProfile,
          ownerValidator: VALIDATOR,
          chainIds: [chain.capability.chainId],
        }),
      },
      chains: [relayChainPort(chain)],
    });
    const oaath = createOAAth({
      approvals: {
        kind: "service",
        url: ISSUER_URL,
        fetch: (request: Request) => {
          const headers = new Headers(request.headers);
          headers.set("authorization", `Bearer ${CLIENT_TOKEN}`);
          return relay(new Request(request, { headers }));
        },
      },
      origin: ORIGIN,
      now: clock.now,
    });
    try {
      const connection = await oaath.connect();
      expect(connection.binding.issuer.url).toBe(ISSUER_URL);
      await oaath.disconnect(null);
      const deletion = await new Promise<"blocked" | "deleted">((resolve, reject) => {
        const request = factory.deleteDatabase(OAATH_INDEXEDDB_NAME);
        request.onblocked = () => resolve("blocked");
        request.onsuccess = () => resolve("deleted");
        request.onerror = () => reject(request.error ?? new Error("database deletion failed"));
      });
      expect(deletion).toBe("deleted");
    } finally {
      await oaath.close().catch(() => undefined);
      if (previous === undefined) Reflect.deleteProperty(globalThis, "indexedDB");
      else Object.defineProperty(globalThis, "indexedDB", previous);
    }
  });

  it("retains the default IndexedDB owner when inner disconnect fails", async () => {
    const factory = new IDBFactory();
    const previous = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: factory });
    const clock = createClock();
    const chain = createChainFixture();
    const relay = createRelay(clock, {
      bootstrap: {
        resolve: async () => ({
          application: { applicationId: "app-a", applicationName: "OAAth Example" },
          context: workspaceContext,
          account: accountProfile,
          ownerValidator: VALIDATOR,
          chainIds: [chain.capability.chainId],
        }),
      },
      chains: [relayChainPort(chain)],
    });
    const oaath = createOAAth({
      approvals: {
        kind: "service",
        url: ISSUER_URL,
        fetch: (request: Request) => {
          const headers = new Headers(request.headers);
          headers.set("authorization", `Bearer ${CLIENT_TOKEN}`);
          return relay(new Request(request, { headers }));
        },
      },
      origin: ORIGIN,
      now: clock.now,
    });
    try {
      await oaath.connect();
      const failingGrant = {
        async revoke() {
          throw new Error("canonical revocation failure");
        },
      } as unknown as Parameters<typeof oaath.disconnect>[0];
      await expect(oaath.disconnect(failingGrant)).rejects.toMatchObject({
        name: "OaathCleanupError",
      });
      const deletion = await new Promise<"blocked" | "deleted">((resolve, reject) => {
        const request = factory.deleteDatabase(OAATH_INDEXEDDB_NAME);
        request.onblocked = () => resolve("blocked");
        request.onsuccess = () => resolve("deleted");
        request.onerror = () => reject(request.error ?? new Error("database deletion failed"));
      });
      expect(deletion).toBe("blocked");
    } finally {
      await oaath.close().catch(() => undefined);
      if (previous === undefined) Reflect.deleteProperty(globalThis, "indexedDB");
      else Object.defineProperty(globalThis, "indexedDB", previous);
    }
  });

  it("waits for an in-progress URL composition before closing its database", async () => {
    const factory = new IDBFactory();
    const previous = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: factory });
    let releaseBootstrap!: () => void;
    const bootstrapReleased = new Promise<void>((resolve) => {
      releaseBootstrap = resolve;
    });
    const oaath = createOAAth({
      origin: ORIGIN,
      now: () => 1_800_000_000,
      approvals: {
        kind: "service",
        url: ISSUER_URL,
        fetch: async () => {
          await bootstrapReleased;
          return new Response("{}", {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        },
      },
    });
    try {
      const connecting = oaath.connect();
      const closing = oaath.close();
      releaseBootstrap();
      await expect(connecting).rejects.toMatchObject({ name: "OaathClientError" });
      await closing;
      await expect(oaath.connect()).rejects.toMatchObject({ code: "oaath_client_closed" });
      const deletion = await new Promise<"blocked" | "deleted">((resolve, reject) => {
        const request = factory.deleteDatabase(OAATH_INDEXEDDB_NAME);
        request.onblocked = () => resolve("blocked");
        request.onsuccess = () => resolve("deleted");
        request.onerror = () => reject(request.error ?? new Error("database deletion failed"));
      });
      expect(deletion).toBe("deleted");
    } finally {
      await oaath.close().catch(() => undefined);
      if (previous === undefined) Reflect.deleteProperty(globalThis, "indexedDB");
      else Object.defineProperty(globalThis, "indexedDB", previous);
    }
  });

  it("drains a successful URL connect and rejects every connect after close", async () => {
    const source = createUrlRealm();
    let enterBootstrap!: () => void;
    let releaseBootstrap!: () => void;
    const bootstrapEntered = new Promise<void>((resolve) => {
      enterBootstrap = resolve;
    });
    const bootstrapReleased = new Promise<void>((resolve) => {
      releaseBootstrap = resolve;
    });
    const realm = createUrlRealm({
      clock: source.clock,
      chain: source.chain,
      stores: createMemoryStores(),
      relay: async (request) => {
        if (request.method === "GET" && new URL(request.url).pathname === "/bootstrap") {
          enterBootstrap();
          await bootstrapReleased;
        }
        return source.relay(request);
      },
    });

    const connecting = realm.oaath.connect();
    await bootstrapEntered;
    let closeSettled = false;
    const closing = realm.oaath.close().then(() => {
      closeSettled = true;
    });
    await Promise.resolve();
    expect(closeSettled).toBe(false);
    releaseBootstrap();
    const connection = await connecting;
    await closing;
    await expect(connection.resume()).rejects.toMatchObject({ code: "oaath_client_closed" });
    await expect(realm.oaath.connect()).rejects.toMatchObject({ code: "oaath_client_closed" });
  });

  it("fails closed on hostile or mismatched service context", async () => {
    for (const tamper of [
      (document: Record<string, unknown>) => ({ ...document, extra: 1 }),
      (document: Record<string, unknown>) => ({
        ...document,
        version: "oaath.service-bootstrap/v1",
      }),
      (document: Record<string, unknown>) => ({ ...document, chains: [] }),
      // A redirect target on another origin never binds this page.
      (document: Record<string, unknown>) => ({
        ...document,
        application: {
          ...(document.application as Record<string, unknown>),
          redirectUris: ["https://other.example/callback"],
        },
      }),
    ]) {
      const realm = createUrlRealm({ bootstrap: tamper });
      await expect(realm.oaath.connect()).rejects.toMatchObject({
        name: "OaathClientError",
        code: "oaath_client_capability_invalid",
      });
    }
  });

  it("runs hosted session custody end to end: the page never holds session key material", async () => {
    const realm = createUrlRealm({
      session: { custody: "oaath-hosted" },
      sessionSigner: {
        mode: "oaath_hosted",
        providerId: "kms-primary",
        provider: createKmsSessionSignerProvider({ kms: relayKms() }),
      },
    });
    const connection = await realm.oaath.connect();
    // The operator credential is the one the deployment's provider served —
    // never a locally minted key.
    expect(realm.oaath.binding.operatorCredential.kind).toBe("ecdsa");
    expect(realm.fetched).toContain("POST /session-signers");

    const grant = await connection.requestPermission(permissionInput());
    expect(grant.state).toBe("active");

    // The execution signature came from the service's signing route; the
    // profile's self-verification proved it matches the served credential —
    // the rotation invariant, enforced per signature.
    const operation = await grant.sendCalls(sendCallsInput());
    expect((await operation.wait()).status).toBe("finalized");
    expect(
      realm.fetched.filter((entry) => entry === "POST /session-signers/signatures").length,
    ).toBeGreaterThan(0);
    await connection.close();
  });

  it("fails closed when the declared custody differs from the session custody requirement", async () => {
    const hosted = createUrlRealm({
      session: { custody: "browser" },
      sessionSigner: {
        mode: "oaath_hosted",
        providerId: "kms-primary",
        provider: createKmsSessionSignerProvider({ kms: relayKms() }),
      },
    });
    await expect(hosted.oaath.connect()).rejects.toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_capability_unsupported",
      source: "session_custody_unsupported",
    });
    const browser = createUrlRealm({ session: { custody: "application-backend" } });
    await expect(browser.oaath.connect()).rejects.toMatchObject({
      code: "oaath_client_capability_unsupported",
      source: "session_custody_unsupported",
    });
    // The server's declaration is never overridden: nothing past the
    // bootstrap is requested, so no session key or signer route exists.
    expect(hosted.fetched).toEqual(["GET /bootstrap"]);
    expect(browser.fetched).toEqual(["GET /bootstrap"]);
    const matching = createUrlRealm({ session: { kind: "ecdsa", custody: "browser" } });
    const connection = await matching.oaath.connect();
    expect(matching.oaath.binding.operatorCredential.kind).toBe("ecdsa");
    await connection.close();
  });

  it("fails closed on custody the service declares but cannot or should not serve", async () => {
    // Declared remote custody with no signing routes composes nothing — the
    // SDK never substitutes a locally minted frontend key.
    const unserved = createUrlRealm({
      bootstrap: (document) => ({
        ...document,
        sessionSigner: { mode: "oaath_hosted", providerId: "kms-primary" },
      }),
    });
    await expect(unserved.oaath.connect()).rejects.toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_issuer_rejected",
    });
    // An unknown custody mode rejects the whole bootstrap document.
    const unknown = createUrlRealm({
      bootstrap: (document) => ({
        ...document,
        sessionSigner: { mode: "owner_hosted", providerId: "kms-primary" },
      }),
    });
    await expect(unknown.oaath.connect()).rejects.toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_capability_invalid",
    });
    // An explicit frontend declaration composes exactly like absence.
    const frontend = createUrlRealm({
      bootstrap: (document) => ({
        ...document,
        sessionSigner: { mode: "frontend", providerId: null },
      }),
    });
    const connection = await frontend.oaath.connect();
    expect(frontend.oaath.binding.operatorCredential.kind).toBe("ecdsa");
    await connection.close();
  });

  it("refuses a chain the service does not advertise", async () => {
    const realm = createUrlRealm();
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    await expect(
      grant.sendCalls({ ...(sendCallsInput() as Record<string, unknown>), chain: 999 }),
    ).rejects.toMatchObject({
      code: "oaath_client_capability_unsupported",
      source: "chain_not_configured",
    });
    expect(realm.chain.sends).toHaveLength(0);
    await connection.close();
  });

  it("refuses unknown and service-selected fields on service approvals", () => {
    for (const configuration of [
      { url: "https://oaath.example" },
      { approvals: { kind: "service", url: "https://oaath.example", relayUrl: "x" } },
      { approvals: { kind: "service" }, relayUrl: "x" },
      { approvals: { kind: "service" }, chains: [] },
      { approvals: { kind: "service" }, account: `0x${"11".repeat(20)}` },
      { approvals: { kind: "phone" } },
    ]) {
      expect(() => createOAAth(configuration as never)).toThrowError(
        expect.objectContaining({ code: "oaath_client_input_invalid" }),
      );
    }
  });

  it("denies execution when the service serves no usage evidence", async () => {
    const realm = createUrlRealm({ chain: createChainFixture({ usage: false }) });
    const connection = await realm.oaath.connect();
    const grant = await connection.requestPermission(permissionInput());
    await expect(grant.sendCalls(sendCallsInput())).rejects.toMatchObject({
      code: "oaath_client_scope_denied",
      source: "session_coverage_unreadable",
    });
    await connection.close();
  });
});
