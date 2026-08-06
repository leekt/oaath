/**
 * The URL-only golden path: one service URL, everything else authenticated
 * service context or locally derived.
 *
 * @author taek <leekt216@gmail.com>
 */
import { describe, expect, it } from "vitest";
import { createOAAth } from "../src/index.js";
import {
  CHAIN_ID,
  createChainFixture,
  createUrlRealm,
  permissionInput,
  sendCallsInput,
} from "./support/browser.js";

describe("URL-only golden path", () => {
  it("connects, requests permission, sends calls, and revokes from one URL", async () => {
    const realm = createUrlRealm();
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

    await grant.revoke();
    // The capability died through the service, but the installed chain
    // permission awaits owner-signed removal: durably revoking, never a
    // claimed revocation no chain observed.
    expect(grant.state).toBe("revoking");
    expect(realm.invalidations()).toBe(1);
    await connection.close();
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
      fetch: async (request: Request) => {
        seen.push(request.url);
        return new Response("{}", { status: 200 });
      },
      origin: "https://app.example",
      now: () => 1_800_000_000,
    });
    await expect(oaath.connect()).rejects.toMatchObject({ name: "OaathClientError" });
    expect(seen).toEqual(["http://localhost:8787/bootstrap"]);
  });

  it("fails closed on hostile or mismatched service context", async () => {
    for (const tamper of [
      (document: Record<string, unknown>) => ({ ...document, extra: 1 }),
      (document: Record<string, unknown>) => ({
        ...document,
        version: "oaath.service-bootstrap/v2",
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

  it("refuses an unknown configuration key on the URL mode", () => {
    expect(() => createOAAth({ url: "https://oaath.example", relayUrl: "x" })).toThrowError(
      expect.objectContaining({ code: "oaath_client_input_invalid" }),
    );
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
