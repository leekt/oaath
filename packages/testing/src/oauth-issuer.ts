/**
 * A loopback OAAth issuer for local tests: OAuth client registration, PAR,
 * an `/authorize` page that approves at once, the token exchange, and JWKS.
 *
 * It composes each `oaath_grant` permission request the way the relay does,
 * and the account root signs it with the SDK's own offline
 * `prepareDerivedAccountPermissionApproval`, as the portal does. It is never
 * an authorization service: every request it sees is approved by the one root.
 */
import { createServer, type Server } from "node:http";
import type { OwnerCredentialProfile } from "@oaath/protocol";
import { type KeyProfile, prepareDerivedAccountPermissionApproval } from "@oaath/sdk/kernel";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

export interface LocalOAuthIssuer {
  /** `http://127.0.0.1:{port}`, the issuer and the `iss` of every response. */
  readonly url: string;
  /** Authorizations approved so far. */
  readonly approvalCount: number;
  readonly close: () => Promise<void>;
}

export interface LocalOAuthIssuerInput {
  /** The chain the permission packages derive from; the approval covers every chain. */
  readonly chainId: number;
  /** The root's factory-derived (index 0) Kernel account address, lowercase. */
  readonly account: `0x${string}`;
  readonly root: Readonly<{ credential: OwnerCredentialProfile; key: Readonly<KeyProfile> }>;
}

type Par = Readonly<{ clientId: string; form: URLSearchParams; createdAt: number }>;

export async function createLocalOAuthIssuer(
  input: LocalOAuthIssuerInput,
): Promise<Readonly<LocalOAuthIssuer>> {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwks = { keys: [{ ...(await exportJWK(publicKey)), kid: "local", alg: "ES256" }] };
  const accountProfile = {
    version: "oaath.kernel-account-profile/v1",
    kind: "kernel",
    accountIndex: "0",
    kernelVersion: "0.4.0",
    factoryRoute: "kernel_factory",
    entryPoint: { version: "0.9" },
    ownerCredential: input.root.credential,
  };
  const clients = new Map<string, readonly string[]>();
  const pars = new Map<string, Par>();
  const codes = new Map<string, Record<string, unknown>>();
  let approvals = 0;
  let url = "";

  /** The relay's composition of one `oaath_grant` detail, then the root's signature. */
  async function approve(parId: string, par: Par) {
    const [detail] = JSON.parse(par.form.get("authorization_details") ?? "[]");
    const redirectUri = par.form.get("redirect_uri") ?? "";
    const requestedAt = Math.floor(par.createdAt / 1000);
    const request = {
      version: "oaath.permission-request/v1",
      requestId: parId,
      context: {
        version: "oaath.workspace-account-context/v1",
        workspaceId: input.account,
        workspaceKind: "personal",
        accountId: input.account,
      },
      application: {
        applicationId: par.clientId,
        clientId: par.clientId,
        origin: new URL(redirectUri).origin,
        deviceId: detail.device_id,
      },
      chainScope: "all",
      logicalAccount: accountProfile,
      operatorCredential: detail.signer,
      policy: detail.policy,
      requestedAt,
      expiresAt: detail.expires_at,
      sessionSigner: null,
    };
    const { installApproval, ...decision } = await prepareDerivedAccountPermissionApproval({
      request: request as never,
      chainId: input.chainId,
      account: input.account,
    }).sign(input.root.key, requestedAt);
    const idToken = await new SignJWT({
      nonce: par.form.get("nonce"),
      verified: true,
      oaath_account: accountProfile,
      oaath_accounts: [{ address: input.account, role: "root", status: "active" }],
      signer: {
        id: "local-root",
        kind: input.root.credential.kind,
        profile: input.root.credential,
      },
    })
      .setProtectedHeader({ alg: "ES256", kid: "local" })
      .setIssuer(url)
      .setAudience(par.clientId)
      .setSubject(input.account)
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(privateKey);
    approvals += 1;
    return {
      id_token: idToken,
      access_token: `local-${parId}`,
      token_type: "Bearer",
      expires_in: 600,
      scope: "openid",
      authorization_details: [
        {
          type: "oaath_grant",
          grant_id: parId,
          permission_request: request,
          decision,
          enable: installApproval,
        },
      ],
    };
  }

  const server: Server = createServer(async (incoming, outgoing) => {
    const json = (status: number, body: unknown) => {
      outgoing.writeHead(status, {
        "content-type": "application/json",
        "access-control-allow-origin": "*",
        "cache-control": "no-store",
      });
      outgoing.end(JSON.stringify(body));
    };
    try {
      const requestUrl = new URL(incoming.url ?? "/", url);
      if (incoming.method === "OPTIONS") {
        outgoing.writeHead(204, {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET, POST",
          "access-control-allow-headers": "content-type",
        });
        outgoing.end();
        return;
      }
      let body = "";
      for await (const chunk of incoming) body += String(chunk);
      if (requestUrl.pathname === "/oauth/jwks") return json(200, jwks);
      if (requestUrl.pathname === "/oauth/clients" && incoming.method === "POST") {
        const { redirect_uris: redirects } = JSON.parse(body) as { redirect_uris: string[] };
        const clientId = `local-client-${clients.size + 1}`;
        clients.set(clientId, redirects);
        return json(201, { client_id: clientId, redirect_uris: redirects });
      }
      if (requestUrl.pathname === "/oauth/par" && incoming.method === "POST") {
        const form = new URLSearchParams(body);
        const clientId = form.get("client_id") ?? "";
        if (!clients.get(clientId)?.includes(form.get("redirect_uri") ?? ""))
          return json(400, { error: "invalid_request" });
        const id = `par-${pars.size + 1}`;
        pars.set(id, { clientId, form, createdAt: Date.now() });
        return json(201, {
          request_uri: `urn:ietf:params:oauth:request_uri:${id}`,
          expires_in: 300,
        });
      }
      if (requestUrl.pathname === "/authorize") {
        const id = requestUrl.searchParams.get("request_uri")?.split(":").pop() ?? "";
        const par = pars.get(id);
        if (!par) return json(404, { error: "not_found" });
        const code = `code-${id}`;
        codes.set(code, await approve(id, par));
        const redirect = new URL(par.form.get("redirect_uri") ?? "");
        redirect.searchParams.set("code", code);
        redirect.searchParams.set("state", par.form.get("state") ?? "");
        redirect.searchParams.set("iss", url);
        outgoing.writeHead(302, { location: redirect.toString() });
        outgoing.end();
        return;
      }
      if (requestUrl.pathname === "/oauth/token" && incoming.method === "POST") {
        const code = new URLSearchParams(body).get("code") ?? "";
        const token = codes.get(code);
        // A code redeems once.
        codes.delete(code);
        return token ? json(200, token) : json(400, { error: "invalid_grant" });
      }
      return json(404, { error: "not_found" });
    } catch {
      json(500, { error: "local_issuer_failed" });
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("local_issuer_unavailable");
  url = `http://127.0.0.1:${address.port}`;
  return Object.freeze({
    url,
    get approvalCount() {
      return approvals;
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  });
}
