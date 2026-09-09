/**
 * Phone demo deployment: pairing and optional notifications around the shared relay.
 * The SDK owns every application key, operation, observation and recovery.
 * @author taek <leekt216@gmail.com>
 */
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { connect } from "node:http2";
import { networkInterfaces } from "node:os";
import { fileURLToPath } from "node:url";
import {
  OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
} from "@oaath/protocol";
import {
  createKernelRuntime,
  KERNEL_V4_ENTRY_POINT_V07,
  kernelV4Deployment,
  ownerOperator,
  p256Key,
  parseKernelAllChainApproval,
  prepareKernelPhonePermissionApproval,
  prepareKernelPhoneRevocation,
} from "@oaath/sdk/kernel";
import { createMemoryOperationStoreAdapter } from "@oaath/sdk/testing";
import {
  createMemoryRelayStore,
  createMemoryServiceDirectoryStore,
  createRelayHandler,
  createServiceDirectory,
} from "@oaath/server";
import { createApnsSender, sendApnsNotification } from "@oaath/server/apns";
import { createOwnerPhoneRevocationExecutor } from "@oaath/server/kernel";
import {
  createMemoryOwnerDeviceCredentialStore,
  createOwnerDeviceAuthentication,
} from "@oaath/server/native";
import {
  createPostgresOperationStoreAdapter,
  createPostgresOwnerDeviceCredentialStore,
  createPostgresRelayStore,
  createPostgresServiceDirectoryStore,
} from "@oaath/server/postgres";
import { build } from "esbuild";
import QRCode from "qrcode";
import { OneShotPairing, servePairingSecret } from "./demo-routes.mjs";

const CLIENT_ID = "demo-web-app";
const SUBJECT = "demo-owner-subject";
const HERE = fileURLToPath(new URL(".", import.meta.url));
const sha256 = (text) => createHash("sha256").update(text).digest("base64url");
const sendJson = (outgoing, status, body) => {
  outgoing.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  outgoing.end(JSON.stringify(body));
};
const refuse = (outgoing, status, code) => sendJson(outgoing, status, { error: { code } });

function chainPort(capability) {
  return {
    chainId: capability.chainId,
    reads: (request) => capability.reads.read(request),
    observation: (request) => capability.observation.read(request),
    bundler: (request) => capability.bundler.probe(request),
    quote: (request) => capability.quote(request),
    async submission(request) {
      const session = await capability.submission.open(request);
      try {
        return await session.send();
      } finally {
        await session.close();
      }
    },
    usage: (request) => capability.usage(request),
    feePayer: capability.feePayer,
    staticPaymasterConfigurationHash: null,
  };
}

/** Borrows configured chain backends and an optional provisioned PostgreSQL pool. */
export async function startPhoneService({
  host = "127.0.0.1",
  port = 0,
  simulate = false,
  workspaceKind = "personal",
  chains,
  pool,
} = {}) {
  if (workspaceKind !== "personal" && workspaceKind !== "team")
    throw new Error("workspace_kind_invalid");
  if (!Array.isArray(chains) || chains.length === 0) throw new Error("chains_required");
  const chainIds = chains.map((chain) => chain.capability.chainId);
  const workspaceId = `${workspaceKind}-1`;
  const members = workspaceKind === "team" ? ["demo-member", "demo-teammate"] : ["demo-member"];
  const bundle = await build({
    entryPoints: [`${HERE}/browser.js`],
    bundle: true,
    format: "esm",
    platform: "browser",
    write: false,
    logLevel: "silent",
  });
  const page = readFileSync(`${HERE}/page.html`);
  const chainById = (chainId) => {
    const chain = chains.find((entry) => entry.capability.chainId === chainId);
    if (!chain) throw new Error("chain_not_configured");
    return chain;
  };
  const primary = chains[0];
  const store = pool ? createPostgresRelayStore({ pool }) : createMemoryRelayStore();
  const operations = pool
    ? createPostgresOperationStoreAdapter({ pool })
    : createMemoryOperationStoreAdapter();
  const closeStores = async () => {
    const results = await Promise.allSettled([operations.close(), store.close()]);
    const errors = results
      .filter((result) => result.status === "rejected")
      .map((result) => result.reason);
    if (errors.length) throw new AggregateError(errors, "phone store cleanup failed");
  };
  try {
    const directory = createServiceDirectory(
      pool ? createPostgresServiceDirectoryStore({ pool }) : createMemoryServiceDirectoryStore(),
    );
    const existing = await directory.read();
    if (existing === null)
      await directory.replace({
        expectedRevision: null,
        directory: {
          version: "oaath.service-directory/v1",
          applications: [
            {
              clientId: CLIENT_ID,
              applicationId: "phone-demo",
              applicationName: "OAAth Phone Demo",
            },
          ],
          workspaces: [{ workspaceId, kind: workspaceKind }],
          memberships: members.map((subject) => ({ workspaceId, clientId: CLIENT_ID, subject })),
          ownerDevices: [],
          accounts: [],
          selections: members.map((subject) => ({
            workspaceId,
            accountId: "account-1",
            clientId: CLIENT_ID,
            subject,
          })),
        },
      });
    const initialized = await directory.read();
    if (
      !initialized?.directory.workspaces.some(
        (workspace) => workspace.workspaceId === workspaceId && workspace.kind === workspaceKind,
      )
    )
      throw new Error("workspace_configuration_differs");
    const enrolledAccount = async () =>
      (await directory.read())?.directory.accounts.find(
        (account) => account.workspaceId === workspaceId && account.accountId === "account-1",
      );
    async function bindPhoneAccount(account) {
      const runtime = createKernelRuntime({
        deployment: kernelV4Deployment(primary.capability.chainId),
        operator: ownerOperator({
          key: p256Key({
            credential: account.ownerCredential,
            sign: async () => {
              throw new Error("phone_signature_required");
            },
          }),
        }),
        reads: primary.capability.reads,
      });
      return runtime.bindAccount({
        accountIndex: account.accountIndex,
        initialPackages: runtime.packages,
      });
    }
    const ownerAuthentication = createOwnerDeviceAuthentication({
      directory,
      store: pool
        ? createPostgresOwnerDeviceCredentialStore({ pool })
        : createMemoryOwnerDeviceCredentialStore(),
    });
    const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    const pairingCode = [...randomBytes(10)]
      .map((byte) => codeAlphabet[byte % codeAlphabet.length])
      .join("");
    const expiresAt = Date.now() + 600_000;
    const pairing = new OneShotPairing({ hash: sha256(pairingCode), expiresAt });
    let pushDestination = null;
    let url;
    let pairingLink;
    let allowedOrigins;
    const clock = { now: () => Date.now() };
    // REPLACE: illustrative encoding, not encryption or production key custody.
    const kms = {
      async encrypt(plaintext) {
        return `demo-not-encrypted:v1:${Buffer.from(plaintext).toString("base64")}`;
      },
      async decrypt(reference) {
        const prefix = "demo-not-encrypted:v1:";
        if (!reference.startsWith(prefix)) throw new Error("unknown_ciphertext");
        return Buffer.from(reference.slice(prefix.length), "base64").toString();
      },
    };
    // Only live resource ownership is cached. The SDK journal alone decides
    // whether a recreated worker can submit or must recover the exact operation.
    const workers = new Map();
    function scheduleRevocation(operationId) {
      if (workers.has(operationId)) return;
      const work = (async () => {
        const executor = await createOwnerPhoneRevocationExecutor({
          store,
          kms,
          clock,
          operationId,
          // Each executor borrows the example backend; only service.close destroys it.
          operations: { ...operations, close: async () => {} },
          observation: {
            read: (request) => chainById(request.chainId).capability.observation.read(request),
            close: async () => {},
          },
          submission: {
            close: async () => {},
            async openSubmission(prepared, signature) {
              const chain = chainById(prepared.chainId);
              const session = await chain.capability.submission.open({
                prepared,
                signature,
                route: "entrypoint-handleops",
                feePayer: chain.capability.feePayer,
              });
              return { submit: () => session.send(), close: () => session.close() };
            },
          },
        });
        try {
          await executor.start(10_000);
          await executor.observe(10_000);
        } finally {
          await executor.close();
        }
      })()
        .catch(() => console.error("phone revocation remains pending; check its chain evidence"))
        .finally(() => workers.delete(operationId));
      workers.set(operationId, work);
    }
    const relay = createRelayHandler({
      ownerRouting: directory,
      bootstrap: directory,
      chains: chains.map((chain) => chainPort(chain.capability)),
      store,
      authentication: {
        async authenticate(request) {
          const token = request.headers.get("authorization");
          const member =
            token === "Bearer demo-client-token"
              ? "demo-member"
              : token === "Bearer demo-teammate-token"
                ? "demo-teammate"
                : null;
          if (member) {
            return {
              role: "client",
              clientId: CLIENT_ID,
              subject: member,
              redirectUris: [`${url}/callback`],
            };
          }
          return ownerAuthentication.authenticate(request);
        },
      },
      kms,
      clock,
      revocations: {
        directory,
        async prepare({ request, artifact, chainId }) {
          const chain = chainById(chainId);
          const approval = parseKernelAllChainApproval(JSON.parse(artifact).installApproval);
          const quote = await chain.quoteRevocation(approval);
          return (
            await prepareKernelPhoneRevocation({
              request,
              approval,
              chainId,
              reads: chain.capability.reads,
              ...quote,
            })
          ).signingRequest;
        },
      },
      permissionApprovals: {
        async prepare(request) {
          const prepared = await prepareKernelPhonePermissionApproval({
            request,
            chainId: primary.capability.chainId,
            reads: primary.capability.reads,
          });
          return {
            signingRequest: prepared.signingRequest,
            complete: async (artifact, decidedAt) =>
              JSON.stringify(await prepared.complete(artifact, decidedAt)),
          };
        },
      },
    });

    async function pair(body, outgoing) {
      let value;
      try {
        value = JSON.parse(body.toString());
      } catch {
        return refuse(outgoing, 400, "pairing_request_invalid");
      }
      if (
        value === null ||
        typeof value !== "object" ||
        Array.isArray(value) ||
        Object.keys(value).sort().join(",") !== "deviceToken,pairingCode,publicKey" ||
        typeof value.pairingCode !== "string" ||
        typeof value.deviceToken !== "string" ||
        !/^[0-9a-fA-F]{64,200}$/.test(value.deviceToken) ||
        typeof value.publicKey !== "string" ||
        !/^0x[0-9a-f]{128}$/.test(value.publicKey)
      )
        return refuse(outgoing, 400, "pairing_request_invalid");
      if (await enrolledAccount()) return refuse(outgoing, 409, "phone_already_enrolled");
      const snapshot = await directory.read();
      try {
        pairing.reserve({
          hash: sha256(value.pairingCode.replace(/[\s-]/g, "").toUpperCase()),
          now: Date.now(),
        });
      } catch {
        return refuse(outgoing, 401, "pairing_invalid");
      }
      const credential = {
        version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
        kind: "p256",
        publicKey: `0x04${value.publicKey.slice(2)}`,
      };
      const account = {
        version: OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
        kind: "kernel",
        accountIndex: "0",
        kernelVersion: "0.4.0",
        factoryRoute: "kernel_factory",
        entryPoint: { version: "0.7" },
        ownerCredential: credential,
      };
      const descriptor = await bindPhoneAccount(account);
      const enrolled = await directory.enrollOwnerDevice({
        expectedRevision: snapshot.revision,
        device: { workspaceId, ownerDeviceId: "demo-owner-phone", subject: SUBJECT },
        accounts: [
          {
            workspaceId,
            accountId: "account-1",
            ownerDeviceId: "demo-owner-phone",
            account,
            ownerValidator: null,
            chainIds,
          },
        ],
      });
      if (!enrolled) return refuse(outgoing, 409, "phone_enrollment_conflict");
      // Local Anvil prefunding is a pairing effect, never part of pure consent preparation.
      for (const chain of chains) await chain.fund(descriptor.account);
      pushDestination = {
        credential: await ownerAuthentication.issue({
          workspaceId,
          ownerDeviceId: "demo-owner-phone",
        }),
        deviceToken: value.deviceToken.toLowerCase(),
      };
      sendJson(outgoing, 200, {
        version: "oaath.phone-pairing/v1",
        deviceCredential: pushDestination.credential,
        account: descriptor.account,
        chains: chainIds.map((chainId) => ({ chainId, entryPoint: KERNEL_V4_ENTRY_POINT_V07 })),
      });
    }

    async function maybePush(projection) {
      if (simulate || !pushDestination) return;
      const pem =
        process.env.APNS_KEY_PEM ??
        (process.env.APNS_KEY_PEM_PATH ? readFileSync(process.env.APNS_KEY_PEM_PATH, "utf8") : "");
      if (!pem || !process.env.APNS_KEY_ID || !process.env.APPLE_TEAM_ID || !process.env.APNS_TOPIC)
        return;
      const sender = createApnsSender({
        credentials: {
          privateKeyPem: pem,
          keyId: process.env.APNS_KEY_ID,
          teamId: process.env.APPLE_TEAM_ID,
          topic: process.env.APNS_TOPIC,
        },
        clock: { now: () => Date.now() },
      });
      const notification = sender.notification({
        deviceToken: pushDestination.deviceToken,
        projection,
      });
      const session = connect("https://api.sandbox.push.apple.com:443");
      try {
        await sendApnsNotification({ session, notification, timeoutMs: 10_000 });
      } finally {
        session.close();
      }
    }

    async function notifyOwner(operationId) {
      if (simulate || !pushDestination) return;
      const response = await relay(
        new Request(`${url}/native/projections/${operationId}`, {
          headers: { authorization: `Bearer ${pushDestination.credential}` },
        }),
      );
      if (!response.ok) return;
      const projection = await response.json();
      const summary = {
        operationId: projection.operationId,
        displayPayload: projection.displayPayload,
        expiresAt: projection.expiresAt,
      };
      await maybePush(summary);
    }

    const server = createServer(async (incoming, outgoing) => {
      try {
        const parsed = new URL(incoming.url ?? "/", url);
        const { pathname } = parsed;
        if (incoming.method === "GET" && (pathname === "/" || pathname === "/demo.js")) {
          outgoing.writeHead(200, {
            "content-type": pathname === "/" ? "text/html" : "text/javascript",
            "cache-control": "no-store",
          });
          outgoing.end(pathname === "/" ? page : bundle.outputFiles[0].contents);
          return;
        }
        if (
          await servePairingSecret({
            incoming,
            outgoing,
            pathname,
            allowedOrigins,
            pairingAvailable: async () =>
              !(await enrolledAccount()) && pairing.available(Date.now()),
            pairingLink,
            expiresAt,
            renderQr: (link) => QRCode.toDataURL(link),
          })
        )
          return;
        if (incoming.method === "GET" && pathname === "/demo/account") {
          const enrolled = await enrolledAccount();
          if (!enrolled) return refuse(outgoing, 409, "phone_not_paired");
          const descriptor = await bindPhoneAccount(enrolled.account);
          return sendJson(outgoing, 200, {
            account: descriptor.account,
            chains: chainIds.map((chainId) => ({ chainId, name: `Local Anvil ${chainId}` })),
          });
        }
        const chunks = [];
        for await (const chunk of incoming) chunks.push(chunk);
        const body = Buffer.concat(chunks);
        if (incoming.method === "POST" && pathname === "/native/pairings")
          return await pair(body, outgoing);
        const response = await relay(
          new Request(parsed, {
            method: incoming.method,
            headers: Object.fromEntries(
              Object.entries(incoming.headers).map(([key, value]) => [key, String(value)]),
            ),
            ...(body.length ? { body } : {}),
          }),
        );
        if (incoming.method === "POST" && response.ok) {
          if (pathname === "/authorization/requests" && response.status === 201) {
            const { requestId } = await response.clone().json();
            // Push is secondary; the relay records already own the pull inbox.
            void notifyOwner(requestId).catch(() =>
              console.error("phone notification unavailable"),
            );
          } else if (/^\/grants\/[^/]+\/revocations\/[0-9]+$/.test(pathname)) {
            const status = await response.clone().json();
            if (status.status === "pending" && response.status === 201)
              void notifyOwner(status.operationId).catch(() =>
                console.error("phone notification unavailable"),
              );
            else if (status.status === "approved") scheduleRevocation(status.operationId);
          } else if (pathname.startsWith("/native/revocation-decisions/")) {
            const decision = await response.clone().json();
            const operationId = pathname.slice("/native/revocation-decisions/".length);
            if (decision.outcome === "approved") scheduleRevocation(operationId);
          }
        }
        outgoing.writeHead(response.status, Object.fromEntries(response.headers));
        outgoing.end(Buffer.from(await response.arrayBuffer()));
      } catch {
        refuse(outgoing, 500, "demo_request_failed");
      }
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, resolve);
    });
    const actualPort = server.address().port;
    url = `http://127.0.0.1:${actualPort}`;
    const lan = Object.values(networkInterfaces())
      .flat()
      .find((entry) => entry?.family === "IPv4" && !entry.internal)?.address;
    const relayUrl = `http://${simulate ? "127.0.0.1" : (lan ?? "127.0.0.1")}:${actualPort}`;
    pairingLink = `oaath-demo://pair?relay=${encodeURIComponent(relayUrl)}&code=${pairingCode}`;
    allowedOrigins = new Set([url, `http://localhost:${actualPort}`]);
    return {
      url,
      pairingCode,
      chains,
      // Embedding/teardown can await current tasks without starting more work.
      settle: () => Promise.all(workers.values()),
      target: `0x${"71".repeat(20)}`,
      async close() {
        const errors = [];
        try {
          server.closeAllConnections();
          await new Promise((resolve, reject) =>
            server.close((error) => (error ? reject(error) : resolve())),
          );
        } catch (error) {
          errors.push(error);
        }
        try {
          await Promise.all(workers.values());
        } catch (error) {
          errors.push(error);
        }
        try {
          await closeStores();
        } catch (error) {
          errors.push(error);
        }
        if (errors.length) throw new AggregateError(errors, "phone service cleanup failed");
      },
    };
  } catch (error) {
    try {
      await closeStores();
    } catch (cleanup) {
      throw new AggregateError([error, cleanup], "phone service startup failed", { cause: error });
    }
    throw error;
  }
}
