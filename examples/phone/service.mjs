/**
 * Phone demo deployment: pairing and inbox transport around the shared relay.
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
  kernelV4Deployment,
  ownerOperator,
  p256Key,
  prepareKernelPhonePermissionApproval,
} from "@oaath/sdk/kernel";
import {
  createMemoryRelayStore,
  createMemoryServiceDirectoryStore,
  createRelayHandler,
  createServiceDirectory,
} from "@oaath/server";
import { createApnsSender, sendApnsNotification } from "@oaath/server/apns";
import { build } from "esbuild";
import QRCode from "qrcode";
import { createAnvilChain } from "../browser/anvil-chain.mjs";
import {
  markInboxTerminal,
  OneShotPairing,
  serveDemoInbox,
  servePairingSecret,
} from "./demo-routes.mjs";

const CHAIN_ID = 421_614;
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

/** In-memory example; restarting recreates both the directory and local chain. */
export async function startPhoneService({ host = "127.0.0.1", port = 0, simulate = false } = {}) {
  const bundle = await build({
    entryPoints: [`${HERE}/browser.js`],
    bundle: true,
    format: "esm",
    platform: "browser",
    write: false,
    logLevel: "silent",
  });
  const page = readFileSync(`${HERE}/page.html`);
  const chain = await createAnvilChain(CHAIN_ID, { p256: true });
  const directory = createServiceDirectory(createMemoryServiceDirectoryStore());
  await directory.replace({
    expectedRevision: null,
    directory: {
      version: "oaath.service-directory/v1",
      applications: [
        { clientId: CLIENT_ID, applicationId: "phone-demo", applicationName: "OAAth Phone Demo" },
      ],
      workspaces: [{ workspaceId: "personal-1", kind: "personal" }],
      memberships: [{ workspaceId: "personal-1", clientId: CLIENT_ID, subject: "demo-member" }],
      ownerDevices: [],
      accounts: [],
      selections: [
        {
          workspaceId: "personal-1",
          accountId: "account-1",
          clientId: CLIENT_ID,
          subject: "demo-member",
        },
      ],
    },
  });
  const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  const pairingCode = [...randomBytes(10)]
    .map((byte) => codeAlphabet[byte % codeAlphabet.length])
    .join("");
  const expiresAt = Date.now() + 600_000;
  const pairing = new OneShotPairing({ hash: sha256(pairingCode), expiresAt });
  const inbox = new Map();
  let activeDevice = null;
  let url;
  let pairingLink;
  let allowedOrigins;
  const relay = createRelayHandler({
    ownerRouting: directory,
    bootstrap: directory,
    chains: [chainPort(chain.capability)],
    store: createMemoryRelayStore(),
    authentication: {
      async authenticate(request) {
        const token = request.headers.get("authorization");
        if (token === "Bearer demo-client-token") {
          return {
            role: "client",
            clientId: CLIENT_ID,
            subject: "demo-member",
            redirectUris: [`${url}/callback`],
          };
        }
        if (activeDevice && token === `Bearer ${activeDevice.credential}`) {
          return {
            role: "owner",
            clientId: "demo-owner-phone",
            subject: SUBJECT,
            redirectUris: [],
          };
        }
        return null;
      },
    },
    // REPLACE: illustrative encoding, not encryption or production key custody.
    kms: {
      async encrypt(plaintext) {
        return `demo-not-encrypted:v1:${Buffer.from(plaintext).toString("base64")}`;
      },
      async decrypt(reference) {
        const prefix = "demo-not-encrypted:v1:";
        if (!reference.startsWith(prefix)) throw new Error("unknown_ciphertext");
        return Buffer.from(reference.slice(prefix.length), "base64").toString();
      },
    },
    clock: { now: () => Date.now() },
    permissionApprovals: {
      async prepare(request) {
        const prepared = await prepareKernelPhonePermissionApproval({
          request,
          chainId: CHAIN_ID,
          reads: chain.capability.reads,
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
    const runtime = createKernelRuntime({
      deployment: kernelV4Deployment(CHAIN_ID),
      operator: ownerOperator({
        key: p256Key({
          credential,
          sign: async () => {
            throw new Error("phone_signature_required");
          },
        }),
      }),
      reads: chain.capability.reads,
    });
    const descriptor = await runtime.bindAccount({
      accountIndex: "0",
      initialPackages: runtime.packages,
    });
    const enrolled = await directory.enrollOwnerDevice({
      expectedRevision: 1,
      device: { workspaceId: "personal-1", ownerDeviceId: "demo-owner-phone", subject: SUBJECT },
      accounts: [
        {
          workspaceId: "personal-1",
          accountId: "account-1",
          ownerDeviceId: "demo-owner-phone",
          account: {
            version: OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
            kind: "kernel",
            accountIndex: "0",
            kernelVersion: "0.4.0",
            factoryRoute: "kernel_factory",
            entryPoint: { version: "0.7" },
            ownerCredential: credential,
          },
          ownerValidator: null,
          chainIds: [CHAIN_ID],
        },
      ],
    });
    if (!enrolled) return refuse(outgoing, 409, "phone_enrollment_conflict");
    activeDevice = {
      credential: randomBytes(32).toString("base64url"),
      deviceToken: value.deviceToken.toLowerCase(),
      account: descriptor.account,
    };
    sendJson(outgoing, 200, {
      deviceCredential: activeDevice.credential,
      account: descriptor.account,
    });
  }

  async function maybePush(projection) {
    if (simulate || !activeDevice) return;
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
    const notification = sender.notification({ deviceToken: activeDevice.deviceToken, projection });
    const session = connect("https://api.sandbox.push.apple.com:443");
    try {
      await sendApnsNotification({ session, notification, timeoutMs: 10_000 });
    } finally {
      session.close();
    }
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
        serveDemoInbox({
          incoming,
          outgoing,
          pathname,
          activeDevice,
          records: inbox,
          now: Date.now,
        })
      )
        return;
      if (
        await servePairingSecret({
          incoming,
          outgoing,
          pathname,
          allowedOrigins,
          pairingAvailable: () => pairing.available(Date.now()),
          pairingLink,
          expiresAt,
          renderQr: (link) => QRCode.toDataURL(link),
        })
      )
        return;
      if (incoming.method === "GET" && pathname === "/demo/account") {
        if (!activeDevice) return refuse(outgoing, 409, "phone_not_paired");
        return sendJson(outgoing, 200, { account: activeDevice.account });
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
      if (
        incoming.method === "POST" &&
        pathname === "/authorization/requests" &&
        response.status === 201
      ) {
        const { requestId } = await response.clone().json();
        const projected = await relay(
          new Request(`${url}/native/projections/${requestId}`, {
            headers: { authorization: `Bearer ${activeDevice.credential}` },
          }),
        );
        if (projected.ok) {
          const projection = await projected.json();
          const summary = {
            operationId: projection.operationId,
            displayPayload: projection.displayPayload,
            expiresAt: projection.expiresAt,
          };
          inbox.set(requestId, { inboxState: "pending", inboxSummary: summary });
          // Push is secondary; a failed push leaves the pull inbox available.
          void maybePush(summary).catch(() => console.error("phone notification unavailable"));
        }
      }
      if (incoming.method === "POST" && pathname.startsWith("/native/decisions/") && response.ok) {
        markInboxTerminal(inbox, pathname.slice("/native/decisions/".length));
      }
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      refuse(outgoing, 500, "demo_request_failed");
    }
  });
  try {
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
      chain,
      chainId: CHAIN_ID,
      target: `0x${"71".repeat(20)}`,
      async close() {
        server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
        await chain.stop();
      },
    };
  } catch (error) {
    await chain.stop();
    throw error;
  }
}
