/**
 * The extension's service worker: one URL-mode OAAth realm per page origin.
 *
 * Authority boundaries:
 * - URL mode never holds owner authority — pairing still routes the owner's
 *   review through the service's own authorization flow (the phone).
 * - One Grant per origin, in that origin's own IndexedDB database; nothing is
 *   shared across origins, so one dapp can never spend another's scope.
 * - The page's identity is `sender.origin` as Chrome reports it. Message
 *   contents never name an origin.
 *
 * @author taek <leekt216@gmail.com>
 */
import { createOAAth } from "@oaath/sdk";
import {
  createIndexedDbCleanupStore,
  createIndexedDbContextStore,
  createIndexedDbGrantStoreAdapter,
  createIndexedDbKeyStore,
  createIndexedDbOperationStoreAdapter,
  createIndexedDbWalletCallBundleStoreAdapter,
  openOaathDatabase,
} from "@oaath/sdk/persistence";
import { oaathProvider } from "@oaath/sdk/viem";

const DEFAULT_SETTINGS = Object.freeze({
  url: "http://127.0.0.1:8787",
  chain: 421_614,
});

/** origin -> { url, connection, grant, providers: Map<chain, provider> } */
const realms = new Map();

async function settings() {
  const stored = await chrome.storage.local.get(DEFAULT_SETTINGS);
  const url =
    typeof stored.url === "string" && stored.url.length > 0 ? stored.url : DEFAULT_SETTINGS.url;
  const chain =
    typeof stored.chain === "number" && Number.isSafeInteger(stored.chain) && stored.chain >= 1
      ? stored.chain
      : DEFAULT_SETTINGS.chain;
  return { url, chain };
}

async function realmFor(origin) {
  const configured = await settings();
  const cached = realms.get(origin);
  if (cached && cached.url === configured.url) {
    // The realm is service-bound; the chain is only a provider parameter, so
    // a saved chain change takes effect immediately (providers are keyed by
    // chain, so stale ones are simply never consulted again).
    cached.chain = configured.chain;
    return cached;
  }
  if (cached) await cached.connection.close().catch(() => undefined);
  const database = await openOaathDatabase({
    factory: indexedDB,
    // One database per (service, origin): a service change starts fresh
    // rather than resuming authority issued by another service.
    name: `oaath-extension:${configured.url}:${origin}`,
  });
  const oaath = createOAAth({
    url: configured.url,
    origin,
    stores: {
      grants: createIndexedDbGrantStoreAdapter(database),
      operations: createIndexedDbOperationStoreAdapter(database),
      walletCallBundles: createIndexedDbWalletCallBundleStoreAdapter(database),
      keys: createIndexedDbKeyStore(database),
      cleanup: createIndexedDbCleanupStore(database),
      context: createIndexedDbContextStore(database),
    },
  });
  const connection = await oaath.connect();
  const realm = {
    url: configured.url,
    chain: configured.chain,
    connection,
    grant: null,
    providers: new Map(),
  };
  realms.set(origin, realm);
  return realm;
}

async function activeGrant(realm) {
  if (realm.grant && realm.grant.state === "active") return realm.grant;
  realm.grant = await realm.connection.resume();
  realm.providers.clear();
  return realm.grant && realm.grant.state === "active" ? realm.grant : null;
}

function providerFor(realm, grant) {
  const cached = realm.providers.get(realm.chain);
  if (cached) return cached;
  const provider = oaathProvider({ grant, chain: realm.chain });
  realm.providers.set(realm.chain, provider);
  return provider;
}

function rpcError(code, message) {
  return { ok: false, error: { code, message } };
}

/** One dapp request, bound to the sender's origin. */
async function handleProvider(origin, method, params) {
  const realm = await realmFor(origin);
  const grant = await activeGrant(realm);
  if (grant === null) {
    // Without a Grant the provider is discoverable but unauthorized: identity
    // reads answer emptily, everything effectful asks for pairing.
    if (method === "eth_chainId") return { ok: true, result: `0x${realm.chain.toString(16)}` };
    if (method === "eth_accounts") return { ok: true, result: [] };
    return rpcError(4100, "no OAAth Grant for this origin; open the OAAth popup to pair");
  }
  try {
    const result = await providerFor(realm, grant).request({ method, params });
    return { ok: true, result };
  } catch (error) {
    return rpcError(
      typeof error?.code === "number" ? error.code : -32603,
      error instanceof Error ? error.message : "OAAth request failed",
    );
  }
}

/** Popup commands; the popup names the tab origin it inspected itself. */
async function handlePopup(message) {
  const origin = message.origin;
  if (typeof origin !== "string" || !/^https?:\/\//u.test(origin)) {
    return rpcError(-32602, "popup command requires the page origin");
  }
  if (message.command === "status") {
    const realm = await realmFor(origin);
    const grant = await activeGrant(realm);
    return {
      ok: true,
      result: {
        origin,
        url: realm.url,
        chain: realm.chain,
        state: grant?.state ?? "unpaired",
        account: grant ? await grant.account(realm.chain) : null,
        expiresAt: grant?.expiresAt ?? null,
      },
    };
  }
  if (message.command === "pair") {
    const scope = message.scope;
    if (!scope || typeof scope !== "object") return rpcError(-32602, "pair requires a scope");
    const realm = await realmFor(origin);
    // The owner still reviews and approves through the service's own flow;
    // this only submits the request and waits for the decision.
    const grant = await realm.connection.requestPermission({
      chainScope: "all",
      permissions: [
        {
          calls: [
            {
              target: String(scope.target),
              selectors: [String(scope.selector)],
              valueLimit: String(scope.valueLimit ?? "0"),
            },
          ],
        },
      ],
      expiresIn: Number(scope.expiresIn ?? 1_800),
      perChainOperationLimit: Number(scope.perChainOperationLimit ?? 10),
    });
    realm.grant = grant;
    realm.providers.clear();
    return { ok: true, result: { state: grant.state, account: await grant.account(realm.chain) } };
  }
  if (message.command === "revoke") {
    const realm = await realmFor(origin);
    const grant = await activeGrant(realm);
    if (grant === null) return rpcError(-32000, "nothing to revoke for this origin");
    await grant.revoke();
    realm.grant = null;
    realm.providers.clear();
    return { ok: true, result: { state: grant.state } };
  }
  return rpcError(-32601, "unknown popup command");
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const respond = (value) => {
    try {
      sendResponse(value);
    } catch {
      // The page or popup went away; nothing to answer.
    }
  };
  (async () => {
    if (!message || typeof message !== "object") return rpcError(-32600, "invalid message");
    if (message.type === "provider") {
      // The browser, not the message, names the page. A content script's
      // sender always carries its page origin.
      const origin = sender.origin;
      if (typeof origin !== "string" || !/^https?:\/\//u.test(origin)) {
        return rpcError(4100, "requests must come from a web page");
      }
      if (typeof message.method !== "string") return rpcError(-32602, "method is required");
      return handleProvider(
        origin,
        message.method,
        Array.isArray(message.params) ? message.params : [],
      );
    }
    if (message.type === "popup") {
      // Only the extension's own pages reach this branch.
      if (sender.origin !== `chrome-extension://${chrome.runtime.id}`) {
        return rpcError(4100, "popup commands must come from the extension");
      }
      return handlePopup(message);
    }
    return rpcError(-32601, "unknown message type");
  })().then(respond, (error) =>
    respond(
      rpcError(
        typeof error?.code === "number" ? error.code : -32603,
        error instanceof Error ? error.message : "OAAth worker failed",
      ),
    ),
  );
  return true;
});
