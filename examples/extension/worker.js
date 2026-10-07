/**
 * The extension's service worker: one portal-approved OAAth realm per page origin.
 *
 * Authority boundaries:
 * - The extension never holds owner authority: pairing opens the issuer's portal
 *   (`chrome.identity.launchWebAuthFlow`), where the account's root reviews and
 *   signs the request.
 * - One Grant per origin, in that origin's own IndexedDB database; nothing is
 *   shared across origins, so one dapp can never spend another's scope.
 * - The page's identity is `sender.origin` as Chrome reports it. Message
 *   contents never name an origin.
 *
 * @author taek <leekt216@gmail.com>
 */
import { createOAAth } from "@oaath/sdk";
import { oaathProvider } from "@oaath/sdk/cetane";
import { showWalletCallStatus } from "./status-presentation.js";
import {
  confirmWalletCalls,
  decideWalletCallConfirmation,
  rejectClosedWalletCallConfirmation,
} from "./transaction-confirmation-presentation.js";

const DEFAULT_SETTINGS = Object.freeze({
  issuer: "https://oaath.taek.tech",
  chain: 421_614,
  rpcUrl: "https://sepolia-rollup.arbitrum.io/rpc",
  bundlerUrl: "",
});

/** origin -> { key, promise }: initialization and pairing are shared by first callers. */
const realms = new Map();

async function settings() {
  const stored = await chrome.storage.local.get(DEFAULT_SETTINGS);
  const text = (key) =>
    typeof stored[key] === "string" && stored[key].length > 0 ? stored[key] : DEFAULT_SETTINGS[key];
  const chain =
    typeof stored.chain === "number" && Number.isSafeInteger(stored.chain) && stored.chain >= 1
      ? stored.chain
      : DEFAULT_SETTINGS.chain;
  return {
    issuer: text("issuer"),
    chain,
    rpcUrl: text("rpcUrl"),
    bundlerUrl: text("bundlerUrl"),
  };
}

/** The issuer client for this extension's redirect URI, registered once per issuer. */
async function clientFor(issuer, redirectUri) {
  const key = `client:${issuer}:${redirectUri}`;
  const stored = (await chrome.storage.local.get(key))[key];
  if (typeof stored === "string" && stored.length > 0) return stored;
  const response = await fetch(`${issuer}/oauth/clients`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "OAAth extension", redirect_uris: [redirectUri] }),
  });
  const body = await response.json().catch(() => null);
  if (!response.ok || typeof body?.client_id !== "string")
    throw new Error("the issuer refused to register this extension");
  await chrome.storage.local.set({ [key]: body.client_id });
  return body.client_id;
}

/** The portal opens in a browser-owned window; its redirect comes back here. */
function launch(url) {
  return chrome.identity.launchWebAuthFlow({ url, interactive: true }).then((redirect) => {
    if (typeof redirect !== "string") throw new Error("the sign-in was not finished");
    return redirect;
  });
}

async function realmFor(origin) {
  const configured = await settings();
  const key = JSON.stringify(configured);
  const cached = realms.get(origin);
  const entry =
    cached?.key === key
      ? cached
      : { key, promise: initializeRealm(origin, configured, cached?.promise) };
  realms.set(origin, entry);
  try {
    return await entry.promise;
  } catch (error) {
    if (realms.get(origin) === entry) realms.delete(origin);
    throw error;
  }
}

async function initializeRealm(origin, configured, previous) {
  if (previous) {
    const old = await previous.catch(() => null);
    if (old) await old.close().catch(() => undefined);
  }
  // A path keeps the redirect URI canonical: OAAth refuses a bare trailing slash.
  const redirectUri = chrome.identity.getRedirectURL("oaath");
  const clientId = await clientFor(configured.issuer, redirectUri);
  const oaath = createOAAth({
    chains: {
      [configured.chain]: {
        publicRpcUrls: [configured.rpcUrl],
        ...(configured.bundlerUrl ? { bundlerUrl: configured.bundlerUrl } : {}),
      },
    },
    approvals: { kind: "oauth", issuer: configured.issuer, clientId, redirectUri, launch },
    // The issuer binds the Grant to the redirect URI's origin: this extension.
    origin: new URL(redirectUri).origin,
    // One database per (issuer, page origin): an issuer change starts fresh
    // rather than resuming authority another issuer approved.
    stores: { kind: "indexeddb", name: `oaath-extension:${configured.issuer}:${origin}` },
  });
  try {
    const connection = await oaath.connect();
    return {
      origin,
      issuer: configured.issuer,
      chain: configured.chain,
      connection,
      // Closes the connection, then the realm's own database.
      close: () => oaath.close(),
      grant: null,
      pairing: false,
      providers: new Map(),
    };
  } catch (error) {
    await oaath.close().catch(() => undefined);
    throw error;
  }
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
  const provider = oaathProvider({
    grant,
    chain: realm.chain,
    confirmCalls: (confirmation) => confirmWalletCalls(chrome, realm.origin, confirmation),
    showCallsStatus: (status) => showWalletCallStatus(chrome, realm.origin, status),
  });
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
    // A revoking, revoked, or expired Grant authorizes nothing, but the popup
    // still reports it so the owner can finish or see the revocation.
    const grant = (await activeGrant(realm)) ?? realm.grant;
    return {
      ok: true,
      result: {
        origin,
        issuer: realm.issuer,
        chain: realm.chain,
        state: grant?.state ?? (realm.pairing ? "requested" : "unpaired"),
        account: grant ? await grant.account(realm.chain).catch(() => null) : null,
        expiresAt: grant?.expiresAt ?? null,
      },
    };
  }
  if (message.command === "pair") {
    const scope = message.scope;
    if (!scope || typeof scope !== "object") return rpcError(-32602, "pair requires a scope");
    const realm = await realmFor(origin);
    // One request at a time per origin, and never over a Grant that is still
    // in force or still being revoked: the realm tracks exactly one Grant.
    if (realm.pairing) {
      return rpcError(-32002, "a permission request is already waiting for the owner");
    }
    // Claim the slot before the first await so a concurrent pair cannot pass.
    realm.pairing = true;
    let grant;
    try {
      const current = (await activeGrant(realm)) ?? realm.grant;
      if (current?.state === "active" || current?.state === "revoking") {
        return rpcError(-32000, "this origin already holds a permission; revoke it first");
      }
      // A member's earlier request may since have been approved by the root.
      const redeemed = await realm.connection.redeemPending();
      // The account root reviews and signs in the issuer's portal; this only
      // opens it and waits for the decision.
      grant =
        redeemed ??
        (await realm.connection.requestPermission({
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
        }));
    } finally {
      realm.pairing = false;
    }
    // A member's request waits for the account root; the SDK journals it and
    // the dapp's next request redeems it.
    if (grant.state === "pending") {
      return rpcError(-32002, "the request awaits the account root's approval");
    }
    realm.grant = grant;
    realm.providers.clear();
    return { ok: true, result: { state: grant.state, account: await grant.account(realm.chain) } };
  }
  if (message.command === "revoke") {
    const realm = await realmFor(origin);
    // A revoking Grant is retried: each call re-checks the chains and
    // completes to revoked once the permission is observed absent.
    const grant = (await activeGrant(realm)) ?? realm.grant;
    if (grant === null || (grant.state !== "active" && grant.state !== "revoking")) {
      return rpcError(-32000, "nothing to revoke for this origin");
    }
    await grant.revoke();
    realm.grant = null;
    realm.providers.clear();
    return { ok: true, result: { state: grant.state } };
  }
  return rpcError(-32601, "unknown popup command");
}

chrome.tabs.onRemoved.addListener((tabId) => {
  void rejectClosedWalletCallConfirmation(chrome, tabId);
});

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
    if (message.type === "transaction-confirmation") {
      if (sender.origin !== `chrome-extension://${chrome.runtime.id}`) {
        return rpcError(4100, "call decisions must come from the extension");
      }
      const settled = await decideWalletCallConfirmation(chrome, message.token, message.decision);
      return settled
        ? { ok: true, result: { decision: message.decision } }
        : rpcError(-32603, "wallet call confirmation is unavailable");
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
