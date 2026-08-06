/**
 * Page-world provider: the only thing a dapp ever sees.
 *
 * Declared in the manifest with `"world": "MAIN"`, so Chrome itself runs it in
 * the page's world — a page CSP that blocks `chrome-extension://` script
 * elements cannot block it, the way it could a DOM-injected script tag.
 *
 * It holds no keys, no Grant, and no transport — every request crosses
 * `window.postMessage` to the content script, which relays it to the
 * extension's service worker where the OAAth realm lives. The page can lie
 * about anything in these messages; the worker binds authority to the sender's
 * origin as the browser reports it, never to anything said here.
 *
 * @author taek <leekt216@gmail.com>
 */
(() => {
  const pending = new Map();
  let nextId = 1;

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.source !== "oaath-content" || data.type !== "response") return;
    const settle = pending.get(data.id);
    if (!settle) return;
    pending.delete(data.id);
    if (data.ok) {
      settle.resolve(data.result);
      return;
    }
    const failure = new Error(
      typeof data.error?.message === "string" ? data.error.message : "OAAth request failed",
    );
    failure.code = typeof data.error?.code === "number" ? data.error.code : -32603;
    settle.reject(failure);
  });

  const provider = {
    request(args) {
      return new Promise((resolve, reject) => {
        const method = args?.method;
        if (typeof method !== "string") {
          const failure = new Error("request requires a method");
          failure.code = -32602;
          reject(failure);
          return;
        }
        const id = nextId;
        nextId += 1;
        pending.set(id, { resolve, reject });
        window.postMessage(
          {
            source: "oaath-page",
            type: "request",
            id,
            method,
            params: Array.isArray(args.params) ? args.params : [],
          },
          window.location.origin,
        );
      });
    },
    // Minimal EIP-1193 event surface: the provider emits nothing yet, and
    // dapps that subscribe must not crash.
    on() {
      return provider;
    },
    removeListener() {
      return provider;
    },
  };

  const info = Object.freeze({
    uuid: crypto.randomUUID(),
    name: "OAAth",
    rdns: "app.oaath",
    icon:
      "data:image/svg+xml;base64," +
      btoa(
        '<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96"><rect width="96" height="96" rx="20" fill="#1a1a2e"/><text x="48" y="62" font-family="monospace" font-size="40" fill="#4ade80" text-anchor="middle">Oa</text></svg>',
      ),
  });
  const announce = () => {
    window.dispatchEvent(
      new CustomEvent("eip6963:announceProvider", {
        detail: Object.freeze({ info, provider }),
      }),
    );
  };
  window.addEventListener("eip6963:requestProvider", announce);
  announce();
})();
