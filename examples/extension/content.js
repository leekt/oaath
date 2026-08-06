/**
 * The untrusted bridge between the page and the extension worker.
 *
 * The page-world provider is a manifest `"world": "MAIN"` content script —
 * Chrome injects it directly, so a page CSP cannot block it — and this script
 * only relays request/response pairs. It interprets nothing: the worker
 * exact-captures every message and takes the page's identity from
 * `sender.origin` as Chrome reports it — a page cannot claim another origin's
 * Grant through anything it posts here.
 *
 * @author taek <leekt216@gmail.com>
 */
(() => {
  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.source !== "oaath-page" || data.type !== "request") return;
    // sendMessage wakes the worker when it sleeps; no port lifecycle to manage.
    chrome.runtime.sendMessage({ type: "provider", method: data.method, params: data.params }).then(
      (response) => {
        window.postMessage(
          {
            source: "oaath-content",
            type: "response",
            id: data.id,
            ok: response?.ok === true,
            result: response?.result,
            error: response?.error ?? { code: -32603, message: "OAAth worker is unavailable" },
          },
          window.location.origin,
        );
      },
      () => {
        window.postMessage(
          {
            source: "oaath-content",
            type: "response",
            id: data.id,
            ok: false,
            error: { code: -32603, message: "OAAth worker is unavailable" },
          },
          window.location.origin,
        );
      },
    );
  });
})();
