/**
 * The untrusted bridge between the page and the extension worker.
 *
 * It injects the page-world provider and relays request/response pairs. It
 * interprets nothing: the worker exact-captures every message and takes the
 * page's identity from `sender.origin` as Chrome reports it — a page cannot
 * claim another origin's Grant through anything it posts here.
 *
 * @author taek <leekt216@gmail.com>
 */
(() => {
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("injected.js");
  script.addEventListener("load", () => script.remove());
  (document.head ?? document.documentElement).appendChild(script);

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
