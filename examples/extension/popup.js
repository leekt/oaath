/**
 * Pairing UI for the active tab's origin: request one scoped Grant, show its
 * state, revoke it. The owner still approves on their own device through the
 * service's authorization flow — this popup never sees owner authority.
 *
 * @author taek <leekt216@gmail.com>
 */
const statusBox = document.getElementById("status");

async function activeOrigin() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !/^https?:\/\//u.test(tab.url)) return null;
  return new URL(tab.url).origin;
}

function show(text) {
  statusBox.textContent = text;
}

async function command(message) {
  const response = await chrome.runtime.sendMessage({ type: "popup", ...message });
  if (!response?.ok) throw new Error(response?.error?.message ?? "command failed");
  return response.result;
}

async function refresh() {
  const origin = await activeOrigin();
  if (origin === null) {
    show("open a web page to pair it");
    return;
  }
  try {
    const status = await command({ command: "status", origin });
    show(
      `origin   ${status.origin}\n` +
        `service  ${status.url} (chain ${status.chain})\n` +
        `state    ${status.state}\n` +
        (status.account ? `account  ${status.account}\n` : "") +
        (status.expiresAt ? `expires  ${new Date(status.expiresAt * 1000).toISOString()}` : ""),
    );
  } catch (error) {
    show(`error: ${error.message}`);
  }
}

document.getElementById("save").addEventListener("click", async () => {
  const url = document.getElementById("url").value.trim();
  const chain = Number(document.getElementById("chain").value.trim());
  await chrome.storage.local.set({
    ...(url ? { url } : {}),
    ...(Number.isSafeInteger(chain) && chain >= 1 ? { chain } : {}),
  });
  await refresh();
});

document.getElementById("pair").addEventListener("click", async () => {
  const origin = await activeOrigin();
  if (origin === null) return;
  show("requesting permission — approve on the owner device…");
  try {
    const result = await command({
      command: "pair",
      origin,
      scope: {
        target: document.getElementById("target").value.trim(),
        selector: document.getElementById("selector").value.trim(),
        valueLimit: document.getElementById("valueLimit").value.trim(),
        expiresIn: Number(document.getElementById("expiresIn").value.trim()),
        perChainOperationLimit: Number(document.getElementById("operationLimit").value.trim()),
      },
    });
    show(`paired: ${result.state}\naccount ${result.account}`);
  } catch (error) {
    show(`pairing failed: ${error.message}`);
  }
  await refresh();
});

document.getElementById("revoke").addEventListener("click", async () => {
  const origin = await activeOrigin();
  if (origin === null) return;
  show("revoking…");
  try {
    await command({ command: "revoke", origin });
  } catch (error) {
    show(`revoke failed: ${error.message}`);
  }
  await refresh();
});

chrome.storage.local.get({ url: "", chain: "" }).then((stored) => {
  if (stored.url) document.getElementById("url").value = stored.url;
  if (stored.chain) document.getElementById("chain").value = String(stored.chain);
});
refresh();
