/**
 * The demo page: request a Grant through the OAAth portal, fund the
 * counterfactual account, then send one covered call that deploys the account,
 * enables the permission and executes, and observe it to finality.
 *
 * Every chain request goes through this page's own server (`/rpc/*`), which
 * holds the endpoints, the request budget and the time cap.
 */
import { createOAAth } from "@oaath/sdk";
import { createCetaneChainPorts } from "@oaath/sdk/cetane";

const config = await (await fetch("/config.json")).json();
const { issuer, chainId, target, selector } = config;
const redirectUri = `${location.origin}/callback`;
const operationKey = `oaath-grant-demo-operation:${issuer}:${chainId}`;
const $ = (id) => document.querySelector(`#${id}`);
$("target").textContent = target;
$("selector").textContent = selector;

function show(outcome, text) {
  $("result").dataset.outcome = outcome;
  $("result").textContent = text;
}

function failed(error) {
  const code = error?.code ?? "error";
  show(code, `${code}: ${error?.message ?? error}`);
}

async function chainRead(method, params) {
  const response = await fetch("/rpc/chain", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = await response.json();
  if (body.error) throw Object.assign(new Error(body.error.message), { code: "rpc_refused" });
  return BigInt(body.result);
}

function ether(wei) {
  const whole = wei / 10n ** 18n;
  const fraction = (wei % 10n ** 18n).toString().padStart(18, "0").slice(0, 6).replace(/0+$/u, "");
  return `${whole}${fraction ? `.${fraction}` : ""} ETH`;
}

async function clientId() {
  if (config.clientId) return config.clientId;
  const key = `oaath-grant-demo-client:${issuer}:${redirectUri}`;
  const stored = localStorage.getItem(key);
  if (stored) return stored;
  const response = await fetch(`${issuer}/oauth/clients`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "OAAth Grant demo", redirect_uris: [redirectUri] }),
  });
  if (!response.ok) throw new Error(`client registration failed (${response.status})`);
  const registered = (await response.json()).client_id;
  localStorage.setItem(key, registered);
  return registered;
}

const client = await clientId();
$("status").textContent = `Issuer ${issuer} · chain ${chainId} · client ${client}`;
const oaath = createOAAth({
  chains: createCetaneChainPorts(
    {
      [chainId]: {
        publicRpcUrls: [`${location.origin}/rpc/chain`],
        bundlerUrl: `${location.origin}/rpc/bundler`,
      },
    },
    // The server enforces the run's budget; these bound this page's share.
    {
      retry: { attempts: 2, delayMs: 1_000 },
      timeoutMs: 15_000,
      maxRequests: config.maxRequests,
      maxConcurrency: 2,
    },
  ),
  approvals: { kind: "oauth", issuer, clientId: client, redirectUri },
});
const connection = await oaath.connect();
let grant = null;

async function showAccount() {
  const account = await grant.account(chainId);
  $("account").textContent = account;
  $("funding").hidden = false;
  $("sending").hidden = false;
  window.oaathDemo = { account, grantState: grant.state };
  try {
    // About 4.1M gas covers deployment, enable and the call; three times the
    // current gas price leaves room for the fee the bundler asks.
    const gasPrice = await chainRead("eth_gasPrice", []);
    $("amount").textContent =
      `Send at least ${ether(4_100_000n * gasPrice * 3n)} on chain ${chainId} (4.1M gas at 3× the current gas price).`;
  } catch (error) {
    failed(error);
  }
}

async function observe(operation) {
  $("operation").textContent = `UserOperation ${operation.id}\nwaiting for inclusion…`;
  for (let poll = 0; poll < config.maxPolls; poll += 1) {
    const outcome = await operation.wait({ attempts: 1 });
    const link =
      outcome.transactionHash && config.explorerTxUrl
        ? `\n${config.explorerTxUrl}${outcome.transactionHash}`
        : "";
    $("operation").textContent =
      `UserOperation ${operation.id}\nstatus ${outcome.status}` +
      (outcome.transactionHash ? `\ntransaction ${outcome.transactionHash}${link}` : "") +
      (outcome.outcome ? `\noutcome ${JSON.stringify(outcome.outcome)}` : "");
    window.oaathDemo = { ...window.oaathDemo, operation: operation.id, outcome };
    if (["finalized", "dropped", "superseded", "abandoned"].includes(outcome.status)) {
      show(outcome.status, `operation ${outcome.status}`);
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, config.pollIntervalMs));
  }
  show(
    "observation-paused",
    "Still not final. Reload this page later to keep observing; nothing is resent.",
  );
}

try {
  grant = await connection.resume();
  if (grant) {
    await showAccount();
    const id = localStorage.getItem(operationKey);
    const operation = id ? await grant.getOperation({ chain: chainId, id }) : null;
    if (operation) {
      $("send").disabled = true;
      await observe(operation);
    }
  }
} catch (error) {
  failed(error);
}

$("grant").disabled = false;
$("grant").addEventListener("click", async () => {
  $("grant").disabled = true;
  try {
    grant = await connection.requestPermission({
      chainScope: "all",
      permissions: [{ calls: [{ target, selectors: [selector], valueLimit: "0" }] }],
      expiresIn: 3_600,
      perChainOperationLimit: 2,
    });
    show("granted", `Grant ${grant.state}`);
    await showAccount();
  } catch (error) {
    failed(error);
  }
  $("grant").disabled = false;
});

$("balance").addEventListener("click", async () => {
  try {
    $("balance-value").textContent = ether(
      await chainRead("eth_getBalance", [$("account").textContent, "latest"]),
    );
  } catch (error) {
    failed(error);
  }
});

$("send").addEventListener("click", async () => {
  // One send per click and per operation: a lost answer is observed, never resent.
  $("send").disabled = true;
  try {
    const operation = await grant.sendCalls({
      chain: chainId,
      calls: [{ target, value: "0", data: selector }],
    });
    localStorage.setItem(operationKey, operation.id);
    await observe(operation);
  } catch (error) {
    failed(error);
    $("send").disabled = false;
  }
});
