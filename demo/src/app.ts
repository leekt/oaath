/**
 * The OAAth demo page: login, invite a member, request a Grant (pending for a
 * member until the root approves), send one covered call, have the root approve
 * one owner operation, and revoke in the portal.
 *
 * Every chain, bundler and paymaster request goes through this origin's Worker
 * (`/rpc/*`, `/paymaster/421614`), which holds the endpoints and budgets. A
 * send is made once per click; a lost answer is observed, never resent.
 */
import {
  createOAAth,
  loginWithOAAth,
  type OaathLogin,
  requestOwnerOperationApproval,
} from "@oaath/sdk";
import { createCetaneChainPorts } from "@oaath/sdk/cetane";
import { type PreparedOwnerOperation, prepareOwnerOperation } from "@oaath/sdk/kernel";

interface DemoConfig {
  readonly issuer: string;
  readonly clientId: string;
  readonly chainId: number;
  readonly target: `0x${string}`;
  readonly selector: `0x${string}`;
  readonly explorerTxUrl: string | null;
  readonly sponsored: boolean;
}

const configuration = await fetch("/config.json");
if (!configuration.ok) throw new Error("Demo configuration unavailable");
const config = (await configuration.json()) as DemoConfig;
const { issuer, clientId, chainId, target, selector } = config;
const redirectUri = `${location.origin}/callback`;
const paymasterUrl = `${location.origin}/paymaster/${chainId}`;
const ENTRY_POINT = "0x433709009b8330fda32311df1c2afa402ed8d009";
const STORAGE = {
  login: `oaath-demo-login:${issuer}`,
  operation: `oaath-demo-operation:${issuer}:${chainId}`,
  owner: `oaath-demo-owner-operation:${issuer}:${chainId}`,
};
const POLL_MS = 3_000;
const MAX_POLLS = 40;
const call = { target, value: "0", data: selector } as const;

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const button = (id: string) => $<HTMLButtonElement>(id);

let feedbackHost = $("s-login");

function busy(source: HTMLButtonElement, active: boolean, label: string) {
  if (active) {
    source.dataset.idleLabel = source.textContent ?? "";
    feedbackHost = source.closest<HTMLElement>("section") ?? feedbackHost;
    $("feedback").hidden = true;
  }
  source.disabled = active;
  source.setAttribute("aria-busy", String(active));
  source.textContent = active ? label : (source.dataset.idleLabel ?? label);
}

function step(name: "login" | "grant" | "send", state: string, label: string) {
  if (state === "current") {
    for (const current of document.querySelectorAll<HTMLElement>(
      ".journey [data-state='current']",
    )) {
      current.dataset.state = "";
      current.querySelector("a")?.removeAttribute("aria-current");
    }
  }
  $(`progress-${name}`).dataset.state = state;
  $(`progress-${name}-label`).textContent = label;
  $(`${name}-badge`).textContent = label;
  $(`${name}-badge`).dataset.state = state;
  const link = $(`progress-${name}`).querySelector("a");
  if (state === "current") link?.setAttribute("aria-current", "step");
  else link?.removeAttribute("aria-current");
}

function log(line: string) {
  $("log").textContent = `${new Date().toLocaleTimeString()} ${line}\n${$("log").textContent}`;
}

function show(outcome: string, text: string) {
  feedbackHost.append($("feedback"));
  $("feedback").hidden = false;
  $("feedback").dataset.tone = ["signed-in", "granted", "finalized", "owner-included"].includes(
    outcome,
  )
    ? "success"
    : "info";
  $("result").dataset.outcome = outcome;
  $("result").textContent = text;
  log(text);
}

function failed(error: unknown) {
  const code = (error as { code?: string } | null)?.code ?? "error";
  const message =
    code === "access_denied"
      ? "The request was declined. You can start a new request when you're ready."
      : code === "uncertain"
        ? "The submission has no confirmed answer yet. Reload to observe it; do not send it again."
        : "The action couldn't complete. No automatic retry was made. Check your connection and the account portal before continuing.";
  show(code, message);
  $("feedback").dataset.tone = "error";
}

function storage(key: string, value?: string | null): string | null {
  try {
    if (value === null) localStorage.removeItem(key);
    else if (value !== undefined) localStorage.setItem(key, value);
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

async function rpc(role: "chain" | "bundler", method: string, params: unknown[]) {
  const response = await fetch(`/rpc/${role}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!response.ok)
    throw Object.assign(new Error(`${role} proxy answered ${response.status}`), {
      code: response.status === 504 ? "uncertain" : "rpc_unavailable",
    });
  const body = (await response.json()) as { result?: unknown; error?: { message: string } };
  if (body.error) throw Object.assign(new Error(body.error.message), { code: "rpc_refused" });
  return body.result;
}

function ether(wei: bigint) {
  const whole = wei / 10n ** 18n;
  const fraction = (wei % 10n ** 18n).toString().padStart(18, "0").slice(0, 6).replace(/0+$/u, "");
  return `${whole}${fraction ? `.${fraction}` : ""} ETH`;
}

function explorer(transactionHash: string) {
  return config.explorerTxUrl ? `\n${config.explorerTxUrl}${transactionHash}` : "";
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// ---- static text --------------------------------------------------------------

$<HTMLAnchorElement>("portal-link").href = issuer;
$<HTMLAnchorElement>("accounts-link").href = `${issuer}/accounts`;
$<HTMLAnchorElement>("revoke-link").href = `${issuer}/accounts`;
$("target").textContent = target;
$("selector").textContent = selector;
$("gas-context").textContent = config.sponsored ? "Test-call gas sponsored" : "Account pays gas";
$("status").textContent =
  `Issuer ${issuer} · client ${clientId} · chain ${chainId} · ` +
  (config.sponsored ? "gas sponsored" : "no sponsorship: accounts pay their own gas");

// ---- 1. login, 2. invite ------------------------------------------------------

let login: OaathLogin | null = null;

function role(summary: Pick<OaathLogin, "account" | "accounts">) {
  return summary.accounts.find((entry) => entry.address === summary.account)?.role ?? "unknown";
}

function showIdentity(summary: Pick<OaathLogin, "account" | "signer" | "accounts" | "verified">) {
  const current = role(summary);
  $("identity").textContent = JSON.stringify(
    {
      account: summary.account,
      signer: summary.signer,
      role: current,
      oaath_accounts: summary.accounts,
      verified: summary.verified,
    },
    null,
    2,
  );
  $("identity").dataset.role = current;
  $("identity-summary").hidden = false;
  $("identity-details").hidden = false;
  $("identity-title").textContent = login
    ? `${current === "root" ? "Owner" : "Member"} · signed in`
    : "Saved account · sign in again";
  $("identity-account").textContent = `${summary.account.slice(0, 8)}…${summary.account.slice(-6)}`;
  if (login) {
    step("login", "done", "Signed in");
    step("grant", "current", "Review permission");
  }
  $("s-invite").hidden = current !== "root";
  $("invite-url").textContent = `${location.origin}/?invite=${summary.account}`;
  $("s-owner").hidden = current !== "root" || login === null;
}

const remembered = storage(STORAGE.login);
if (remembered) {
  try {
    showIdentity(JSON.parse(remembered));
  } catch {
    storage(STORAGE.login, null);
  }
}

async function signIn(source: HTMLButtonElement) {
  busy(source, true, "Waiting for sign-in…");
  try {
    // Called inside the click: the popup opens before anything is awaited.
    login = await loginWithOAAth({ issuer, clientId, redirectUri });
    const { account, signer, accounts, verified } = login;
    storage(STORAGE.login, JSON.stringify({ account, signer, accounts, verified }));
    showIdentity(login);
    show("signed-in", "You're signed in. Review a permission when you're ready.");
  } catch (error) {
    failed(error);
  }
  busy(source, false, "Sign in with OAAth");
  if (login && source.id === "login") source.textContent = "Sign in again";
}

button("login").addEventListener("click", () => signIn(button("login")));
async function copy(source: HTMLButtonElement, value: string) {
  feedbackHost = source.closest<HTMLElement>("section") ?? feedbackHost;
  try {
    await navigator.clipboard.writeText(value);
    const label = source.textContent ?? "Copy";
    source.textContent = "Copied";
    setTimeout(() => {
      source.textContent = label;
    }, 2_000);
  } catch {
    show(
      "copy-unavailable",
      "Copy isn't available. Open the details and copy the address or link manually.",
    );
  }
}
button("copy-invite").addEventListener("click", () =>
  copy(button("copy-invite"), $("invite-url").textContent ?? ""),
);

const invited = new URLSearchParams(location.search).get("invite");
if (invited && /^0x[0-9a-fA-F]{40}$/u.test(invited)) {
  $("s-join").hidden = false;
  $("join-account").textContent = invited.toLowerCase();
  button("join").addEventListener("click", () => signIn(button("join")));
  button("copy-join").addEventListener("click", () =>
    copy(button("copy-join"), invited.toLowerCase()),
  );
}

// ---- 3. grant, 4. send ----------------------------------------------------------

const oaath = createOAAth({
  chains: createCetaneChainPorts(
    {
      [chainId]: {
        publicRpcUrls: [`${location.origin}/rpc/chain`],
        bundlerUrl: `${location.origin}/rpc/bundler`,
        ...(config.sponsored ? { paymasterUrl } : {}),
      },
    },
    // The Worker enforces the shared budget; these bound this page's share.
    {
      retry: { attempts: 2, delayMs: 1_000 },
      timeoutMs: 15_000,
      maxRequests: 400,
      maxConcurrency: 2,
    },
  ),
  approvals: { kind: "oauth", issuer, clientId, redirectUri },
});
const connection = await oaath.connect();
type Grant = NonNullable<Awaited<ReturnType<typeof connection.resume>>>;
type Operation = Awaited<ReturnType<Grant["sendCalls"]>>;
let grant: Grant | null = null;

async function showAccount() {
  if (!grant) return;
  const account = await grant.account(chainId);
  $("account").textContent = account;
  $("s-send").hidden = false;
  $("call-empty").hidden = true;
  step("grant", "done", `Permission ${grant.state}`);
  step("send", "current", "Ready to send");
  $("sponsored").hidden = !config.sponsored;
  $("funding").hidden = config.sponsored;
  if (config.sponsored) return;
  try {
    // About 4.1M gas covers deployment, enable and the call, at 3× today's gas price.
    const gasPrice = BigInt((await rpc("chain", "eth_gasPrice", [])) as string);
    $("amount").textContent =
      `Fund ${account} with at least ${ether(4_100_000n * gasPrice * 3n)} of Arbitrum Sepolia ETH.`;
  } catch (error) {
    failed(error);
  }
}

async function observe(operation: Operation) {
  feedbackHost = $("step-send");
  step("send", "current", "Observing call");
  button("send").textContent = "Call submitted";
  $("operation").textContent = `UserOperation ${operation.id}\nwaiting for inclusion…`;
  for (let poll = 0; poll < MAX_POLLS; poll += 1) {
    const outcome = await operation.wait({ attempts: 1 });
    $("operation").textContent =
      `UserOperation ${operation.id}\nstatus ${outcome.status}` +
      (outcome.transactionHash
        ? `\ntransaction ${outcome.transactionHash}${explorer(outcome.transactionHash)}`
        : "");
    if (["finalized", "dropped", "superseded", "abandoned"].includes(outcome.status)) {
      step("send", outcome.status === "finalized" ? "done" : "", `Call ${outcome.status}`);
      show(outcome.status, `Test call ${outcome.status}`);
      return;
    }
    await sleep(POLL_MS);
  }
  step("send", "current", "Awaiting confirmation");
  show("observation-paused", "Still not final. Reload later to keep observing; nothing is resent.");
}

/** A Grant, or a request still waiting for the account root. */
async function settle(result: Awaited<ReturnType<typeof connection.requestPermission>> | null) {
  if (result === null) return;
  feedbackHost = $("s-grant");
  if ("state" in result && result.state === "pending") {
    button("redeem").hidden = false;
    step("grant", "current", "Waiting for owner");
    const review = $<HTMLAnchorElement>("owner-review-link");
    review.href = `${issuer}/requests/${result.requestId}`;
    review.hidden = false;
    $("grant-state").textContent =
      `Waiting for the account owner.\nThe owner approves at ${issuer}/requests/${result.requestId}\n` +
      `(or under ${issuer}/accounts). Then click "Check approval".`;
    show("pending", `Request ${result.requestId} is waiting for the account owner`);
    return;
  }
  button("redeem").hidden = true;
  $("owner-review-link").hidden = true;
  grant = result as Grant;
  $("grant-state").textContent = `Grant ${grant.state}`;
  await showAccount();
  show("granted", `Grant ${grant.state}`);
}

try {
  // A request journaled before a reload is redeemed once; otherwise resume.
  const redeemed = await connection.redeemPending();
  if (redeemed) await settle(redeemed);
  else {
    grant = await connection.resume();
    if (grant) {
      $("grant-state").textContent = `Grant ${grant.state} (resumed)`;
      await showAccount();
    }
  }
  const id = storage(STORAGE.operation);
  if (grant && id) {
    const operation = await grant.getOperation({ chain: chainId, id });
    if (operation) {
      button("send").disabled = true;
      void observe(operation);
    }
  }
} catch (error) {
  failed(error);
}

$("startup-message").hidden = true;
button("login").disabled = false;
button("join").disabled = false;
button("grant").disabled = false;
button("grant").addEventListener("click", async () => {
  busy(button("grant"), true, "Waiting for review…");
  try {
    await settle(
      await connection.requestPermission({
        chainScope: "all",
        permissions: [{ calls: [{ target, selectors: [selector], valueLimit: "0" }] }],
        expiresIn: 3_600,
        perChainOperationLimit: 2,
      }),
    );
  } catch (error) {
    failed(error);
  }
  busy(button("grant"), false, "Request permission");
});

button("redeem").addEventListener("click", async () => {
  busy(button("redeem"), true, "Checking approval…");
  try {
    // Exactly one token request per click.
    await settle(await connection.redeemPending());
  } catch (error) {
    failed(error);
  }
  busy(button("redeem"), false, "Check approval");
});

button("balance").addEventListener("click", async () => {
  feedbackHost = $("step-send");
  try {
    const wei = (await rpc("chain", "eth_getBalance", [
      $("account").textContent,
      "latest",
    ])) as string;
    $("balance-value").textContent = ether(BigInt(wei));
  } catch (error) {
    failed(error);
  }
});

button("send").addEventListener("click", async () => {
  if (!grant) return;
  feedbackHost = $("step-send");
  $("feedback").hidden = true;
  button("send").disabled = true;
  button("send").textContent = "Sending test call…";
  step("send", "current", "Sending call");
  try {
    const operation = await grant.sendCalls({
      chain: chainId,
      calls: [call],
      ...(config.sponsored
        ? { payer: { kind: "paymaster-service", url: paymasterUrl, context: {} } }
        : {}),
    });
    storage(STORAGE.operation, operation.id);
    await observe(operation);
  } catch (error) {
    failed(error);
    button("send").disabled = false;
    button("send").textContent = "Send test call";
    step("send", "current", "Check activity");
  }
});

// ---- 5. owner operation ----------------------------------------------------------

let prepared: Readonly<PreparedOwnerOperation> | null = null;

function word(value: string | bigint) {
  return BigInt(value).toString(16).padStart(64, "0");
}

button("owner-prepare").addEventListener("click", async () => {
  if (!login) return failed(new Error("log in as the account owner first"));
  busy(button("owner-prepare"), true, "Preparing operation…");
  try {
    const account = login.accountProfile as Parameters<typeof prepareOwnerOperation>[0]["account"];
    const existing = "address" in account;
    const prepare = (deployed: boolean, sequence: bigint, fee: bigint) =>
      prepareOwnerOperation({
        account,
        chainId,
        deployed,
        calls: [call],
        nonce: { lane: "0", sequence: sequence.toString() },
        gas: {
          callGasLimit: "200000",
          verificationGasLimit: deployed ? "1500000" : "3000000",
          // Arbitrum charges L1 data through preVerificationGas.
          preVerificationGas: "1000000",
          maxFeePerGas: fee.toString(),
          maxPriorityFeePerGas: fee.toString(),
        },
      });
    const draft = prepare(existing, 0n, 1n);
    const sender = draft.request.userOperation.sender;
    const deployed = existing || (await rpc("chain", "eth_getCode", [sender, "latest"])) !== "0x";
    const key = BigInt(draft.request.userOperation.nonce) >> 64n;
    const nonce = BigInt(
      (await rpc("chain", "eth_call", [
        { to: ENTRY_POINT, data: `0x35567e1a${word(sender)}${word(key)}` },
        "latest",
      ])) as string,
    );
    const fee = BigInt((await rpc("chain", "eth_gasPrice", [])) as string) * 2n;
    prepared = prepare(deployed, nonce & ((1n << 64n) - 1n), fee);
    const gas = (deployed ? 1_500_000n : 3_000_000n) + 1_200_000n;
    $("owner-result").textContent =
      `Operation ${prepared.request.userOperationHash}\nsender ${sender}\n` +
      `The account pays up to ${ether(gas * fee)}; fund it first if needed.`;
    button("owner-approve").hidden = false;
    show("owner-prepared", "Owner operation prepared");
  } catch (error) {
    failed(error);
  }
  busy(button("owner-prepare"), false, "Prepare operation");
});

async function observeOwner(hash: string) {
  feedbackHost = $("s-owner");
  for (let poll = 0; poll < MAX_POLLS; poll += 1) {
    const receipt = (await rpc("bundler", "eth_getUserOperationReceipt", [hash])) as {
      success: boolean;
      receipt: { transactionHash: string };
    } | null;
    if (receipt) {
      const transaction = receipt.receipt.transactionHash;
      $("owner-result").textContent =
        `UserOperation ${hash}\n${receipt.success ? "included" : "reverted"}\n` +
        `transaction ${transaction}${explorer(transaction)}`;
      show(receipt.success ? "owner-included" : "owner-reverted", `Owner operation ${hash}`);
      storage(STORAGE.owner, null);
      return;
    }
    await sleep(POLL_MS);
  }
  show("owner-observation-paused", "Not included yet. Reload later; nothing is resent.");
}

button("owner-approve").addEventListener("click", async () => {
  if (!prepared) return;
  const request = prepared.request;
  busy(button("owner-approve"), true, "Waiting for approval…");
  try {
    // Inside the click: the popup opens before anything is awaited.
    const verified = await requestOwnerOperationApproval({
      issuer,
      clientId,
      redirectUri,
      request,
    });
    prepared = null;
    button("owner-approve").hidden = true;
    storage(STORAGE.owner, request.userOperationHash);
    $("owner-result").textContent = `UserOperation ${request.userOperationHash}\nsubmitting once…`;
    try {
      await rpc("bundler", "eth_sendUserOperation", [verified.userOperation, verified.entryPoint]);
    } catch (error) {
      // A lost answer may still land; only observe it.
      if ((error as { code?: string }).code !== "uncertain") throw error;
    }
    await observeOwner(request.userOperationHash);
  } catch (error) {
    failed(error);
  }
  busy(button("owner-approve"), false, "Approve in OAAth");
});

const pendingOwner = storage(STORAGE.owner);
if (pendingOwner) {
  $("s-owner").hidden = false;
  void observeOwner(pendingOwner).catch(failed);
}
