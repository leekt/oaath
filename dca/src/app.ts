/**
 * The DCA example page: sign in with OAAth, set a small plan (amount per buy,
 * number of buys, interval), approve it once in the OAAth popup, and watch the
 * hosted automation service make each buy.
 *
 * The Worker turns the verified login into an automation session; the page
 * then creates, authorizes and watches the plan at the service directly. The
 * service holds the session key and sends every operation, each once; this page
 * never signs a plan operation. Balances are read through the Worker's chain proxy.
 *
 * "Mint 1,000 tUSD" sends one zero-fee operation, `tUSD.mint(account, 1000e6)`,
 * through the Worker's gas-paying relay. tUSD's mint is permissionless, so the
 * sender is a throwaway Kernel account of a key this page generates and keeps;
 * its first operation deploys it. No wallet prompt; each click sends once.
 */
import {
  type AutomationClient,
  createAutomation,
  type Plan,
  type PlanStatus,
} from "@oaath/automation";
import { loginWithOAAth } from "@oaath/sdk";
import { ECDSA_VALIDATOR, kernelDeployment } from "@oaath/sdk/kernel";
import { createClient, createWalletClient, http } from "cetane";
import { createAccount, generatePrivateKey, privateKeyToSigner } from "cetane/accounts";
import { createAuthorization } from "cetane/accounts/kernel";
import { waitForTransactionReceipt } from "cetane/actions";
import { arbitrum } from "cetane/chains/arbitrum";
import { withKernel } from "cetane/chains/kernel";
import {
  BUY_DECIMALS,
  BUY_TOKEN_DATA,
  balanceOfData,
  type DcaOption,
  dcaOptions,
  decodeAddress,
  decodeUint,
  formatUnits,
  intervalLabel,
  mintCall,
  PlanInputError,
  parseAmount,
  planRequest,
  runRows,
  SELL_DECIMALS,
} from "./plan.js";

interface AppConfig {
  readonly issuer: string;
  readonly clientId: string;
  readonly chainId: number;
  readonly explorerTxUrl: string | null;
  /** The automation service and the definition id prefix this app offers, or null. */
  readonly automation: Readonly<{ url: string; prefix: string }> | null;
  /** The relay-paid test tUSD mint, or null when the relay is not configured. */
  readonly mint: Readonly<{ token: `0x${string}`; amount: string }> | null;
}

interface Stored {
  readonly account: `0x${string}`;
  readonly token: string;
  readonly expiresAt: number;
  readonly planId: string | null;
}

const configuration = await fetch("/config.json");
if (!configuration.ok) throw new Error("configuration unavailable");
const config = (await configuration.json()) as AppConfig;
const { issuer, clientId, chainId } = config;
const redirectUri = `${location.origin}/callback`;
const STORAGE = `oaath-dca:${issuer}`;
const POLL_MS = 5_000;
const TERMINAL: readonly PlanStatus[] = ["completed", "cancelled", "expired", "failed"];
const PLAN_STATUS: Readonly<Record<PlanStatus, string>> = {
  draft: "Draft",
  awaiting_consent: "Awaiting approval",
  authorized: "Approved",
  active: "Running",
  paused: "Paused",
  cancelling: "Cancelling",
  cancelled: "Cancelled",
  completed: "Completed",
  expired: "Expired",
  failed: "Failed",
};

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

function step(name: "login" | "plan" | "approve" | "watch", state: "" | "current" | "done") {
  const item = $(`progress-${name}`);
  item.dataset.state = state;
  const link = item.querySelector("a");
  if (state === "current") link?.setAttribute("aria-current", "step");
  else link?.removeAttribute("aria-current");
}

function badge(id: "login" | "plan" | "watch", text: string, state: "" | "current" | "done") {
  $(`${id}-badge`).textContent = text;
  $(`${id}-badge`).dataset.state = state;
}

function show(tone: "info" | "success" | "error", text: string) {
  $("feedback").hidden = false;
  $("feedback").dataset.tone = tone;
  $("result").textContent = text;
}

function failed(error: unknown) {
  const code = (error as { code?: unknown } | null)?.code;
  const known = typeof code === "string" ? code : "error";
  console.error("[oaath-dca]", known, error);
  show(
    "error",
    known === "access_denied"
      ? "The request was declined. You can start again when you're ready."
      : (error as { rpcCode?: unknown } | null)?.rpcCode === -32001
        ? "The bundler refused this site's API key (RPC -32001). Nothing was submitted."
        : known === "request_outcome_unknown"
          ? "The service didn't answer. Reload to check the plan before trying again."
          : `That didn't work (${known}). Nothing was retried automatically.`,
  );
}

function stored(next?: Stored | null): Stored | null {
  try {
    if (next === null) localStorage.removeItem(STORAGE);
    else if (next) localStorage.setItem(STORAGE, JSON.stringify(next));
    const value = JSON.parse(localStorage.getItem(STORAGE) ?? "null") as Stored | null;
    return value && value.expiresAt > Date.now() / 1000 + 60 ? value : null;
  } catch {
    return null;
  }
}

async function chainCall(to: string, data: string): Promise<unknown> {
  const response = await fetch("/rpc/chain", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "eth_call",
      params: [{ to, data }, "latest"],
    }),
  });
  const body = (await response.json()) as { result?: unknown };
  return response.ok ? body.result : null;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

$<HTMLAnchorElement>("portal-link").href = issuer;

// ---- 1. sign in, then an automation session ----------------------------------

let client: AutomationClient | null = null;
let options: DcaOption[] = [];

function signedIn(account: string) {
  $("identity-summary").hidden = false;
  $("identity-account").textContent = `${account.slice(0, 8)}…${account.slice(-6)}`;
  $("login").textContent = "Sign in again";
  $("login").classList.replace("button-primary", "button-outline");
  badge("login", "Signed in", "done");
  step("login", "done");
  if (config.mint) {
    $("mint-row").hidden = false;
    void mintBalance(account);
  }
}

async function connect(state: Stored) {
  if (!config.automation) return;
  client = createAutomation({ baseUrl: config.automation.url, token: state.token });
  signedIn(state.account);
  const { automations } = await client.automations();
  options = dcaOptions(automations, config.automation.prefix, chainId);
  if (options.length === 0) {
    show("error", "The automation service offers no DCA plan for this network yet.");
    return;
  }
  $<HTMLSelectElement>("interval").replaceChildren(
    ...options.map(
      (option) => new Option(`Every ${intervalLabel(option.every).replace(/^1 /u, "")}`, option.id),
    ),
  );
  summarize();
  if (state.planId) void watch(state.planId);
  else showForm();
}

async function signIn() {
  const source = $<HTMLButtonElement>("login");
  source.disabled = true;
  source.textContent = "Waiting for sign-in…";
  try {
    // Called inside the click: the popup opens before anything is awaited.
    const login = await loginWithOAAth({ issuer, clientId, redirectUri });
    const response = await fetch("/automation/session", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ idToken: login.idToken }),
    });
    const body = (await response.json()) as {
      token?: string;
      expiresAt?: number;
      account?: `0x${string}`;
      error?: string;
    };
    if (!response.ok || !body.token || !body.expiresAt || !body.account)
      throw Object.assign(new Error("no automation session"), { code: body.error ?? "error" });
    // A plan belongs to its account: keep it only when the same account signs in again.
    const previous = stored();
    const state = stored({
      account: body.account,
      token: body.token,
      expiresAt: body.expiresAt,
      planId: previous?.account === body.account ? previous.planId : null,
    }) as Stored;
    $("feedback").hidden = true;
    await connect(state);
  } catch (error) {
    failed(error);
  }
  source.disabled = false;
  if (!client) source.textContent = "Sign in with OAAth";
}

$("login").addEventListener("click", () => void signIn());

// ---- 2. set a plan, 3. approve once ----------------------------------------------

function selected(): DcaOption | undefined {
  return options.find((option) => option.id === $<HTMLSelectElement>("interval").value);
}

function summarize() {
  const option = selected();
  if (!option) return;
  const buys = $<HTMLInputElement>("buys");
  buys.min = String(option.minBuys);
  buys.max = String(option.maxBuys);
  const perBuy = parseAmount($<HTMLInputElement>("amount").value, SELL_DECIMALS);
  const count = Number(buys.value);
  $("plan-summary").textContent =
    perBuy === null || !Number.isSafeInteger(count) || count < 1
      ? `Enter an amount and 1 to ${option.maxBuys} buys.`
      : `${formatUnits(perBuy * BigInt(count), SELL_DECIMALS)} tUSD in total: ` +
        `${formatUnits(perBuy, SELL_DECIMALS)} tUSD every ${intervalLabel(option.every)}, ` +
        `${count} time${count === 1 ? "" : "s"}. The first buy is about three minutes after you start.` +
        (option.maxBudget === null
          ? ""
          : ` At most ${formatUnits(option.maxBudget, SELL_DECIMALS)} tUSD per plan.`);
}

function showForm() {
  $("plan-form").hidden = false;
  $("watch").hidden = true;
  $("watch-empty").hidden = false;
  badge("plan", "Ready", "current");
  badge("watch", "No plan yet", "");
  step("plan", "current");
  step("approve", "");
  step("watch", "");
}

for (const id of ["amount", "buys", "interval"]) $(id).addEventListener("input", summarize);

const INPUT_MESSAGES: Readonly<Record<PlanInputError["code"], string>> = {
  amount_invalid: "Enter a positive tUSD amount with at most 6 decimals.",
  buys_invalid: "Choose a number of buys within the allowed range.",
  budget_too_large: "That plan is over the per-plan tUSD limit. Lower the amount or buys.",
};

$("plan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const option = selected();
  const state = stored();
  if (!client || !option || !state) {
    show("error", "Sign in again to start a plan.");
    return;
  }
  let request: ReturnType<typeof planRequest>;
  try {
    request = planRequest(
      option,
      $<HTMLInputElement>("amount").value,
      Number($<HTMLInputElement>("buys").value),
      Math.floor(Date.now() / 1000),
      crypto.randomUUID(),
    );
  } catch (error) {
    if (error instanceof PlanInputError) show("error", INPUT_MESSAGES[error.code]);
    else failed(error);
    return;
  }
  const submit = $<HTMLButtonElement>("approve");
  submit.disabled = true;
  submit.textContent = "Waiting for approval…";
  // Opened inside the submit, before anything is awaited, so it is not blocked.
  const popup = window.open("about:blank", "oaath-dca-approval", "popup,width=480,height=760");
  try {
    const plan = await client.create(request);
    stored({ ...state, planId: plan.id });
    const { authorizationUrl } = await client.authorize(plan.id);
    if (!authorizationUrl)
      throw Object.assign(new Error("nothing to approve"), { code: plan.status });
    if (popup) popup.location.href = authorizationUrl;
    else location.assign(authorizationUrl);
    step("plan", "done");
    step("approve", "current");
    badge("plan", "Approve in OAAth", "current");
    show("info", "Review and approve the plan in the OAAth window.");
    void watch(plan.id);
  } catch (error) {
    popup?.close();
    failed(error);
  }
  submit.disabled = false;
  submit.textContent = "Approve in OAAth";
});

// ---- 4. watch every buy ----------------------------------------------------------

let watching: string | null = null;

async function balances(plan: Plan) {
  const option = options.find((entry) => entry.id === plan.automation.id);
  if (!option) return;
  const sell = decodeUint(await chainCall(option.sellToken, balanceOfData(plan.terms.account)));
  const buyToken = decodeAddress(await chainCall(option.executor, BUY_TOKEN_DATA));
  const buy = buyToken
    ? decodeUint(await chainCall(buyToken, balanceOfData(plan.terms.account)))
    : null;
  $("sell-balance").textContent = sell === null ? "–" : formatUnits(sell, SELL_DECIMALS, 2);
  $("buy-balance").textContent = buy === null ? "–" : formatUnits(buy, BUY_DECIMALS, 6);
}

function render(plan: Plan, runs: Parameters<typeof runRows>[0]) {
  $("plan-status").textContent = PLAN_STATUS[plan.status];
  $("plan-details").textContent =
    `Plan ${plan.id}\nAccount ${plan.terms.account}\nDefinition ${plan.automation.id}` +
    (plan.signer ? `\nService session key ${plan.signer}` : "");
  const rows = runRows(
    runs,
    plan.terms.schedule,
    config.explorerTxUrl,
    TERMINAL.includes(plan.status),
  );
  $("runs").replaceChildren(
    ...rows.map((row) => {
      const item = document.createElement("li");
      item.dataset.tone = row.tone;
      const label = document.createElement("strong");
      label.textContent = row.label;
      const time = document.createElement("span");
      time.textContent = row.at ? new Date(row.at * 1000).toLocaleTimeString() : "";
      const status = document.createElement("span");
      status.className = "run-status";
      status.textContent = row.status;
      item.append(label, time, status);
      if (row.transactionUrl) {
        const link = document.createElement("a");
        link.href = row.transactionUrl;
        link.target = "_blank";
        link.rel = "noopener";
        link.textContent = "Arbiscan";
        item.append(link);
      }
      return item;
    }),
  );
  const approved = !["draft", "awaiting_consent"].includes(plan.status);
  if (approved) {
    step("approve", "done");
    step("watch", TERMINAL.includes(plan.status) ? "done" : "current");
    badge("plan", "Approved", "done");
  }
  const bought = rows.filter((row) => row.key.startsWith("buy-") && row.tone === "done").length;
  badge(
    "watch",
    `${bought} of ${plan.terms.schedule.occurrences} bought`,
    TERMINAL.includes(plan.status) ? "done" : "current",
  );
}

async function watch(planId: string) {
  if (!client || watching === planId) return;
  watching = planId;
  $("plan-form").hidden = true;
  $("watch").hidden = false;
  $("watch-empty").hidden = true;
  while (watching === planId && client) {
    try {
      const plan = await client.get(planId);
      render(plan, (await client.runs(planId, { limit: 50 })).runs);
      await balances(plan).catch(() => undefined);
      if (TERMINAL.includes(plan.status)) {
        show(
          plan.status === "completed" ? "success" : "info",
          `The plan is ${PLAN_STATUS[plan.status].toLowerCase()}.`,
        );
        break;
      }
    } catch (error) {
      if ((error as { status?: unknown }).status === 401) {
        client = null;
        show("info", "Your session ended. Sign in again to keep watching this plan.");
      } else failed(error);
      break;
    }
    await sleep(POLL_MS);
  }
  if (watching === planId) watching = null;
}

$("new-plan").addEventListener("click", () => {
  const state = stored();
  if (state) stored({ ...state, planId: null });
  watching = null;
  $("feedback").hidden = true;
  showForm();
});

// ---- mint test tUSD into the account ---------------------------------------------

const MINT_KEY = "oaath-dca:mint-key";
const MINT_LABEL = "Mint 1,000 tUSD";

/** The throwaway key whose Kernel account sends mints. It holds nothing. */
function mintKey(): `0x${string}` {
  try {
    const kept = localStorage.getItem(MINT_KEY);
    if (kept && /^0x[0-9a-fA-F]{64}$/u.test(kept)) return kept as `0x${string}`;
    const key = generatePrivateKey();
    localStorage.setItem(MINT_KEY, key);
    return key;
  } catch {
    return generatePrivateKey();
  }
}

let minter: Promise<ReturnType<typeof createWalletClient>> | null = null;

/** A Cetane client for the throwaway key's counterfactual Kernel v4 account. */
function mintClient() {
  minter ??= (async () => {
    const signer = privateKeyToSigner(mintKey());
    const deployment = kernelDeployment({ chainId });
    const chain = withKernel(
      { ...arbitrum, id: chainId, name: "Arbitrum Sepolia" },
      {
        version: "4",
        factory: deployment.factory,
        root: createAuthorization({
          validator: ECDSA_VALIDATOR,
          owner: signer.address,
          role: "owner",
        }),
      },
    );
    const transport = http(`${location.origin}/rpc/chain`);
    const account = await createAccount({ client: createClient({ chain, transport }) });
    return createWalletClient({
      chain,
      transport,
      relay: http(`${location.origin}/rpc/bundler`),
      account,
      signer,
    });
  })().catch((error: unknown) => {
    minter = null;
    throw error;
  });
  return minter;
}

async function mintBalance(account: string): Promise<bigint | null> {
  if (!config.mint) return null;
  const balance = decodeUint(
    await chainCall(config.mint.token, balanceOfData(account)).catch(() => null),
  );
  $("mint-balance").textContent = balance === null ? "–" : formatUnits(balance, SELL_DECIMALS, 2);
  return balance;
}

$("mint").addEventListener("click", async () => {
  const state = stored();
  if (!config.mint || !state) {
    show("error", "Sign in again to mint test tUSD.");
    return;
  }
  const source = $<HTMLButtonElement>("mint");
  const link = $<HTMLAnchorElement>("mint-link");
  source.disabled = true;
  source.textContent = "Minting…";
  $("mint-done").hidden = true;
  $("feedback").hidden = true;
  try {
    const before = await mintBalance(state.account);
    const client = await mintClient();
    // The relay pays the gas: the operation carries zero fees. Sent once, never resent.
    const { id } = await client.sendCalls({
      calls: [mintCall(config.mint.token, state.account, config.mint.amount)],
      maxFeePerGas: 0n,
      maxPriorityFeePerGas: 0n,
    });
    // Polling stays well inside the Worker's per-IP budget.
    const receipt = await waitForTransactionReceipt(client, {
      hash: id,
      pollingInterval: 2_000,
      timeout: 90_000,
    });
    if (receipt.status !== "success")
      throw Object.assign(new Error("mint reverted"), { code: "mint_reverted" });
    link.hidden = !config.explorerTxUrl;
    link.href = `${config.explorerTxUrl ?? ""}${receipt.transactionHash}`;
    $("mint-done").hidden = false;
    // The chain proxy's reads can trail inclusion briefly.
    for (let read = 0; read < 5; read += 1) {
      if ((await mintBalance(state.account)) !== before) break;
      await sleep(2_000);
    }
  } catch (error) {
    failed(error);
  }
  source.disabled = false;
  source.textContent = MINT_LABEL;
});

// ---- startup ---------------------------------------------------------------------

$("startup-message").hidden = true;
if (!config.automation) {
  show("error", "This app isn't configured yet: the automation service credential is missing.");
} else {
  $<HTMLButtonElement>("login").disabled = false;
  const state = stored();
  if (state) void connect(state).catch(failed);
}
