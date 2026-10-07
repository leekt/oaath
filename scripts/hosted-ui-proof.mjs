/** Browser-only state regressions. Every API request is intercepted; no chain calls. */
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { chromium } from "@playwright/test";

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
	viewport: { width: 1440, height: 1000 },
});
const page = await context.newPage();
const owner = `0x${"12".repeat(20)}`,
	account = `0x${"34".repeat(20)}`;
const hash = `0x${"56".repeat(32)}`;
const session = {
	owner,
	account,
	expiresAt: 1900000000,
	deployment: { factory: owner, data: "0x" },
	chains: {
		421614: {
			publicRpcUrls: ["https://dca.taek.tech/api/rpc/read"],
			bundlerUrl: "https://dca.taek.tech/api/rpc/bundler",
		},
	},
};
let signedIn = false;
await page.route("**/api/**", async (route) => {
	const path = new URL(route.request().url()).pathname;
	let status = 200,
		body;
	if (path === "/api/session") {
		status = signedIn ? 200 : 401;
		body = signedIn ? session : { error: "wallet_login_required" };
	} else if (path === "/api/login/challenge")
		body = { nonce: "fixture", message: "Local UI fixture login" };
	else if (path === "/api/login/complete") {
		signedIn = true;
		body = session;
	} else if (path === "/api/logout") {
		signedIn = false;
		body = { signedOut: true };
	} else if (path === "/api/account")
		body = { deployed: false, eth: "0", usdc: "0", sellToken: owner };
	else {
		status = 403;
		body = { error: "fixture_method_denied" };
	}
	await route.fulfill({
		status,
		contentType: "application/json",
		body: JSON.stringify(body),
	});
});
await page.addInitScript(
	({ owner, hash }) => {
		window.walletSends = 0;
		window.ethereum = {
			on() {},
			removeListener() {},
			async request({ method }) {
				if (method === "eth_chainId") return "0x66eee";
				if (method === "wallet_switchEthereumChain") return null;
				if (["eth_accounts", "eth_requestAccounts"].includes(method))
					return [owner];
				if (method === "personal_sign") return `0x${"11".repeat(65)}`;
				if (method === "eth_sendTransaction") {
					window.walletSends++;
					return hash;
				}
				throw Error("fixture_method_denied");
			},
		};
	},
	{ owner, hash },
);
await page.goto("https://dca.taek.tech", { waitUntil: "networkidle" });
await page.getByRole("button", { name: "Connect wallet", exact: true }).click();
const heading = page.getByRole("heading", {
	level: 1,
	name: "Your testnet account",
});
await heading.waitFor();
assert.equal(await heading.evaluate((e) => e === document.activeElement), true);
await page.getByRole("button", { name: "Set up account", exact: true }).click();
await page
	.getByRole("status")
	.filter({ hasText: "Account setup requested" })
	.waitFor();
assert.equal(
	await page
		.getByRole("button", { name: "Set up account", exact: true })
		.count(),
	0,
);
assert.equal(await page.evaluate(() => window.walletSends), 1);
await page
	.getByRole("button", { name: "Refresh account", exact: true })
	.click();
assert.equal(await page.evaluate(() => window.walletSends), 1);
await page.reload({ waitUntil: "networkidle" });
await page
	.getByRole("status")
	.filter({ hasText: "Account setup requested" })
	.waitFor();
assert.equal(
	await page
		.getByRole("button", { name: "Set up account", exact: true })
		.count(),
	0,
);
assert.equal(
	await page
		.getByRole("link", { name: "View setup transaction" })
		.getAttribute("href"),
	`https://sepolia.arbiscan.io/tx/${hash}`,
);
mkdirSync(".impeccable/review", { recursive: true });
await page.screenshot({
	path: ".impeccable/review/hosted-pending-setup.png",
	fullPage: true,
});
await page.setViewportSize({ width: 390, height: 844 });
await page.screenshot({
	path: ".impeccable/review/hosted-pending-setup-mobile.png",
	fullPage: true,
});
await page.getByRole("button", { name: "Disconnect", exact: true }).click();
const home = page.getByRole("heading", {
	level: 1,
	name: "Your purchase, on a schedule.",
});
await home.waitFor();
assert.equal(await home.evaluate((e) => e === document.activeElement), true);
console.log(
	"Pending setup survives reload without another send; connect/disconnect headings receive focus. No chain RPC used.",
);
await browser.close();
