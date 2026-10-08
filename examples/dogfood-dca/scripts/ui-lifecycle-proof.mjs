import { readFileSync } from "node:fs";
import { chromium, expect } from "@playwright/test";

const url = JSON.parse(readFileSync(".local/public-url.json")).webUrl;
const browser = await chromium.launch();
const context = await browser.newContext({
	viewport: { width: 1440, height: 1000 },
});
const page = await context.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));
await page.goto(url);
await page.getByLabel("Amount each day").fill("12.5");
await page.getByLabel("Scheduled opportunities").fill("7");
await expect(page.getByText("87.5 USDC", { exact: true })).toBeVisible();
await page
	.getByRole("button", { name: "Review automation", exact: true })
	.click();
await page.getByRole("heading", { name: "Review your automation" }).waitFor();
await expect(page.getByText("87.5 USDC", { exact: true })).toBeVisible();
await expect(
	page.getByText("One session key for your user. OAAth holds"),
).toBeVisible();
await page.screenshot({
	path: ".impeccable/review/review-desktop.png",
	fullPage: true,
});
await page.setViewportSize({ width: 390, height: 844 });
await page.screenshot({
	path: ".impeccable/review/review-mobile.png",
	fullPage: true,
});
await page.getByText("Account, price source & onchain terms").click();
await expect(
	page.getByRole("heading", { name: "Owner setup transactions" }),
).toBeVisible();
await page.getByRole("button", { name: "Approve with wallet" }).click();
await page
	.getByText("Your automation is active.", { exact: true })
	.waitFor({ timeout: 45000 });
await page.getByRole("button", { name: "Pause", exact: true }).click();
await expect(page.getByText("Paused", { exact: true })).toBeVisible();
await page.getByRole("button", { name: "Resume", exact: true }).click();
await expect(page.getByText("Active", { exact: true })).toBeVisible();
await page.getByRole("button", { name: "Cancel automation" }).click();
await page.getByRole("button", { name: "Keep automation" }).click();
await expect(page.getByRole("alertdialog")).not.toBeVisible();
await page.getByRole("button", { name: "Cancel automation" }).click();
await page.getByRole("button", { name: "Stop & cancel" }).click();
await page
	.getByText(
		"Cancellation submitted. Its onchain effects are being confirmed.",
		{ exact: true },
	)
	.waitFor({ timeout: 45000 });
await expect(page.getByText("Onchain cancellation confirmed.")).toBeVisible({
	timeout: 75000,
});
await page.reload();
await page.getByRole("button", { name: /12.5 USDC/ }).click();
await expect(page.getByText("Cancelled", { exact: true })).toBeVisible();
if (errors.length) throw Error(errors.join(";"));
console.log(
	"Tailnet UI: exact total and owner terms, real setup approval, pause/resume, cancel confirmation, reload recovery; no browser errors.",
);
await browser.close();
