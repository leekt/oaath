import { readFileSync } from "node:fs";
import { chromium, expect } from "@playwright/test";

const url = JSON.parse(readFileSync(".local/public-url.json")).webUrl;
const browser = await chromium.launch();
const context = await browser.newContext({
	viewport: { width: 1440, height: 1000 },
});
const page = await context.newPage();
try {
	await page.goto(url);
	await page.getByLabel("Amount each day").waitFor();
	await page.screenshot({
		path: ".impeccable/review/desktop.png",
		fullPage: true,
	});
	await page.setViewportSize({ width: 390, height: 844 });
	await page.screenshot({
		path: ".impeccable/review/mobile.png",
		fullPage: true,
	});
	await page.getByLabel("Amount each day").fill("0");
	await page
		.getByRole("button", { name: "Review automation", exact: true })
		.click();
	await expect(page.getByRole("alert")).toContainText(
		"Check the amount and schedule",
	);
	await expect(page.getByLabel("Amount each day")).toBeEnabled();
	expect(
		await page.evaluate(
			() =>
				Object.keys(sessionStorage).filter((k) =>
					k.startsWith("automation.create:"),
				).length,
		),
	).toBe(0);
	await page.getByLabel("Amount each day").fill("12.5");
	await page.getByLabel("Scheduled opportunities").fill("7");
	await page
		.getByRole("button", { name: "Review automation", exact: true })
		.click();
	await expect(
		page.getByRole("heading", { name: "Review your automation" }),
	).toBeFocused();
	await expect(page.getByText("87.5 USDC", { exact: true })).toBeVisible();
	const animation = await page
		.locator(".automation-review-enter")
		.evaluate((e) => getComputedStyle(e).animationName);
	expect(animation).toBe("automation-review-enter");
	await page.waitForTimeout(250);
	await page.setViewportSize({ width: 1440, height: 1000 });
	await page.screenshot({
		path: ".impeccable/review/review-desktop.png",
		fullPage: true,
	});
	await page.setViewportSize({ width: 390, height: 844 });
	await page.screenshot({
		path: ".impeccable/review/review-mobile.png",
		fullPage: true,
	});
	await page.emulateMedia({ reducedMotion: "reduce" });
	expect(
		await page
			.locator(".automation-review-enter")
			.evaluate((e) => getComputedStyle(e).animationName),
	).toBe("none");
	await page.getByRole("button", { name: "All automations" }).click();
	await expect(
		page.getByRole("heading", { name: "Make a purchase routine." }),
	).toBeFocused();
	console.log(
		"Review fixes proved: rejected create editable with cleared intent; heading focus in both directions; visible opacity transition and reduced-motion override.",
	);
} finally {
	await browser.close();
}
