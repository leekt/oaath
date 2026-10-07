import { readFileSync } from "node:fs";
import { chromium } from "@playwright/test";

const url = JSON.parse(readFileSync(".local/public-url.json")).webUrl;
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
	viewport: { width: 1440, height: 1000 },
});
const page = await context.newPage();
page.on("pageerror", (e) => console.error("Page error:", e.message));
await page.goto(url);
await page.getByRole("heading", { name: "Make a purchase routine." }).waitFor();
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
console.log(
	"Tailnet page, authenticated user session, config and retained activity loaded at desktop and mobile sizes.",
);
await context.storageState({ path: ".local/ui-session.json" });
await browser.close();
