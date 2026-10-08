import { expect, test } from "bun:test";
import {
	apiPath,
	ENTRY_POINT,
	loginMessage,
	rpcAllowed,
} from "../examples/dca/hosted/policy.js";

const account = `0x${"11".repeat(20)}`;
test("public gateway exposes plan actions, never application credentials or local owner fixtures", () => {
	expect(apiPath("/v1/plans", "POST")).toBe(true);
	expect(apiPath(`/v1/plans/0x${"22".repeat(32)}/approve`, "POST")).toBe(true);
	for (const path of [
		"/v1/sessions",
		"/v1/application",
		"/demo/approve",
		"/v1/plans/../sessions",
	])
		expect(apiPath(path, "POST")).toBe(false);
});
test("bundler sends are tied to the authenticated account and EntryPoint", () => {
	const body = {
		jsonrpc: "2.0",
		method: "eth_sendUserOperation",
		params: [{ sender: account }, ENTRY_POINT],
	};
	expect(rpcAllowed(body, account, true)).toBe(true);
	expect(rpcAllowed(body, `0x${"33".repeat(20)}`, true)).toBe(false);
	expect(
		rpcAllowed(
			{ ...body, params: [{ sender: account }, account] },
			account,
			true,
		),
	).toBe(false);
	expect(rpcAllowed([body], account, true)).toBe(false);
	expect(
		rpcAllowed({ ...body, method: "eth_sendRawTransaction" }, account, false),
	).toBe(false);
});
test("wallet login binds domain, chain, owner, nonce and expiry", () => {
	const message = loginMessage(account, "nonce", 1800000000);
	for (const part of [
		"https://dca.taek.tech",
		"421614",
		account,
		"nonce",
		"2027-",
	])
		expect(message).toContain(part);
	expect(loginMessage(account, "another", 1800000000)).not.toBe(message);
});
