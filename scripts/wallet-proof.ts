import assert from "node:assert/strict";
import { createLocalOwnerAnvilFixture } from "@oaath/testing/anvil";
import { IDBFactory } from "fake-indexeddb";
import { createWalletOwner } from "../.local/consumer/node_modules/@oaath/automation/dist/wallet.js";

const fixture = await createLocalOwnerAnvilFixture({
	chainId: 31337,
	kernelVersion: "0.4.0",
	wallet: "local",
});
globalThis.indexedDB = new IDBFactory();
let typed = 0;
const wallet = createWalletOwner({
	chains: await fixture.chainDescriptors(),
	provider: {
		async request({ method, params }) {
			if (method === "eth_chainId") return "0x7a69";
			if (method === "eth_requestAccounts")
				return [fixture.wallet.account!.address];
			if (method === "personal_sign")
				return fixture.wallet.signMessage({
					message: { raw: params![0] as `0x${string}` },
				});
			if (method === "eth_signTypedData_v4") {
				const value = JSON.parse(params![1] as string);
				assert.ok(value.types.EIP712Domain);
				typed++;
				return fixture.wallet.signTypedData(value);
			}
			throw Error("unexpected_wallet_method");
		},
	},
});
try {
	const data = {
		domain: { name: "Automation test", version: "1", chainId: 31337 },
		types: { Consent: [{ name: "value", type: "uint256" }] },
		primaryType: "Consent",
		message: { value: "1" },
	};
	const review = {
		commitment: `0x${"cd".repeat(32)}`,
		terms: { account: fixture.address, chainId: 31337 },
		consent: data,
		permission: data,
		setupCalls: [
			{ target: fixture.wallet.account!.address, data: "0x", value: "1" },
		],
	} as never;
	const result = await wallet.approve(review);
	assert.ok(result.setupOperation);
	assert.equal(fixture.bundlerSubmissionCount, 1);
	assert.equal(typed, 2);
	await fixture.mine();
	assert.deepEqual(await wallet.approve(review), result);
	assert.equal(fixture.bundlerSubmissionCount, 1);
	console.log(
		"Packed EIP-1193 wallet adapter signed complete typed data and submitted real Kernel owner setup once; repeat approval reused its journal.",
	);
} finally {
	await wallet.close();
	await fixture.close();
}
