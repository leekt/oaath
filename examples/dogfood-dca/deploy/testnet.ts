/** Explicit operator command: bounded Arbitrum Sepolia deployment, never part of tests. */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { type Hex, http } from "cetane";
import { privateKeyToSigner } from "cetane/accounts";
import { signEvmTransaction } from "cetane/execution/evm";
import { concatHex, keccak256 } from "cetane/utils";

if (process.env.DCA_TESTNET_DEPLOY !== "421614")
	throw Error("explicit_testnet_deployment_required");
const load = (path: string) => JSON.parse(readFileSync(path, "utf8"));
const root = ".local/hosting";
const signer = privateKeyToSigner(
	load(`${root}/testnet-deployer.json`).privateKey,
);
const transport = http("https://sepolia-rollup.arbitrum.io/rpc", {
	timeout: 12000,
});
let count = 0;
async function rpc(method: string, params: unknown[] = []): Promise<any> {
	if (++count > 100) throw Error("deployment_rpc_budget_exhausted");
	return transport.request({ method, params } as never);
}
if ((await rpc("eth_chainId")) !== "0x66eee") throw Error("chain_mismatch");
const deployer = "0x4e59b44847b379578588920ca78fbf26c0b4956c" as Hex;
if (
	keccak256(await rpc("eth_getCode", [deployer, "latest"])) !==
	"0x2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989"
)
	throw Error("singleton_deployer_mismatch");
const factory = load("vendor/DcaFactory.json");
const salt = `0x${"00".repeat(32)}` as Hex;
const factoryAddress = `0x${keccak256(concatHex(["0xff", deployer, salt, keccak256(factory.bytecode.object)])).slice(-40)}`;
const validity = load(
	".local/oaath-automation/packages/contracts/artifacts/OaathKernelV4ValidityPolicy.json",
).deployment;
const journalPath = `${root}/deployment-journal.json`;
const journal: Record<string, any> = existsSync(journalPath)
	? load(journalPath)
	: {};
const save = () =>
	writeFileSync(journalPath, JSON.stringify(journal, null, 2), { mode: 0o600 });
for (const item of [
	{
		name: "validity",
		address: validity.expectedAddress,
		hash: validity.runtimeCodeHash,
		data: validity.deploymentInput,
	},
	{
		name: "dcaFactory",
		address: factoryAddress,
		hash: keccak256(factory.deployedBytecode.object),
		data: concatHex([salt, factory.bytecode.object]),
	},
]) {
	let code = await rpc("eth_getCode", [item.address, "latest"]);
	if (code !== "0x") {
		if (keccak256(code) !== item.hash) throw Error("deployment_code_mismatch");
		console.log(`${item.name}: verified existing ${item.address}`);
		continue;
	}
	if (!journal[item.name]) {
		const nonce = BigInt(
			await rpc("eth_getTransactionCount", [signer.address, "pending"]),
		);
		const price = BigInt(await rpc("eth_gasPrice"));
		if (price > 500_000_000n) throw Error("deployment_fee_ceiling");
		const estimate = BigInt(
			await rpc("eth_estimateGas", [
				{ from: signer.address, to: deployer, data: item.data },
			]),
		);
		const gas = (estimate * 12n) / 10n;
		if (gas * price * 2n > 2_000_000_000_000_000n)
			throw Error("deployment_cost_ceiling");
		const signed = await signEvmTransaction({
			signer,
			transaction: {
				type: "eip1559",
				chainId: 421614,
				nonce,
				gas,
				to: deployer,
				data: item.data,
				maxFeePerGas: price * 2n,
				maxPriorityFeePerGas: 0n,
			},
		});
		journal[item.name] = {
			address: item.address,
			hash: signed.hash,
			raw: signed.serializedTransaction,
			attempted: false,
		};
		save();
	}
	const entry = journal[item.name];
	if (entry.address !== item.address) throw Error("deployment_intent_conflict");
	if (!entry.attempted) {
		entry.attempted = true;
		save();
		const hash = await rpc("eth_sendRawTransaction", [entry.raw]);
		if (hash !== entry.hash) throw Error("deployment_hash_mismatch");
	}
	for (let n = 0; n < 25; n++) {
		const receipt = await rpc("eth_getTransactionReceipt", [entry.hash]);
		if (receipt) {
			if (receipt.status !== "0x1") throw Error("deployment_reverted");
			entry.blockHash = receipt.blockHash;
			save();
			break;
		}
		await new Promise((r) => setTimeout(r, 2000));
	}
	code = await rpc("eth_getCode", [item.address, "latest"]);
	if (keccak256(code) !== item.hash) throw Error("deployment_unresolved");
	console.log(`${item.name}: deployed and verified ${item.address}`);
}
const config = load("deploy/arbitrum-sepolia.json");
const project = load(`${root}/zerodev.json`).projectId;
config.factory = factoryAddress;
config.rpcBudget = 3000;
config.chainDescriptors = {
	421614: {
		publicRpcUrls: [config.rpcUrl],
		bundlerUrl: `https://rpc.zerodev.app/api/v3/${project}/chain/421614`,
	},
};
writeFileSync(`${root}/deployment.json`, JSON.stringify(config, null, 2), {
	mode: 0o600,
});
console.log(`Deployment complete; RPC methods used: ${count}/100`);
