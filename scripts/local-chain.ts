/** Local-only chain and owner fixture. No inherited provider settings or production authority. */

import { createHash, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { userInfo } from "node:os";
import { kernelDeployment } from "@oaath/sdk/kernel";
import { createLocalOwnerAnvilFixture } from "@oaath/testing/anvil";
import { createPublicClient, createWalletClient, type Hex, http } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

process.on("uncaughtException", () => {
	console.error("local_fixture_failed");
	process.exit(1);
});
process.on("unhandledRejection", () => {
	console.error("local_fixture_failed");
	process.exit(1);
});
const root = new URL("../", import.meta.url);
const artifact = (path: string) =>
	JSON.parse(readFileSync(new URL(path, root), "utf8"));
const fixture = await createLocalOwnerAnvilFixture({
	chainId: 31337,
	kernelVersion: "0.4.0",
	wallet: "local",
});
const client = createPublicClient({
	transport: http(fixture.rpcUrl, { retryCount: 0 }),
});
const signer = privateKeyToAccount(generatePrivateKey());
const deployer = signer.address;
await client.request({
	method: "anvil_setBalance",
	params: [deployer, "0x3635c9adc5dea00000"],
} as never);
const wallet = createWalletClient({
	account: signer,
	transport: http(fixture.rpcUrl, { retryCount: 0 }),
});
async function tx(to: Hex, data: Hex) {
	const h = await wallet.sendTransaction({
		account: signer,
		to,
		data,
		chain: null,
		gas: 15_000_000n,
	});
	const r = await client.waitForTransactionReceipt({ hash: h });
	if (r.status !== "success") throw new Error("fixture_transaction_failed");
	return r;
}
async function deploy(a: any, args: unknown[] = []) {
	const h = await wallet.deployContract({
		abi: a.abi,
		bytecode: typeof a.bytecode === "string" ? a.bytecode : a.bytecode.object,
		args,
		account: signer,
		chain: null,
		gas: 25_000_000n,
	});
	const r = await client.waitForTransactionReceipt({ hash: h });
	if (!r.contractAddress || r.status !== "success")
		throw new Error("fixture_deployment_failed");
	return r.contractAddress.toLowerCase() as Hex;
}
const { encodeFunctionData } = await import("viem");
const token = artifact("vendor/FixtureToken.json"),
	feed = artifact("vendor/FixtureFeed.json");
const sellToken = await deploy(token, [6]),
	buyToken = await deploy(token, [18]);
const sellFeed = await deploy(feed, [100_000_000n]),
	buyFeed = await deploy(feed, [200_000_000_000n]);
const v3 = artifact(
	"node_modules/@uniswap/v3-core/artifacts/contracts/UniswapV3Factory.sol/UniswapV3Factory.json",
);
const routerA = artifact(
	"node_modules/@uniswap/v3-periphery/artifacts/contracts/SwapRouter.sol/SwapRouter.json",
);
const managerA = artifact(
	"node_modules/@uniswap/v3-periphery/artifacts/contracts/NonfungiblePositionManager.sol/NonfungiblePositionManager.json",
);
const swapFactory = await deploy(v3),
	router = await deploy(routerA, [swapFactory, buyToken]);
const manager = await deploy(managerA, [
	swapFactory,
	buyToken,
	"0x0000000000000000000000000000000000000000",
]);
for (const [address, amount] of [
	[sellToken, 2_000_000n * 10n ** 6n],
	[buyToken, 1_000n * 10n ** 18n],
] as const) {
	await tx(
		address,
		encodeFunctionData({
			abi: token.abi,
			functionName: "mint",
			args: [deployer, amount],
		}),
	);
	await tx(
		address,
		encodeFunctionData({
			abi: token.abi,
			functionName: "approve",
			args: [manager, amount],
		}),
	);
}
const [token0, token1] = [sellToken, buyToken].sort() as [Hex, Hex];
function sqrt(n: bigint) {
	let x = n,
		y = (x + 1n) / 2n;
	while (y < x) {
		x = y;
		y = (x + n / x) / 2n;
	}
	return x;
}
const ratio = sellToken === token0 ? 500_000_000n : 1n;
const denom = sellToken === token0 ? 1n : 500_000_000n;
await tx(
	manager,
	encodeFunctionData({
		abi: managerA.abi,
		functionName: "createAndInitializePoolIfNecessary",
		args: [token0, token1, 3000, sqrt((ratio << 192n) / denom)],
	}),
);
await tx(
	manager,
	encodeFunctionData({
		abi: managerA.abi,
		functionName: "mint",
		args: [
			{
				token0,
				token1,
				fee: 3000,
				tickLower: -887220,
				tickUpper: 887220,
				amount0Desired:
					sellToken === token0 ? 1_000_000n * 10n ** 6n : 500n * 10n ** 18n,
				amount1Desired:
					sellToken === token0 ? 500n * 10n ** 18n : 1_000_000n * 10n ** 6n,
				amount0Min: 0n,
				amount1Min: 0n,
				recipient: deployer,
				deadline: BigInt(Math.floor(Date.now() / 1000) + 3600),
			},
		],
	}),
);
const factory = await deploy(artifact("vendor/DcaFactory.json"));
await tx(
	sellToken,
	encodeFunctionData({
		abi: token.abi,
		functionName: "mint",
		args: [fixture.address, 10_000n * 10n ** 6n],
	}),
);
await fixture.mine();
const chainDescriptors = await fixture.chainDescriptors();
const tokenSecret = randomBytes(32).toString("hex"),
	runtimeToken = randomBytes(32).toString("hex"),
	ownerToken = randomBytes(32).toString("hex");
const config = {
	chainId: 31337,
	rpcUrl: fixture.rpcUrl,
	chainDescriptors,
	account: fixture.address.toLowerCase(),
	owner: fixture.wallet.account?.address.toLowerCase(),
	sellToken,
	buyToken,
	sellFeed,
	buyFeed,
	router,
	swapFactory,
	poolFee: 3000,
	factory,
	ecdsaValidator: kernelDeployment({ chainId: 31337, kernelVersion: "0.3.3" })
		.ecdsaValidator,
	maxPriceAgeSeconds: 3600,
	maxFeePerGas: "100000000000",
	maxGasCost: "10000000000000000",
	origin: "http://leekt-macmini.tail45c85e.ts.net:4317",
};
writeFileSync(
	new URL(".local/deployment.json", root),
	JSON.stringify(config, null, 2),
	{ mode: 0o600 },
);
writeFileSync(
	new URL(".local/environment.json", root),
	JSON.stringify({
		AUTOMATION_DATABASE_URL:
			process.env.AUTOMATION_DATABASE_URL ??
			`postgres://${encodeURIComponent(userInfo().username)}@127.0.0.1:55437/dca`,
		AUTOMATION_CONFIG: new URL(".local/deployment.json", root).pathname,
		AUTOMATION_APPLICATION_HASHES: JSON.stringify([
			["local-demo", createHash("sha256").update(tokenSecret).digest("hex")],
		]),
		AUTOMATION_API_TOKEN: tokenSecret,
		AUTOMATION_RUNTIME_TOKEN: runtimeToken,
		AUTOMATION_SEAL_KEY: randomBytes(32).toString("hex"),
		AUTOMATION_RUNTIME_URL: "http://127.0.0.1:4318",
		AUTOMATION_RUNTIME_PORT: "4318",
		DCA_OWNER_TOKEN: ownerToken,
		AUTOMATION_ALLOWED_HOSTS:
			"127.0.0.1:4317,localhost:4317,100.89.250.34:4317,leekt-macmini.tail45c85e.ts.net:4317",
	}),
	{ mode: 0o600 },
);
const server = createServer(async (req, res) => {
	try {
		if (req.headers.authorization !== `Bearer ${ownerToken}`) {
			res.writeHead(401);
			res.end();
			return;
		}
		const chunks = [];
		let size = 0;
		for await (const chunk of req) {
			size += chunk.length;
			if (size > 65536) throw new Error("request_too_large");
			chunks.push(chunk);
		}
		const body = chunks.length
			? JSON.parse(Buffer.concat(chunks).toString())
			: {};
		let value: unknown;
		if (req.url === "/sign")
			value = { signature: await fixture.wallet.signTypedData(body) };
		else if (req.url === "/calls") {
			const owner = await fixture.openClient();
			const op = await owner
				.account(fixture.address)
				.owner(fixture.wallet)
				.sendCalls({ chain: fixture.chainId, calls: body.calls });
			await fixture.mine();
			const result = await op.wait({ attempts: 3 });
			value = { operationId: op.id, outcome: result };
		} else if (req.url === "/mine") {
			await fixture.mine();
			value = { ok: true };
		} else if (req.url === "/stats")
			value = {
				submissions: fixture.bundlerSubmissionCount,
				rpc: fixture.rpcRequestCount,
				signatures: fixture.signatureCount,
			};
		else throw new Error("route_missing");
		res.writeHead(200, { "content-type": "application/json" });
		res.end(
			JSON.stringify(value, (_, v) =>
				typeof v === "bigint" ? v.toString() : v,
			),
		);
	} catch {
		res.writeHead(409);
		res.end(JSON.stringify({ error: "fixture_action_failed" }));
	}
});
server.listen(4319, "127.0.0.1");
console.log(
	"Owned Anvil, real Kernel v4, Uniswap v3 and local owner fixture ready",
);
const stop = async () => {
	server.close();
	await fixture.close();
	process.exit(0);
};
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
