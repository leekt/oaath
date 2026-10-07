import { keccak256 } from "cetane/utils";
import { createMoesi, type MoesiObservationAdapter } from "moesi";
import { config, factory, rpc } from "./chain.js";

/** Read-only Cetane adapter: OAAth remains the only purchase submission owner. */
const observer: MoesiObservationAdapter = {
	async captureSnapshot(chainId) {
		if (chainId !== config.chainId) throw new Error("chain_mismatch");
		const block = await rpc("eth_getBlockByNumber", ["finalized", false]);
		return {
			blockNumber: BigInt(block.number).toString(),
			blockHash: block.hash,
		};
	},
	async readCode({ address, snapshot }) {
		return rpc("eth_getCode", [
			address,
			{ blockHash: snapshot.blockHash, requireCanonical: true },
		]);
	},
	async readCall({ caller, target, data, snapshot }) {
		return rpc("eth_call", [
			{ from: caller, to: target, data },
			{ blockHash: snapshot.blockHash, requireCanonical: true },
		]);
	},
	async readStorage({ address, slot, snapshot }) {
		return rpc("eth_getStorageAt", [
			address,
			slot,
			{ blockHash: snapshot.blockHash, requireCanonical: true },
		]);
	},
	async checkBlockAncestry({ ancestor, descendant }) {
		if (BigInt(ancestor.blockNumber) > BigInt(descendant.blockNumber))
			return false;
		const a = await rpc("eth_getBlockByNumber", [
			`0x${BigInt(ancestor.blockNumber).toString(16)}`,
			false,
		]);
		const d = await rpc("eth_getBlockByNumber", [
			`0x${BigInt(descendant.blockNumber).toString(16)}`,
			false,
		]);
		return a.hash === ancestor.blockHash && d.hash === descendant.blockHash;
	},
};
export async function verifyDeployment() {
	const moesi = createMoesi({ observer });
	const plan = await moesi.plan({
		chains: [config.chainId],
		manifest: {
			version: "moesi.manifest/v6",
			contracts: [
				{
					kind: "external",
					id: "dca-factory",
					address: config.factory,
					expectedRuntimeCodeHash: keccak256(factory.deployedBytecode.object),
					checks: [],
					storageChecks: [],
				},
			],
		},
	});
	const result = await moesi.verify({ plan });
	if (result.status !== "converged")
		throw new Error("executor_implementation_unverified");
	return { planId: plan.planId, status: result.status };
}
