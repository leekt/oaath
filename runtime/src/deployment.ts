import { keccak256 } from "cetane/utils";
import { createMoesi } from "moesi";
import { createCetaneObserver } from "moesi/cetane";
import { budget, config, factory, stats } from "./chain.js";

export async function verifyDeployment() {
	const observer = createCetaneObserver({
		chains: {
			[config.chainId]: { rpcUrls: [config.rpcUrl], pin: "finalized" },
		},
		admitRpc({ methods }) {
			budget.take(methods.length);
			for (const method of methods) {
				stats.methods[method] = (stats.methods[method] ?? 0) + 1;
			}
			return true;
		},
	});
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
