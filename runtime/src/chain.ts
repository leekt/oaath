import { readFileSync } from "node:fs";
import { createCetaneChainPorts } from "@oaath/sdk/cetane";
import type { Address, Hex } from "cetane";
import { http } from "cetane";
import { decodeFunctionResult, encodeFunctionData } from "cetane/utils";
import { RpcBudget } from "./budget.js";
export const config = JSON.parse(
	readFileSync(process.env.AUTOMATION_CONFIG!, "utf8"),
);
export const factory = JSON.parse(
	readFileSync(
		new URL("../../vendor/DcaFactory.json", import.meta.url),
		"utf8",
	),
);
export const executor = JSON.parse(
	readFileSync(
		new URL("../../vendor/DcaExecutor.json", import.meta.url),
		"utf8",
	),
);
export const stats = { methods: {} as Record<string, number>, submissions: 0 };
export const budget = new RpcBudget();
const upstream = http(config.rpcUrl, { timeout: 8000 });
export async function rpc(
	method: string,
	params: readonly unknown[] = [],
): Promise<any> {
	budget.take();
	stats.methods[method] = (stats.methods[method] ?? 0) + 1;
	return upstream.request({ method, params } as never);
}
export async function read(
	address: Address,
	abi: any,
	functionName: string,
	args: readonly unknown[] = [],
	block: unknown = "latest",
): Promise<any> {
	const data = encodeFunctionData({ abi, functionName, args } as never);
	const result = await rpc("eth_call", [{ to: address, data }, block]);
	return decodeFunctionResult({ abi, functionName, data: result } as never);
}
let chainPorts: ReturnType<typeof createCetaneChainPorts>[number] | undefined;
let portsWindow = -1;
export function ports() {
	if (!chainPorts || portsWindow !== budget.windowId) {
		portsWindow = budget.windowId;
		chainPorts = createCetaneChainPorts(config.chainDescriptors, {
			maxRequests: 20000,
			maxConcurrency: 16,
			retry: { attempts: 2, delayMs: 100 },
			timeoutMs: 8000,
			fetch: async (request) => {
				budget.take();
				const body = JSON.parse(await request.clone().text());
				stats.methods[body.method] = (stats.methods[body.method] ?? 0) + 1;
				if (body.method === "eth_sendUserOperation") stats.submissions++;
				return fetch(request);
			},
		})[0]!;
	}
	return chainPorts;
}
export const tokenAbi = [
	{
		type: "function",
		name: "allowance",
		stateMutability: "view",
		inputs: [
			{ name: "owner", type: "address" },
			{ name: "spender", type: "address" },
		],
		outputs: [{ type: "uint256" }],
	},
	{
		type: "function",
		name: "approve",
		stateMutability: "nonpayable",
		inputs: [
			{ name: "spender", type: "address" },
			{ name: "amount", type: "uint256" },
		],
		outputs: [{ type: "bool" }],
	},
] as const;
export const encode = (
	abi: any,
	functionName: string,
	args: readonly unknown[] = [],
) => encodeFunctionData({ abi, functionName, args } as never) as Hex;
