import { createOAAth, type OaathOwnerOptions } from "@oaath/sdk";
import { createOwnerApproval, type OwnerApprovalOptions } from "./approval.js";
import {
	type CancellationRecord,
	createOwnerCancellation,
} from "./cancellation.js";
import { type Address, AutomationError } from "./index.js";
import { createApprovalJournal, createBrowserJournal } from "./journal.js";
export interface WalletProvider {
	request(input: {
		method: string;
		params?: readonly unknown[];
	}): Promise<unknown>;
}
/** Uses the connected owner wallet and OAAth's durable browser Operation journal. */
export function createWalletOwner(options: {
	provider: WalletProvider;
	chains: OaathOwnerOptions["chains"];
	journal?: OwnerApprovalOptions["journal"];
}) {
	const journal = options.journal ?? createApprovalJournal();
	const client = createOAAth({ chains: options.chains });
	const request = options.provider.request.bind(options.provider);
	async function owner(chainId: number) {
		if (
			BigInt(String(await request({ method: "eth_chainId" }))) !==
			BigInt(chainId)
		)
			throw new AutomationError("wallet_chain_mismatch", 0);
		const accounts = await request({ method: "eth_requestAccounts" });
		if (
			!Array.isArray(accounts) ||
			typeof accounts[0] !== "string" ||
			!/^0x[0-9a-fA-F]{40}$/.test(accounts[0])
		)
			throw new AutomationError("wallet_account_required", 0);
		return accounts[0] as Address;
	}
	const sendCalls = async (
		calls: readonly { target: Address; data: Address; value: string }[],
		account: Address,
		chainId: number,
	) => {
		const address = await owner(chainId);
		const operation = await client
			.account(account)
			.owner({
				account: { address, type: "json-rpc" },
				signMessage: ({ message }) =>
					request({ method: "personal_sign", params: [message.raw, address] }),
			})
			.sendCalls({ chain: chainId, calls });
		return { operationId: operation.id };
	};
	return Object.freeze({
		approve: createOwnerApproval({
			journal,
			confirm: async () => true,
			signTypedData: async (value) => {
				const data = value as {
					domain: { chainId: number; [key: string]: unknown };
					types: Record<string, unknown>;
				};
				const domainFields = [
					["name", "string"],
					["version", "string"],
					["chainId", "uint256"],
					["verifyingContract", "address"],
					["salt", "bytes32"],
				];
				const typedData = {
					...data,
					types: {
						...data.types,
						EIP712Domain:
							data.types.EIP712Domain ??
							domainFields
								.filter(([name]) => data.domain[name!] !== undefined)
								.map(([name, type]) => ({ name, type })),
					},
				};
				const address = await owner(Number(data.domain.chainId));
				const signature = await request({
					method: "eth_signTypedData_v4",
					params: [
						address,
						JSON.stringify(typedData, (_, v) =>
							typeof v === "bigint" ? v.toString() : v,
						),
					],
				});
				if (typeof signature !== "string")
					throw new AutomationError("wallet_signature_invalid", 0);
				return signature;
			},
			executeSetup: (calls, review) =>
				sendCalls(calls, review.terms.account, review.terms.chainId),
		}),
		cancel: createOwnerCancellation({
			journal: createBrowserJournal<CancellationRecord>(
				"automation-cancellations-v1",
			),
			executeCalls: (calls, plan) =>
				sendCalls(calls!, plan.terms.account, plan.terms.chainId),
		}),
		sendCalls,
		close: () => client.close(),
	});
}
