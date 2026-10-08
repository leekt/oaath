export const ORIGIN = "https://dca.taek.tech";
export const CHAIN_ID = 421614;
export const ENTRY_POINT = "0x433709009b8330fda32311df1c2afa402ed8d009";
export const address = (value: unknown): string => {
	if (typeof value !== "string" || !/^0x[\da-f]{40}$/i.test(value))
		throw Error("wallet_address_invalid");
	return value.toLowerCase();
};
export function loginMessage(owner: string, nonce: string, expires: number) {
	return `${ORIGIN} requests a wallet login.\n\nAddress: ${owner}\nChain ID: ${CHAIN_ID}\nNonce: ${nonce}\nExpires: ${new Date(expires * 1000).toISOString()}\n\nThis proves wallet ownership. It does not authorize purchases or transfers.`;
}
export function apiPath(path: string, method: string) {
	if (
		method === "GET" &&
		/^\/v1\/(config|plans(?:\/0x[\da-f]{64}(?:\/runs)?)?)$/.test(path)
	)
		return true;
	return (
		method === "POST" &&
		/^\/v1\/plans(?:\/0x[\da-f]{64}\/(authorize|approve|pause|resume|cancel|refresh))?$/.test(
			path,
		)
	);
}
export function rpcAllowed(body: any, account: string, bundler: boolean) {
	if (
		!body ||
		Array.isArray(body) ||
		body.jsonrpc !== "2.0" ||
		!Array.isArray(body.params)
	)
		return false;
	if (bundler) {
		if (
			["eth_estimateUserOperationGas", "eth_sendUserOperation"].includes(
				body.method,
			)
		)
			return (
				body.params.length === 2 &&
				body.params[1]?.toLowerCase() === ENTRY_POINT &&
				body.params[0]?.sender?.toLowerCase() === account
			);
		return [
			"eth_getUserOperationReceipt",
			"eth_getUserOperationByHash",
		].includes(body.method)
			? body.params.length === 1 && /^0x[\da-f]{64}$/i.test(body.params[0])
			: [
					"eth_chainId",
					"eth_supportedEntryPoints",
					"zd_getUserOperationGasPrice",
				].includes(body.method) && body.params.length === 0;
	}
	return [
		"eth_chainId",
		"eth_blockNumber",
		"eth_getBlockByNumber",
		"eth_getBlockByHash",
		"eth_getCode",
		"eth_getStorageAt",
		"eth_getBalance",
		"eth_call",
		"eth_getTransactionCount",
		"eth_getTransactionReceipt",
		"eth_getTransactionByHash",
		"eth_gasPrice",
		"eth_maxPriorityFeePerGas",
		"eth_feeHistory",
		"eth_estimateGas",
		"eth_getLogs",
	].includes(body.method);
}
