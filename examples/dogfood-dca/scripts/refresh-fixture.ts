/** Refresh only the two owned, permissionless test feeds; never used by the service. */
import { encodeFunctionData, parseAbi } from "viem";
import { config, owner } from "./proof-support.js";

const abi = parseAbi(["function set(int256 price,uint256 timestamp)"]);
const timestamp = BigInt(Math.floor(Date.now() / 1000));
const result = await owner("calls", {
	calls: [
		[config.sellFeed, 100000000n],
		[config.buyFeed, 200000000000n],
	].map(([target, price]) => ({
		target,
		value: "0",
		data: encodeFunctionData({
			abi,
			functionName: "set",
			args: [price as bigint, timestamp],
		}),
	})),
});
if (result.outcome.status !== "finalized")
	throw Error("fixture_feed_refresh_pending");
await owner("mine");
console.log("Owned fixture feed prices refreshed");
