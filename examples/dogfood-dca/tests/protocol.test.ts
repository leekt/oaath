import { describe, expect, it } from "bun:test";
import {
	captureDcaTerms,
	DCA_VERSION,
	hashDcaSlot,
	hashDcaTerms,
} from "../protocol/dca.ts";

const address = (n: number) => `0x${n.toString(16).padStart(40, "0")}`;
const terms = () => ({
	version: DCA_VERSION,
	planId: `0x${"01".repeat(32)}`,
	account: address(1),
	chainId: 31337,
	sellToken: address(2),
	buyToken: address(3),
	amountIn: "25000000",
	totalInputCap: "750000000",
	startAt: 1800000000,
	intervalSeconds: 86400,
	graceSeconds: 900,
	maxRuns: 30,
	endAt: 1800000000 + 29 * 86400 + 900,
	recipient: address(1),
	router: address(4),
	poolFee: 3000,
	sellFeed: address(5),
	buyFeed: address(6),
	maxPriceAgeSeconds: 3600,
	maxSlippageBps: 50,
});
describe("DCA commitment", () => {
	it("captures immutable canonical terms and deterministic slot commitments", () => {
		const a = captureDcaTerms(terms());
		expect(Object.isFrozen(a)).toBe(true);
		expect(hashDcaTerms(a)).toBe(hashDcaTerms(captureDcaTerms({ ...terms() })));
		expect(hashDcaSlot(a, 0)).not.toBe(hashDcaSlot(a, 1));
		expect(() => hashDcaSlot(a, 30)).toThrow();
	});
	it.each([
		"amountIn",
		"account",
		"router",
		"sellToken",
		"buyToken",
		"poolFee",
		"sellFeed",
		"buyFeed",
		"maxPriceAgeSeconds",
		"maxSlippageBps",
	])("binds %s", (field) => {
		const input = terms() as Record<string, unknown>;
		if (field === "amountIn") {
			input[field] = "24000000";
			input.totalInputCap = "720000000";
		} else if (field === "account") {
			input[field] = address(9);
			input.recipient = address(9);
		} else if (typeof input[field] === "number")
			input[field] = Number(input[field]) + 1;
		else input[field] = address(9);
		expect(hashDcaTerms(captureDcaTerms(input))).not.toBe(
			hashDcaTerms(captureDcaTerms(terms())),
		);
	});
	it.each([
		{ version: "oaath.dca-terms/v0" },
		{ unexpected: true },
		{ amountIn: "25.0" },
		{ amountIn: "025" },
		{ intervalSeconds: 1 },
		{ graceSeconds: 0 },
		{ maxRuns: 0 },
		{ maxRuns: 366 },
		{ maxSlippageBps: 10001 },
		{ recipient: address(9) },
		{ endAt: 1800000000 },
		{ totalInputCap: "1" },
		{ chainId: 0 },
		{ router: address(0) },
		{ buyToken: address(2) },
	])("rejects invalid or weakened terms %j", (change) => {
		expect(() => captureDcaTerms({ ...terms(), ...change })).toThrow();
	});
});
