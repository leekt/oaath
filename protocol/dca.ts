import type { Hex } from "cetane";
import { encodeAbiParameters, keccak256, stringToHex } from "cetane/utils";

export const DCA_VERSION = "oaath.dca-terms/v1" as const;
export const DCA_TERMS_FIELDS = [
	["planId", "bytes32"],
	["account", "address"],
	["chainId", "uint256"],
	["sellToken", "address"],
	["buyToken", "address"],
	["amountIn", "uint256"],
	["totalInputCap", "uint256"],
	["startAt", "uint64"],
	["intervalSeconds", "uint32"],
	["graceSeconds", "uint32"],
	["maxRuns", "uint32"],
	["endAt", "uint64"],
	["recipient", "address"],
	["router", "address"],
	["poolFee", "uint24"],
	["sellFeed", "address"],
	["buyFeed", "address"],
	["maxPriceAgeSeconds", "uint32"],
	["maxSlippageBps", "uint16"],
] as const;
export interface DcaTerms {
	readonly version: typeof DCA_VERSION;
	readonly planId: Hex;
	readonly account: Hex;
	readonly chainId: number;
	readonly sellToken: Hex;
	readonly buyToken: Hex;
	readonly amountIn: string;
	readonly totalInputCap: string;
	readonly startAt: number;
	readonly intervalSeconds: number;
	readonly graceSeconds: number;
	readonly maxRuns: number;
	readonly endAt: number;
	readonly recipient: Hex;
	readonly router: Hex;
	readonly poolFee: number;
	readonly sellFeed: Hex;
	readonly buyFeed: Hex;
	readonly maxPriceAgeSeconds: number;
	readonly maxSlippageBps: number;
}
export class DcaTermsError extends Error {
	readonly code: "dca_version_unsupported" | "dca_terms_invalid";
	constructor(code: DcaTermsError["code"]) {
		super(code);
		this.code = code;
	}
}
const invalid = (): never => {
	throw new DcaTermsError("dca_terms_invalid");
};
/** The v1 profile is standard 6-decimal input and 18-decimal output, daily, no catch-up. */
export function captureDcaTerms(input: unknown): Readonly<DcaTerms> {
	if (!input || typeof input !== "object" || Array.isArray(input))
		return invalid();
	const descriptors = Object.getOwnPropertyDescriptors(input);
	if (descriptors.version?.value !== DCA_VERSION)
		throw new DcaTermsError("dca_version_unsupported");
	const names = ["version", ...DCA_TERMS_FIELDS.map(([name]) => name)];
	if (
		Reflect.ownKeys(input).length !== names.length ||
		names.some((name) => {
			const descriptor = descriptors[name];
			return !descriptor || !("value" in descriptor);
		})
	)
		return invalid();
	const value: Record<string, string | number> = { version: DCA_VERSION };
	for (const [name, type] of DCA_TERMS_FIELDS) {
		const v: unknown = descriptors[name]?.value;
		if (type === "address" || type === "bytes32") {
			if (
				typeof v !== "string" ||
				!(
					type === "address" ? /^0x[0-9a-fA-F]{40}$/u : /^0x[0-9a-fA-F]{64}$/u
				).test(v) ||
				/^0x0+$/u.test(v)
			)
				return invalid();
			value[name] = v.toLowerCase();
		} else if (name === "amountIn" || name === "totalInputCap") {
			if (
				typeof v !== "string" ||
				!/^[1-9][0-9]{0,77}$/u.test(v) ||
				BigInt(v) >= 2n ** 256n
			)
				return invalid();
			value[name] = v;
		} else {
			if (
				typeof v !== "number" ||
				!Number.isSafeInteger(v) ||
				Object.is(v, -0) ||
				v < (name === "maxSlippageBps" ? 0 : 1) ||
				BigInt(v) >= 2n ** BigInt(type.slice(4))
			)
				return invalid();
			value[name] = v;
		}
	}
	const result = value as unknown as DcaTerms;
	if (
		result.sellToken === result.buyToken ||
		result.account !== result.recipient ||
		result.intervalSeconds !== 86400 ||
		result.graceSeconds > result.intervalSeconds ||
		result.maxRuns > 365 ||
		result.maxSlippageBps > 1000 ||
		result.poolFee >= 1_000_000 ||
		result.maxPriceAgeSeconds > 86400 ||
		result.endAt !==
			result.startAt +
				(result.maxRuns - 1) * result.intervalSeconds +
				result.graceSeconds ||
		!Number.isSafeInteger(result.endAt) ||
		BigInt(result.totalInputCap) !==
			BigInt(result.amountIn) * BigInt(result.maxRuns)
	)
		return invalid();
	return Object.freeze(result);
}
/** Solidity abi.encode(domain, Terms); every Terms member is static. */
export function encodeDcaTerms(input: unknown): Hex {
	const terms = captureDcaTerms(input);
	return encodeAbiParameters(
		[
			{ type: "bytes32" },
			...DCA_TERMS_FIELDS.map(([name, type]) => ({ name, type })),
		],
		[
			keccak256(stringToHex(DCA_VERSION)),
			...DCA_TERMS_FIELDS.map(([name, type]) =>
				type.startsWith("uint") ? BigInt(terms[name]) : terms[name],
			),
		] as never,
	);
}
export function hashDcaTerms(input: unknown): Hex {
	return keccak256(encodeDcaTerms(input));
}
export function hashDcaSlot(input: unknown, slot: number): Hex {
	const terms = captureDcaTerms(input);
	if (!Number.isSafeInteger(slot) || slot < 0 || slot >= terms.maxRuns)
		return invalid();
	return keccak256(
		encodeAbiParameters(
			[{ type: "bytes32" }, { type: "bytes32" }, { type: "uint32" }],
			[keccak256(stringToHex("oaath.dca-slot/v1")), hashDcaTerms(terms), slot],
		),
	);
}
