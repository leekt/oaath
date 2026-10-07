import { createTransport } from "./transport.js";
export type Address = `0x${string}`;
export type PlanStatus =
	| "draft"
	| "awaiting_consent"
	| "authorized"
	| "active"
	| "paused"
	| "cancelling"
	| "cancelled"
	| "expired"
	| "completed";
export type KeyScope = "user" | "application";
export interface CreatePlan {
	recipe: "dca.v1";
	amount: string;
	opportunities: number;
	maxSlippageBps: number;
	startAt?: number;
	idempotencyKey: string;
}
export interface Session {
	token: string;
	expiresAt: number;
	account: Address;
	keyScope: KeyScope;
}
export interface Config {
	version: "automation.api/v1";
	recipes: readonly { id: "dca.v1"; name: string }[];
	account: Address | null;
	keyScope: KeyScope;
	chainId: number;
	sell: { token: Address; symbol: string; decimals: number };
	buy: { token: Address; symbol: string; decimals: number };
	intervalSeconds: number;
	graceSeconds: number;
	serviceFee: string;
	maxFeePerGas: string;
	maxGasCost: string;
	factory: Address;
}
export interface Terms {
	version: "oaath.dca-terms/v1";
	planId: Address;
	account: Address;
	chainId: number;
	sellToken: Address;
	buyToken: Address;
	amountIn: string;
	totalInputCap: string;
	startAt: number;
	intervalSeconds: number;
	graceSeconds: number;
	maxRuns: number;
	endAt: number;
	recipient: Address;
	router: Address;
	poolFee: number;
	sellFeed: Address;
	buyFeed: Address;
	maxPriceAgeSeconds: number;
	maxSlippageBps: number;
}
export interface Plan {
	recipe: "dca.v1";
	keyScope: KeyScope;
	id: Address;
	status: PlanStatus;
	revision: number;
	terms: Terms;
	executor: Address | null;
	signer: Address | null;
	commitment: Address | null;
	progress: Record<string, number>;
	nextSlot: number;
	nextAt: number;
	setup: unknown;
	cancellation: null | {
		status: "confirmed" | "owner_action_required";
		calls?: readonly { target: Address; data: Address; value: string }[];
		executorStopped?: boolean;
		grantRevoked?: boolean;
		allowanceCleared?: boolean;
	};
	diagnostic: string | null;
	fees: {
		serviceFee: string;
		payer: "account";
		maxFeePerGas: string;
		maxGasCost: string;
	};
	asOf: number;
}
export interface Run {
	plan_id: Address;
	slot: number;
	scheduled_at: number;
	closes_at: number;
	digest: Address;
	status:
		| "reserved"
		| "observing"
		| "unresolved"
		| "succeeded"
		| "failed"
		| "skipped";
	operation: unknown;
	evidence: unknown;
	reason: string | null;
}
export interface Approval {
	status: "pending" | "active" | "cancelled";
	plan: Plan;
	review?: {
		commitment: Address;
		custody: "oaath_hosted";
		keyScope: KeyScope;
		terms: Terms;
		fees: Plan["fees"];
		permission: unknown;
		consent: unknown;
		setupCalls: readonly { target: Address; data: Address; value: string }[];
	};
}
export class AutomationError extends Error {
	constructor(
		readonly code: string,
		readonly status: number,
	) {
		super(code);
		this.name = "AutomationError";
	}
}
export interface ClientOptions {
	baseUrl: string;
	token: string | (() => string | Promise<string>);
	fetch?: typeof fetch;
	timeoutMs?: number;
}
/** HTTP-only entry: no private keys, chain polling, database, wallet or scheduler dependency. */
export function createAutomation(options: ClientOptions) {
	const request = createTransport(options);
	const path = (id: string) => {
		if (!/^0x[0-9a-f]{64}$/.test(id))
			throw new AutomationError("plan_id_invalid", 0);
		return `/v1/plans/${id}`;
	};
	return Object.freeze({
		create: (input: CreatePlan) => request<Plan>("POST", "/v1/plans", input),
		get: (id: string) => request<Plan>("GET", path(id)),
		list: () => request<{ plans: Plan[] }>("GET", "/v1/plans"),
		listRuns: (id: string, options: { after?: number; limit?: number } = {}) =>
			request<{ runs: Run[] }>(
				"GET",
				path(id) +
					`/runs?after=${options.after ?? -1}&limit=${options.limit ?? 50}`,
			),
		authorize: (id: string) =>
			request<Approval>("POST", `${path(id)}/authorize`),
		submitApproval: (id: string, evidence: unknown) =>
			request<Approval>("POST", `${path(id)}/approve`, evidence),
		pause: (id: string) => request<Plan>("POST", `${path(id)}/pause`),
		resume: (id: string) => request<Plan>("POST", `${path(id)}/resume`),
		cancel: (id: string) => request<Plan>("POST", `${path(id)}/cancel`),
		refresh: (id: string) =>
			request<{ status: "queued"; planId: Address }>(
				"POST",
				`${path(id)}/refresh`,
			),
		config: () => request<Config>("GET", "/v1/config"),
	});
}
export type AutomationClient = ReturnType<typeof createAutomation>;
