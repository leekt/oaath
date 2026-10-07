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
export interface CreatePlan {
	account: Address;
	chainId: number;
	sell: { token: Address; amount: string };
	buy: { token: Address };
	intervalSeconds: 86400;
	maxRuns: number;
	maxSlippageBps: number;
	startAt?: number;
	idempotencyKey: string;
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
	cancellation: unknown;
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
		terms: Terms;
		fees: Plan["fees"];
		permission: unknown;
		consent: unknown;
		setupCalls: readonly { target: Address; data: Address; value: string }[];
	};
}
export class DcaError extends Error {
	constructor(
		readonly code: string,
		readonly status: number,
	) {
		super(code);
		this.name = "DcaError";
	}
}
export interface ClientOptions {
	baseUrl: string;
	token: string | (() => string | Promise<string>);
	fetch?: typeof fetch;
	timeoutMs?: number;
	approve?: (review: NonNullable<Approval["review"]>) => Promise<unknown>;
}
/** HTTP-only entry: no private keys, chain polling, database, wallet or scheduler dependency. */
export function createDca(options: ClientOptions) {
	const url = new URL(options.baseUrl);
	if (
		!["http:", "https:"].includes(url.protocol) ||
		url.username ||
		url.password ||
		url.search ||
		url.hash
	)
		throw new DcaError("base_url_invalid", 0);
	const base = url.href.replace(/\/$/, "");
	const fetcher = options.fetch ?? globalThis.fetch;
	async function request<T>(
		method: string,
		path: string,
		body?: unknown,
	): Promise<T> {
		const token =
			typeof options.token === "function"
				? await options.token()
				: options.token;
		let r: Response;
		try {
			r = await fetcher(base + path, {
				method,
				headers: {
					authorization: `Bearer ${token}`,
					"content-type": "application/json",
				},
				...(body === undefined ? {} : { body: JSON.stringify(body) }),
				signal: AbortSignal.timeout(options.timeoutMs ?? 30000),
				redirect: "error",
			});
		} catch {
			throw new DcaError("request_outcome_unknown", 0);
		}
		const value: unknown = await r.json().catch(() => {
			throw new DcaError("response_unreadable", r.status);
		});
		if (!r.ok) {
			const code = (value as { error?: { code?: unknown } })?.error?.code;
			throw new DcaError(
				typeof code === "string" && /^[a-z0-9_]{1,100}$/.test(code)
					? code
					: "request_failed",
				r.status,
			);
		}
		if (!value || typeof value !== "object")
			throw new DcaError("response_invalid", r.status);
		return value as T;
	}
	const path = (id: string) => {
		if (!/^0x[0-9a-f]{64}$/.test(id)) throw new DcaError("plan_id_invalid", 0);
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
		async authorize(id: string): Promise<Approval> {
			const approval = await request<Approval>("POST", `${path(id)}/authorize`);
			if (approval.review && options.approve) {
				return request<Approval>(
					"POST",
					`${path(id)}/approve`,
					await options.approve(approval.review),
				);
			}
			return approval;
		},
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
		config: () => request<Record<string, unknown>>("GET", "/v1/config"),
	});
}
export type DcaClient = ReturnType<typeof createDca>;
