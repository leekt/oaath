/** A fixed, explicit job window shared by all chain clients in one worker process. */
export class RpcBudget {
	private window = -1;
	private used = 0;
	constructor(
		readonly limit = 20000,
		readonly windowMs = 600000,
		private clock = Date.now,
	) {}
	get windowId() {
		return Math.floor(this.clock() / this.windowMs);
	}
	get retryAt() {
		return (this.windowId + 1) * this.windowMs;
	}
	take(count = 1) {
		if (!Number.isSafeInteger(count) || count < 1)
			throw new Error("rpc_budget_count_invalid");
		if (this.window !== this.windowId) {
			this.window = this.windowId;
			this.used = 0;
		}
		if (this.used + count > this.limit) throw new Error("rpc_budget_exhausted");
		this.used += count;
	}
	snapshot() {
		return {
			window: this.windowId,
			used: this.used,
			limit: this.limit,
			retryAt: this.retryAt,
		};
	}
}
