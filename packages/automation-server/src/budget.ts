/**
 * Hard request budgets for paid or shared providers: a fixed window per
 * provider role (chain RPC, bundler, paymaster), shared by every chain client
 * in one process. An exhausted budget fails the request; the caller defers
 * the work to `retryAt` and never treats the failure as permission to resend.
 *
 * @author taek <leekt216@gmail.com>
 */
export class BudgetError extends Error {
  readonly code = "budget_exhausted" as const;
  constructor(readonly role: string) {
    super("budget_exhausted");
    this.name = "BudgetError";
  }
}

export class RequestBudget {
  private window = -1;
  private used = 0;
  constructor(
    readonly role: string,
    readonly limit: number,
    readonly windowMs: number,
    private readonly clock: () => number = Date.now,
  ) {
    if (!Number.isSafeInteger(limit) || limit < 1) throw new RangeError("budget limit");
    if (!Number.isSafeInteger(windowMs) || windowMs < 1) throw new RangeError("budget window");
  }

  get windowId(): number {
    return Math.floor(this.clock() / this.windowMs);
  }

  /** Unix milliseconds at which the next window opens. */
  get retryAt(): number {
    return (this.windowId + 1) * this.windowMs;
  }

  /** All-or-nothing admission of `count` requests in the current window. */
  take(count = 1): void {
    if (!Number.isSafeInteger(count) || count < 1) throw new RangeError("budget count");
    if (this.window !== this.windowId) {
      this.window = this.windowId;
      this.used = 0;
    }
    if (this.used + count > this.limit) throw new BudgetError(this.role);
    this.used += count;
  }

  snapshot() {
    if (this.window !== this.windowId) return { role: this.role, used: 0, limit: this.limit };
    return { role: this.role, used: this.used, limit: this.limit };
  }
}
