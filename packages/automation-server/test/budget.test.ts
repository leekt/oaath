import { describe, expect, it } from "vitest";
import { BudgetError, RequestBudget } from "../src/budget.js";

describe("RequestBudget", () => {
  it("defers exhaustion until the next explicit window", () => {
    let time = 0;
    const budget = new RequestBudget("rpc", 2, 100, () => time);
    budget.take();
    budget.take();
    expect(() => budget.take()).toThrow(BudgetError);
    time = 99;
    expect(() => budget.take()).toThrow(BudgetError);
    expect(budget.retryAt).toBe(100);
    time = 100;
    budget.take();
    expect(budget.snapshot().used).toBe(1);
  });

  it("admits a batch all or nothing", () => {
    const budget = new RequestBudget("bundler", 3, 100, () => 0);
    budget.take(2);
    expect(() => budget.take(2)).toThrow(BudgetError);
    expect(budget.snapshot().used).toBe(2);
    budget.take();
    expect(budget.snapshot().used).toBe(3);
  });
});
