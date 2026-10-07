import { expect, test } from "bun:test";
import { RpcBudget } from "../runtime/src/budget.ts";

test("budget exhaustion defers until the next explicit window", () => {
	let time = 0;
	const budget = new RpcBudget(2, 100, () => time);
	budget.take();
	budget.take();
	expect(() => budget.take()).toThrow("rpc_budget_exhausted");
	time = 99;
	expect(() => budget.take()).toThrow();
	time = 100;
	budget.take();
	expect(budget.snapshot().used).toBe(1);
});
