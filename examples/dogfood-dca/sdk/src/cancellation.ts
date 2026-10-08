import { AutomationError, type Plan } from "./index.js";
export interface CancellationRecord {
	version: "automation.cancellation/v1";
	calls: string;
	stage: "started" | "submitted";
	operationId?: string;
}
export interface CancellationJournal {
	read(key: string): Promise<CancellationRecord | null>;
	compareAndSwap(
		key: string,
		expected: CancellationRecord | null,
		next: CancellationRecord,
	): Promise<boolean>;
}
/** A lost cancellation reply remains observable and never grants permission to resend. */
export function createOwnerCancellation(options: {
	journal: CancellationJournal;
	executeCalls(
		calls: NonNullable<Plan["cancellation"]>["calls"],
		plan: Plan,
	): Promise<{ operationId: string }>;
}) {
	return async (plan: Plan) => {
		if (plan.status !== "cancelling" || !plan.cancellation?.calls?.length)
			throw new AutomationError("cancellation_not_ready", 0);
		const key = `cancel:${plan.id}`;
		const old = await options.journal.read(key);
		if (old) {
			if (old.version !== "automation.cancellation/v1")
				throw new AutomationError("cancellation_record_invalid", 0);
			return { operationId: old.operationId, status: "pending" as const };
		}
		const started: CancellationRecord = {
			version: "automation.cancellation/v1",
			stage: "started",
			calls: JSON.stringify(plan.cancellation.calls),
		};
		if (!(await options.journal.compareAndSwap(key, null, started)))
			throw new AutomationError("cancellation_in_progress", 0);
		let operationId: string;
		try {
			operationId = (await options.executeCalls(plan.cancellation.calls, plan))
				.operationId;
		} catch {
			return { status: "pending" as const };
		}
		if (
			!(await options.journal.compareAndSwap(key, started, {
				...started,
				stage: "submitted",
				operationId,
			}))
		)
			throw new AutomationError("cancellation_journal_conflict", 0);
		return { operationId, status: "pending" as const };
	};
}
