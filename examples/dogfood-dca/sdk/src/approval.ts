import { type Approval, AutomationError } from "./index.js";
export type OwnerReview = NonNullable<Approval["review"]>;
export interface SignedConsent {
	commitment: string;
	consentSignature: string;
	permissionSignature: string;
	setupOperation?: string;
}
export interface ApprovalRecord {
	version: "dca.owner-approval/v1";
	stage: "reviewed" | "setup_started" | "submitted";
	evidence: SignedConsent;
}
export interface ApprovalJournal {
	read(key: string): Promise<ApprovalRecord | null>;
	/** Atomic insert/update. A failed comparison must leave the record unchanged. */
	compareAndSwap(
		key: string,
		expected: ApprovalRecord | null,
		next: ApprovalRecord,
	): Promise<boolean>;
}
export interface OwnerApprovalOptions {
	journal: ApprovalJournal;
	/** Display all terms, custody, separate fees and both setup calls before accepting. */
	confirm(review: OwnerReview): Promise<boolean>;
	signTypedData(value: unknown, review: OwnerReview): Promise<string>;
	/** Use the existing OAAth owner account sendCalls flow and its durable Operation store. */
	executeSetup(
		calls: OwnerReview["setupCalls"],
		review: OwnerReview,
	): Promise<{ operationId: string }>;
}
/** Supplied consent orchestration. Unknown setup outcomes are reconciled by the service, never resent. */
export function createOwnerApproval(options: OwnerApprovalOptions) {
	return async function approve(review: OwnerReview): Promise<SignedConsent> {
		const key = review.commitment;
		let record = await options.journal.read(key);
		if (!record) {
			if (!(await options.confirm(review)))
				throw new AutomationError("owner_declined", 0);
			const evidence = {
				commitment: key,
				consentSignature: await options.signTypedData(review.consent, review),
				permissionSignature: await options.signTypedData(
					review.permission,
					review,
				),
			};
			const next: ApprovalRecord = {
				version: "dca.owner-approval/v1",
				stage: "reviewed",
				evidence,
			};
			if (!(await options.journal.compareAndSwap(key, null, next)))
				throw new AutomationError("approval_in_progress", 0);
			record = next;
		}
		if (
			record.version !== "dca.owner-approval/v1" ||
			!["reviewed", "setup_started", "submitted"].includes(record.stage) ||
			record.evidence.commitment !== key
		)
			throw new AutomationError("consent_mismatch", 0);
		if (record.stage !== "reviewed") return record.evidence;
		const started: ApprovalRecord = {
			version: "dca.owner-approval/v1",
			stage: "setup_started",
			evidence: record.evidence,
		};
		if (!(await options.journal.compareAndSwap(key, record, started)))
			throw new AutomationError("approval_in_progress", 0);
		// Retain the signed evidence even if the owner transaction's acknowledgement is lost.
		let result: { operationId: string };
		try {
			result = await options.executeSetup(review.setupCalls, review);
		} catch {
			return started.evidence;
		}
		const next: ApprovalRecord = {
			version: "dca.owner-approval/v1",
			stage: "submitted",
			evidence: { ...started.evidence, setupOperation: result.operationId },
		};
		if (!(await options.journal.compareAndSwap(key, started, next)))
			throw new AutomationError("approval_journal_conflict", 0);
		return next.evidence;
	};
}
