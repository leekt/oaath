import { expect, test } from "bun:test";
import { IDBFactory } from "fake-indexeddb";
import {
	type CancellationRecord,
	createOwnerCancellation,
} from "../sdk/src/cancellation.ts";
import {
	createApprovalJournal,
	createBrowserJournal,
} from "../sdk/src/journal.ts";

test("independent browser journals retain one setup admission and survive recreation", async () => {
	const factory = new IDBFactory();
	const a = createApprovalJournal("test", factory),
		b = createApprovalJournal("test", factory);
	const next = {
		version: "dca.owner-approval/v1",
		stage: "setup_started",
		evidence: {
			commitment: "key",
			consentSignature: "consent",
			permissionSignature: "permission",
		},
	} as const;
	const winners = await Promise.all([
		a.compareAndSwap("key", null, next),
		b.compareAndSwap("key", null, next),
	]);
	expect(winners.filter(Boolean)).toHaveLength(1);
	expect(await createApprovalJournal("test", factory).read("key")).toEqual(
		next,
	);
});
test("recreated cancellation flow never resends a lost acknowledgement", async () => {
	const factory = new IDBFactory();
	let sends = 0;
	const make = () =>
		createOwnerCancellation({
			journal: createBrowserJournal<CancellationRecord>("cancel", factory),
			executeCalls: async () => {
				sends++;
				throw Error("lost reply");
			},
		});
	const p = {
		id: "plan",
		status: "cancelling",
		cancellation: { calls: [{ target: "target", data: "data", value: "0" }] },
	} as never;
	await make()(p);
	await make()(p);
	expect(sends).toBe(1);
});
