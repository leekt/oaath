import { expect, test } from "bun:test";
import {
	type ApprovalRecord,
	createOwnerApproval,
} from "../sdk/src/approval.ts";
import { createDca, DcaError } from "../sdk/src/index.ts";

test("HTTP transport does not retry an unknown mutation or follow redirects", async () => {
	let calls = 0;
	const dca = createDca({
		baseUrl: "http://service",
		token: "secret",
		fetch: async (_, init) => {
			calls++;
			expect(init?.redirect).toBe("error");
			throw new Error("secret network diagnostic");
		},
	});
	await expect(dca.cancel(`0x${"ab".repeat(32)}`)).rejects.toMatchObject({
		code: "request_outcome_unknown",
	});
	expect(calls).toBe(1);
});
test("SDK sanitizes upstream errors", async () => {
	const dca = createDca({
		baseUrl: "http://service",
		token: "secret",
		fetch: async () =>
			Response.json({ error: { code: "a secret raw error" } }, { status: 409 }),
	});
	await expect(dca.get(`0x${"ab".repeat(32)}`)).rejects.toMatchObject({
		code: "request_failed",
		status: 409,
	});
});
test("owner flow persists before setup and never resends after a lost reply", async () => {
	let record: ApprovalRecord | null = null,
		sends = 0,
		signs = 0;
	const approve = createOwnerApproval({
		journal: {
			read: async () => record,
			compareAndSwap: async (_, old, next) => {
				if (record !== old) return false;
				record = next;
				return true;
			},
		},
		confirm: async () => true,
		signTypedData: async () => {
			signs++;
			return "0xsigned";
		},
		executeSetup: async () => {
			sends++;
			throw new Error("lost reply");
		},
	});
	const review = { commitment: `0x${"ab".repeat(32)}`, setupCalls: [] } as any;
	const a = await approve(review);
	expect(await approve(review)).toEqual(a);
	expect(sends).toBe(1);
	expect(signs).toBe(2);
});
test("declining owner review causes no signature or setup", async () => {
	const approve = createOwnerApproval({
		journal: {
			read: async () => null,
			compareAndSwap: async () => {
				throw Error();
			},
		},
		confirm: async () => false,
		signTypedData: async () => {
			throw Error();
		},
		executeSetup: async () => {
			throw Error();
		},
	});
	await expect(approve({ commitment: "0x" } as any)).rejects.toBeInstanceOf(
		DcaError,
	);
});

test("unknown persisted approval versions fail closed", async () => {
	const approve = createOwnerApproval({
		journal: {
			read: async () =>
				({
					version: "dca.owner-approval/v9",
					stage: "submitted",
					evidence: { commitment: "0xabc" },
				}) as never,
			compareAndSwap: async () => {
				throw Error("must not write");
			},
		},
		confirm: async () => {
			throw Error("must not prompt");
		},
		signTypedData: async () => {
			throw Error("must not sign");
		},
		executeSetup: async () => {
			throw Error("must not submit");
		},
	});
	await expect(approve({ commitment: "0xabc" } as any)).rejects.toMatchObject({
		code: "consent_mismatch",
	});
});
