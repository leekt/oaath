import {
	encodeKernelInstallNonceInvalidationCall,
	encodeKernelPermissionUninstallCalls,
} from "@oaath/protocol";
import { readKernelPermissionStatus } from "@oaath/sdk/kernel";
import { authority, openGrant } from "./authority.js";
import {
	config,
	encode,
	executor,
	ports,
	read,
	rpc,
	tokenAbi,
} from "./chain.js";
import { getRecord, now, plan, pool } from "./store.js";
export async function cancel(id: string) {
	const p = await plan(id);
	if (p.status === "cancelled") return { status: "cancelled" };
	if (p.status !== "cancelling") throw new Error("cancel_state_conflict");
	const auth = await getRecord(id, "authorization");
	if (!auth) {
		await pool.query(
			"UPDATE dca_plans SET status='cancelled',revision=revision+1,cancellation=$2 WHERE id=$1 AND status='cancelling'",
			[id, { status: "confirmed", reason: "no_authority_issued" }],
		);
		return { status: "cancelled" };
	}
	const decision = await getRecord(id, "decision");
	const block = await rpc("eth_getBlockByNumber", ["finalized", false]);
	if (!block?.hash) throw new Error("finality_unavailable");
	const pin = { blockHash: block.hash, requireCanonical: true };
	const code = await rpc("eth_getCode", [auth.executor, pin]);
	let stopped = code === "0x";
	if (!stopped)
		stopped = await read(auth.executor, executor.abi, "cancelled", [], pin);
	const calls: any[] = [];
	if (!stopped)
		calls.push({
			target: auth.executor,
			data: encode(executor.abi, "cancel"),
			value: "0",
		});
	const allowance = await read(
		p.terms.sellToken,
		tokenAbi,
		"allowance",
		[p.account, auth.executor],
		pin,
	);
	if (allowance > 0n)
		calls.push({
			target: p.terms.sellToken,
			data: encode(tokenAbi, "approve", [auth.executor, 0n]),
			value: "0",
		});
	let revoked = false;
	if (decision) {
		const state = await readKernelPermissionStatus({
			approval: decision.approval,
			chainId: config.chainId,
			reads: ports().reads,
			blockTag: "finalized",
		});
		if (state.status === "unreadable") throw new Error("permission_unreadable");
		if (state.status === "installed")
			calls.push(
				...encodeKernelPermissionUninstallCalls({
					account: p.account,
					packages: decision.approval.packages,
				}),
			);
		if (state.status === "approval-replayable")
			calls.push(
				encodeKernelInstallNonceInvalidationCall({
					account: p.account,
					installNonce: decision.approval.installNonce,
				}),
			);
		const grant = await openGrant(id);
		try {
			await grant.revoke();
			revoked = grant.state === "revoked";
		} finally {
			await grant.close();
		}
	} else {
		const a = await authority(id);
		const signer = a.prepared.runtime.packages.find(
			(p: any) => p.moduleType === 6,
		)!;
		const state: any = await ports().reads.read({
			type: "kernel_v4_permission_state",
			chainId: config.chainId,
			account: p.account,
			signer: signer.module,
			permissionId: (a.prepared.runtime.validation as any).permissionId,
			nonce: a.prepared.nonce,
			blockTag: "finalized",
		});
		if (!state || typeof state.installed !== "boolean")
			throw new Error("permission_unreadable");
		if (state.installed)
			calls.push(
				...encodeKernelPermissionUninstallCalls({
					account: p.account,
					packages: a.prepared.runtime.packages,
				}),
			);
		else if (BigInt(state.installNonce) <= BigInt(a.prepared.nonce))
			calls.push(
				encodeKernelInstallNonceInvalidationCall({
					account: p.account,
					installNonce: a.prepared.nonce,
				}),
			);
		else revoked = true;
	}
	const rebound = await rpc("eth_getBlockByNumber", [block.number, false]);
	if (rebound.hash !== block.hash) throw new Error("canonicality_unproven");
	const complete = stopped && revoked && allowance === 0n;
	const cancellation = {
		status: complete ? "confirmed" : "owner_action_required",
		calls,
		executorStopped: stopped,
		grantRevoked: revoked,
		allowanceCleared: allowance === 0n,
		blockHash: block.hash,
		blockNumber: block.number,
	};
	await pool.query(
		"UPDATE dca_plans SET status=CASE WHEN $2 THEN 'cancelled' ELSE status END,revision=revision+1,cancellation=$3 WHERE id=$1 AND status='cancelling'",
		[id, complete, cancellation],
	);
	return { status: complete ? "cancelled" : "pending", cancellation };
}

/** Claim a bounded cancellation observation window; never sends owner calls. */
export async function cancellationWorker(signal: AbortSignal) {
	while (!signal.aborted) {
		const row = await pool.query(
			"UPDATE dca_plans SET next_cleanup_at=$1 WHERE id=(SELECT id FROM dca_plans WHERE status='cancelling' AND next_cleanup_at<=$2 ORDER BY next_cleanup_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id",
			[now() + 60, now()],
		);
		if (row.rows[0]) {
			try {
				await cancel(row.rows[0].id);
			} catch {
				await pool.query(
					"UPDATE dca_plans SET diagnostic='cancellation_reconciliation_pending' WHERE id=$1",
					[row.rows[0].id],
				);
			}
		} else await new Promise((resolve) => setTimeout(resolve, 1000));
	}
}
