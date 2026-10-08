import { isDeepStrictEqual } from "node:util";
import { executeKeyed } from "@oaath/sdk/headless";
import { decodeEventLog } from "cetane/utils";
import { captureDcaTerms, hashDcaSlot } from "../../protocol/dca.js";
import { openGrant } from "./authority.js";
import { budget, encode, executor } from "./chain.js";
import { now, plan, pool } from "./store.js";

export async function claim() {
	const c = await pool.connect();
	try {
		await c.query("BEGIN");
		const { rows } = await c.query(
			"SELECT r.plan_id,r.slot FROM automation_runs r WHERE r.status IN ('reserved','observing','unresolved') AND r.next_observe_at<=$1 AND r.lease_until<=$1 ORDER BY r.next_observe_at,r.plan_id LIMIT 1 FOR UPDATE SKIP LOCKED",
			[now()],
		);
		if (!rows[0]) {
			await c.query("COMMIT");
			return null;
		}
		const result = await c.query(
			"UPDATE automation_runs SET generation=generation+1,lease_until=$3 WHERE plan_id=$1 AND slot=$2 RETURNING *",
			[rows[0].plan_id, rows[0].slot, now() + 60],
		);
		await c.query("COMMIT");
		return result.rows[0];
	} catch (e) {
		await c.query("ROLLBACK");
		throw e;
	} finally {
		c.release();
	}
}
async function update(run: any, sql: string, args: unknown[] = []) {
	return pool.query(
		`UPDATE automation_runs SET ${sql} WHERE plan_id=$1 AND slot=$2 AND generation=$3`,
		[run.plan_id, run.slot, run.generation, ...args],
	);
}
export async function reconcile(run: any) {
	let grant: Awaited<ReturnType<typeof openGrant>> | undefined;
	try {
		const p = await plan(run.plan_id),
			t = captureDcaTerms(p.terms);
		if (run.digest !== hashDcaSlot(t, run.slot))
			throw new Error("input_digest_conflict");
		if (!run.operation) {
			if (
				now() >= Number(run.closes_at) ||
				["cancelling", "cancelled", "expired", "completed"].includes(p.status)
			) {
				await update(
					run,
					"status='skipped',lease_until=0,reason='admission_closed'",
				);
				return;
			}
			if (p.status !== "active") {
				await update(
					run,
					"lease_until=0,next_observe_at=$4,reason='admission_closed'",
					[now() + 10],
				);
				return;
			}
		}
		grant = await openGrant(p.id);
		const result = await executeKeyed(grant, {
			chain: t.chainId,
			calls: [
				{
					target: p.executor,
					value: "0",
					data: encode(executor.abi, "execute", [run.slot]),
				},
			],
			intent: {
				digest: run.digest,
				read: async () => {
					const row = (
						await pool.query(
							"SELECT * FROM automation_runs WHERE plan_id=$1 AND slot=$2",
							[p.id, run.slot],
						)
					).rows[0];
					if (
						!row ||
						row.digest !== run.digest ||
						String(row.generation) !== String(run.generation)
					)
						return { status: "unresolved" };
					return row.operation
						? { status: "reserved", identity: row.operation.identity }
						: { status: "fresh" };
				},
				publication: {
					reserve: async (reservation) => {
						const c = await pool.connect();
						try {
							await c.query("BEGIN");
							const latest = (
								await c.query(
									"SELECT status,revision FROM automation_plans WHERE id=$1 FOR UPDATE",
									[p.id],
								)
							).rows[0];
							if (
								latest.status !== "active" ||
								String(latest.revision) !== String(p.revision) ||
								now() >= Number(run.closes_at)
							)
								throw new Error("admission_closed");
							const result = await c.query(
								"UPDATE automation_runs SET operation=$4 WHERE plan_id=$1 AND slot=$2 AND generation=$3 AND operation IS NULL AND digest=$5 AND lease_until>$6",
								[
									p.id,
									run.slot,
									run.generation,
									reservation.operation,
									run.digest,
									now(),
								],
							);
							if (result.rowCount !== 1)
								throw new Error("reservation_conflict");
							await c.query("COMMIT");
						} catch (e) {
							await c.query("ROLLBACK");
							throw e;
						} finally {
							c.release();
						}
					},
					confirm: async (pointer) => {
						const r = await update(run, "status='observing',reason=NULL");
						if (r.rowCount !== 1) throw new Error("stale_claim");
						const current = (
							await pool.query(
								"SELECT operation FROM automation_runs WHERE plan_id=$1 AND slot=$2",
								[p.id, run.slot],
							)
						).rows[0];
						if (
							!isDeepStrictEqual(current.operation.identity, pointer.identity)
						)
							throw new Error("operation_conflict");
					},
					abandon: async () => {
						await update(
							run,
							"status='unresolved',reason='publication_incomplete'",
						);
					},
				},
			},
		});
		if (result.status === "unresolved") {
			await update(
				run,
				"status='unresolved',lease_until=0,next_observe_at=$4,reason='operation_unresolved'",
				[now() + 30],
			);
			return;
		}
		const op = result.operation;
		const outcome = await op.observe();
		if (outcome.status !== "finalized") {
			if (["dropped", "superseded", "abandoned"].includes(outcome.status)) {
				await update(run, "status='failed',reason=$4,lease_until=0", [
					outcome.status,
				]);
				return;
			}
			await update(
				run,
				"status='observing',lease_until=0,observations=observations+1,next_observe_at=$4,reason=$5",
				[
					now() + Math.min(60, 2 ** Math.min(Number(run.observations) + 1, 6)),
					outcome.reason ?? "pending",
				],
			);
			return;
		}
		const evidence = await op.execution();
		if (
			evidence.sender !== t.account ||
			evidence.chainId !== t.chainId ||
			evidence.grantId !== p.id ||
			evidence.calls.length !== 1 ||
			evidence.calls[0]?.target !== p.executor ||
			evidence.calls[0]?.data !== encode(executor.abi, "execute", [run.slot]) ||
			evidence.calls[0]?.value !== "0"
		)
			throw new Error("result_binding_invalid");
		if (evidence.outcome === "reverted") {
			await update(
				run,
				"status='failed',lease_until=0,evidence=$4,reason='finalized_revert'",
				[evidence],
			);
			return;
		}
		const receipt = await op.receipt();
		const logs = receipt.logs
			.filter((log) => log.address === p.executor)
			.flatMap((log) => {
				try {
					const decoded: any = decodeEventLog({
						abi: executor.abi,
						data: log.data,
						topics: [...log.topics] as never,
					});
					return decoded.eventName === "Purchased" ? [decoded.args as any] : [];
				} catch {
					return [];
				}
			});
		if (logs.length !== 1) throw new Error("purchase_evidence_invalid");
		const event = logs[0];
		if (
			event.planId !== p.id ||
			Number(event.slot) !== run.slot ||
			event.account.toLowerCase() !== t.account ||
			event.sellToken.toLowerCase() !== t.sellToken ||
			event.buyToken.toLowerCase() !== t.buyToken ||
			event.amountIn !== BigInt(t.amountIn) ||
			event.amountOut <= 0n
		)
			throw new Error("purchase_evidence_invalid");
		await update(
			run,
			"status='succeeded',lease_until=0,reason=NULL,evidence=$4",
			[
				{
					...evidence,
					amountIn: event.amountIn.toString(),
					amountOut: event.amountOut.toString(),
				},
			],
		);
	} catch (error) {
		const raw =
			(error as { code?: string })?.code ??
			(error instanceof Error ? error.message : "");
		const code = /^[a-z0-9_]{1,80}$/.test(raw)
			? raw
			: "reconciliation_unavailable";
		console.error(
			JSON.stringify({
				event: "reconcile_deferred",
				code,
				source: /^[a-z0-9_]{1,80}$/.test((error as any)?.source)
					? (error as any).source
					: null,
			}),
		);
		await update(
			run,
			"lease_until=0,observations=observations+1,next_observe_at=$4,reason=$5",
			[
				budget.snapshot().used >= budget.limit
					? Math.ceil(budget.retryAt / 1000)
					: now() + 30,
				code,
			],
		);
	} finally {
		if (grant) {
			try {
				await grant.close();
			} catch {
				await update(run, "cleanup_diagnostic='grant_close_pending'");
				try {
					await grant.close();
					await update(run, "cleanup_diagnostic=NULL");
				} catch {
					/* Retain cleanup diagnostic separately from the primary operation result. */
				}
			}
		}
	}
}
export async function worker(signal: AbortSignal) {
	while (!signal.aborted) {
		const run = await claim();
		if (run) await reconcile(run);
		else await new Promise((resolve) => setTimeout(resolve, 1000));
	}
}
