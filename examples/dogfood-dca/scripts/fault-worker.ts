/** Test-only process: interrupt real PostgreSQL acknowledgements at owned crash boundaries. */
import { writeFileSync } from "node:fs";
import { now, pool } from "../runtime/src/store.js";
import { reconcile } from "../runtime/src/worker.js";

const id = process.env.FAULT_PLAN!,
	point = process.env.FAULT_POINT!;
const connect = pool.connect.bind(pool);
(pool as any).connect = (callback?: unknown) => {
	if (callback) return (connect as any)(callback);
	return connect().then((c) => {
		const query = c.query.bind(c);
		let armed = false;
		(c as any).query = async (sql: any, args?: any) => {
			const text = typeof sql === "string" ? sql : sql.text;
			if (
				point === "reservation" &&
				text.startsWith("UPDATE automation_runs SET operation=") &&
				args?.[0] === id
			)
				armed = true;
			if (
				text.startsWith("UPDATE oaath_operation_lane_v2 SET record") &&
				args?.[0] === id
			) {
				const record = JSON.parse(args[4]);
				if (point === "publication" && record.value.state === "prepared")
					armed = true;
				if (point === "inclusion" && record.value.state === "included")
					armed = true;
			}
			const result = await query(sql, args);
			if (armed && text === "COMMIT") {
				writeFileSync(
					`.local/fault-${point}.json`,
					JSON.stringify({ point, planId: id }),
				);
				process.kill(process.pid, "SIGKILL");
				await new Promise(() => {});
			}
			return result;
		};
		const release = c.release.bind(c);
		c.release = (err: any) => {
			(c as any).query = query;
			c.release = release;
			release(err);
		};
		return c;
	});
};
let row: any;
for (let n = 0; n < 45; n++) {
	row = (
		await pool.query(
			"UPDATE automation_runs SET generation=generation+1,lease_until=$2 WHERE plan_id=$1 AND slot=0 AND lease_until<=$3 RETURNING *",
			[id, now() + 60, now()],
		)
	).rows[0];
	if (row) break;
	await new Promise((r) => setTimeout(r, 1000));
}
if (!row) throw Error("fault_run_missing");
await reconcile(row);
await pool.end();
throw Error("fault_boundary_not_reached");
