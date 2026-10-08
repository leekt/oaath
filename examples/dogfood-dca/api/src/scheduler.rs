use crate::model::Terms;
use sqlx::{PgPool, Row};
/// The transaction is the admission owner; a pause competes for the same plan row.
pub async fn admit(pool: &PgPool, now: i64) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let plans=sqlx::query("SELECT id,terms,next_slot,status FROM automation_plans WHERE status IN ('active','paused') AND next_at<=$1 ORDER BY next_at,id LIMIT 32 FOR UPDATE SKIP LOCKED").bind(now).fetch_all(&mut *tx).await?;
    for row in plans {
        let id: String = row.get("id");
        let active = row.get::<String, _>("status") == "active";
        let raw: serde_json::Value = row.get("terms");
        let Ok(t) = serde_json::from_value::<Terms>(raw) else {
            continue;
        };
        if t.validate().is_err() {
            continue;
        }
        let occupied:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM automation_runs WHERE plan_id=$1 AND status IN ('reserved','observing','unresolved'))").bind(&id).fetch_one(&mut *tx).await?;
        let mut slot = row.get::<i32, _>("next_slot") as u32;
        while slot < t.max_runs {
            let at = t.start_at + i64::from(slot) as u64 * 86400;
            let close = at + u64::from(t.grace_seconds);
            if now < (at as i64) {
                break;
            }
            if (occupied || !active) && now < (close as i64) {
                break;
            }
            let skipped = now >= close as i64;
            sqlx::query("INSERT INTO automation_runs(plan_id,slot,scheduled_at,closes_at,digest,status,reason,next_observe_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING").bind(&id).bind(slot as i32).bind(at as i64).bind(close as i64).bind(t.slot_digest(slot).unwrap()).bind(if skipped{"skipped"}else{"reserved"}).bind(if skipped{Some("admission_window_missed")}else{None}).bind(now).execute(&mut *tx).await?;
            slot += 1;
            if !skipped {
                break;
            }
        }
        let remains:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM automation_runs WHERE plan_id=$1 AND status IN ('reserved','observing','unresolved'))").bind(&id).fetch_one(&mut *tx).await?;
        let done = slot == t.max_runs;
        sqlx::query("UPDATE automation_plans SET next_slot=$2,next_at=$3,status=CASE WHEN $4 AND NOT $5 AND status='active' THEN 'completed' WHEN $6 THEN 'expired' ELSE status END WHERE id=$1").bind(&id).bind(slot as i32).bind(if done{now+5}else{((t.start_at+u64::from(slot)*86400+if active{0}else{u64::from(t.grace_seconds)}) as i64).max(now+5)}).bind(done).bind(remains).bind(now>=t.end_at as i64).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE automation_plans SET status='expired',revision=revision+1 WHERE status IN ('draft','awaiting_consent','authorized') AND (terms->>'endAt')::bigint<=$1").bind(now).execute(&mut *tx).await?;
    tx.commit().await
}
