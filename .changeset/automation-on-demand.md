---
"@oaath/automation": patch
"@oaath/automation-server": patch
---

On-demand automations: a definition of `kind: "on-demand"` names chains, an exact call list (target, selector, value limit) and a per-chain operation limit, with no schedule. One plan's Grant covers every listed chain; the application then submits exact calls with `POST /v1/plans/{id}/operations`, each admitted only when it fits the approved policy, persisted on a `request` run and sent exactly once. Runs carry their chain, and `GET /v1/plans/{id}/runs/{runId}` reads one back. The PostgreSQL schema is now `oaath.automation-postgres-schema/v3`: drop and recreate the database.
