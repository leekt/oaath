CREATE TABLE dca_plans (
 id text PRIMARY KEY, app_id text NOT NULL, account text NOT NULL,
 creation_key text NOT NULL, input_digest text NOT NULL, terms jsonb NOT NULL,
 status text NOT NULL CHECK(status IN ('draft','awaiting_consent','authorized','active','paused','cancelling','cancelled','completed','expired')),
 revision bigint NOT NULL DEFAULT 0, executor text, signer text, commitment text,
 next_slot integer NOT NULL DEFAULT 0, next_at bigint NOT NULL, created_at bigint NOT NULL,
 setup jsonb, cancellation jsonb, diagnostic text,
 UNIQUE(app_id,account,creation_key)
);
CREATE INDEX dca_plans_due ON dca_plans(next_at,id) WHERE status='active';
CREATE TABLE dca_runs (
 plan_id text NOT NULL REFERENCES dca_plans(id), slot integer NOT NULL CHECK(slot>=0),
 scheduled_at bigint NOT NULL, closes_at bigint NOT NULL, digest text NOT NULL,
 status text NOT NULL CHECK(status IN ('reserved','observing','succeeded','failed','skipped','unresolved')),
 generation bigint NOT NULL DEFAULT 0, lease_until bigint NOT NULL DEFAULT 0,
 operation jsonb, evidence jsonb, reason text, next_observe_at bigint NOT NULL DEFAULT 0,
 observations integer NOT NULL DEFAULT 0,
 PRIMARY KEY(plan_id,slot)
);
CREATE INDEX dca_runs_observe ON dca_runs(next_observe_at,plan_id) WHERE status IN ('reserved','observing','unresolved');
CREATE TABLE dca_runtime_records (
 plan_id text NOT NULL REFERENCES dca_plans(id), kind text NOT NULL, version text NOT NULL,
 payload jsonb NOT NULL, PRIMARY KEY(plan_id,kind)
);
CREATE TABLE dca_grants (grant_id text PRIMARY KEY, revision bigint NOT NULL, payload jsonb NOT NULL);
CREATE TABLE dca_contexts (binding_id text PRIMARY KEY, payload jsonb NOT NULL);
