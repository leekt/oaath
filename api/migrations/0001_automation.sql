CREATE TABLE automation_plans (
 id text PRIMARY KEY, app_id text NOT NULL, account text NOT NULL,
 user_id text NOT NULL, key_scope text NOT NULL CHECK(key_scope IN ('user','application')),
 recipe text NOT NULL CHECK(recipe='dca.v1'), fee_terms jsonb NOT NULL,
 next_cleanup_at bigint NOT NULL DEFAULT 0, next_setup_at bigint NOT NULL DEFAULT 0,
 creation_key text NOT NULL, input_digest text NOT NULL, terms jsonb NOT NULL,
 status text NOT NULL CHECK(status IN ('draft','awaiting_consent','authorized','active','paused','cancelling','cancelled','completed','expired')),
 revision bigint NOT NULL DEFAULT 0, executor text, signer text, commitment text,
 next_slot integer NOT NULL DEFAULT 0, next_at bigint NOT NULL, created_at bigint NOT NULL,
 setup jsonb, cancellation jsonb, diagnostic text,
 UNIQUE(app_id,account,creation_key)
);

CREATE TABLE automation_runs (
 plan_id text NOT NULL REFERENCES automation_plans(id), slot integer NOT NULL CHECK(slot>=0),
 scheduled_at bigint NOT NULL, closes_at bigint NOT NULL, digest text NOT NULL,
 status text NOT NULL CHECK(status IN ('reserved','observing','succeeded','failed','skipped','unresolved')),
 generation bigint NOT NULL DEFAULT 0, lease_until bigint NOT NULL DEFAULT 0,
 operation jsonb, evidence jsonb, reason text, cleanup_diagnostic text, next_observe_at bigint NOT NULL DEFAULT 0,
 observations integer NOT NULL DEFAULT 0,
 PRIMARY KEY(plan_id,slot)
);
CREATE INDEX automation_runs_observe ON automation_runs(next_observe_at,plan_id) WHERE status IN ('reserved','observing','unresolved');
CREATE TABLE automation_runtime_records (
 plan_id text NOT NULL REFERENCES automation_plans(id), kind text NOT NULL, version text NOT NULL,
 payload jsonb NOT NULL, PRIMARY KEY(plan_id,kind)
);
CREATE TABLE automation_grants (grant_id text PRIMARY KEY, revision bigint NOT NULL, payload jsonb NOT NULL);
CREATE TABLE automation_contexts (binding_id text PRIMARY KEY, payload jsonb NOT NULL);

CREATE INDEX automation_plans_cleanup ON automation_plans(next_cleanup_at,id) WHERE status='cancelling';

CREATE INDEX automation_plans_setup ON automation_plans(next_setup_at,id) WHERE status IN ('awaiting_consent','authorized');

CREATE INDEX automation_plans_due ON automation_plans(next_at,id) WHERE status IN ('active','paused');


CREATE TABLE automation_applications (
 app_id text PRIMARY KEY, key_scope text NOT NULL DEFAULT 'user' CHECK(key_scope IN ('user','application'))
);
CREATE TABLE automation_sessions (
 token_hash text PRIMARY KEY, app_id text NOT NULL, user_id text NOT NULL,
 account text NOT NULL, expires_at bigint NOT NULL
);
CREATE INDEX automation_sessions_expiry ON automation_sessions(expires_at);
CREATE INDEX automation_plans_user ON automation_plans(app_id,user_id,created_at,id);
