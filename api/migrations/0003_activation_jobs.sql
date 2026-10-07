ALTER TABLE dca_plans ADD COLUMN next_setup_at bigint NOT NULL DEFAULT 0;
CREATE INDEX dca_plans_setup ON dca_plans(next_setup_at,id) WHERE status IN ('awaiting_consent','authorized');
