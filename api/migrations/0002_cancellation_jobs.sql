ALTER TABLE dca_plans ADD COLUMN next_cleanup_at bigint NOT NULL DEFAULT 0;
CREATE INDEX dca_plans_cleanup ON dca_plans(next_cleanup_at,id) WHERE status='cancelling';
