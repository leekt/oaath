DROP INDEX dca_plans_due;
CREATE INDEX dca_plans_due ON dca_plans(next_at,id) WHERE status IN ('active','paused');
