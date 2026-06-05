-- Migration 038: email_log observability columns
-- Adds user_id, context linking, tenant support, and delivery reconciliation
-- columns. All nullable with no defaults (forward-only D1, NULL-safe).

ALTER TABLE email_log ADD COLUMN user_id TEXT;
ALTER TABLE email_log ADD COLUMN context_type TEXT;
ALTER TABLE email_log ADD COLUMN context_id TEXT;
ALTER TABLE email_log ADD COLUMN tenant_id TEXT;
ALTER TABLE email_log ADD COLUMN delivery_state TEXT;
ALTER TABLE email_log ADD COLUMN delivery_synced_at INTEGER;

-- Partial index for reconciliation queries: find rows with a provider_id that
-- haven't had their delivery state resolved yet.
CREATE INDEX IF NOT EXISTS idx_email_log_reconcile
  ON email_log (provider, delivery_synced_at)
  WHERE provider_id IS NOT NULL AND delivery_state IS NULL;

-- Index for per-user email history queries.
CREATE INDEX IF NOT EXISTS idx_email_log_user_id
  ON email_log (user_id)
  WHERE user_id IS NOT NULL;
