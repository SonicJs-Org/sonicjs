-- Migration 0008: index for the /admin/content "All" view.
--
-- The All view lists every current, non-deleted document for a tenant ordered by updated_at.
-- Without an index matching that filter + sort, SQLite reads every document and sorts it in a
-- temp B-tree on each page load. On telemetry-heavy installs (stats.sonicjs.com: ~260k documents,
-- 1.4 GB) that read ~785k rows per request and tripped D1's "overloaded / too many resources
-- consumed within a 10 second window" limit. With this index the planner walks it in order and
-- stops after LIMIT rows.
CREATE INDEX IF NOT EXISTS idx_docs_tenant_draft_updated
  ON documents(tenant_id, is_current_draft, deleted_at, updated_at DESC);
