-- Index on json_extract(data, '$.event_type') for the events documents.
-- Without this, every stats dashboard query that filters by event_type (e.g.
-- installation_started, project_snapshot, demo_login) performs a full table
-- scan of all 200k+ events rows.  This expression index lets SQLite skip to
-- only the rows with the requested event_type, cutting the scan from ~200k
-- to a few hundred or thousand rows per query.

CREATE INDEX IF NOT EXISTS idx_documents_event_type
  ON documents (json_extract(data, '$.event_type'))
  WHERE type_id = 'events'
    AND tenant_id = 'default'
    AND is_published = 1
    AND deleted_at IS NULL;
