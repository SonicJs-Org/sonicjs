-- Composite index to speed up event-type-filtered queries on the events collection.
-- The existing idx_docs_type_published index returns all 200k+ events for type_id='events',
-- then each row's data column must be loaded for json_extract.  By including
-- json_extract(data,'$.event_type') as the second column in this index, the query
-- planner can seek directly to rows with a specific event_type (e.g. 'installation_failed',
-- 'project_snapshot') without reading the data column of unrelated rows.

DROP INDEX IF EXISTS idx_documents_event_type;

CREATE INDEX IF NOT EXISTS idx_documents_events_by_type
  ON documents (type_id, json_extract(data, '$.event_type'), tenant_id)
  WHERE is_published = 1 AND deleted_at IS NULL;
