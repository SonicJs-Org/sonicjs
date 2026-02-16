-- Related Searches
-- Admin-curated and agent-approved related search pairs.

CREATE TABLE IF NOT EXISTS ai_search_related (
  id TEXT PRIMARY KEY,
  source_query TEXT NOT NULL,
  related_query TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'agent')),
  position INTEGER NOT NULL DEFAULT 0,
  bidirectional INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_related_source_query ON ai_search_related(source_query, enabled, position);
CREATE INDEX IF NOT EXISTS idx_related_source ON ai_search_related(source);
CREATE UNIQUE INDEX IF NOT EXISTS idx_related_unique_pair ON ai_search_related(source_query, related_query);
