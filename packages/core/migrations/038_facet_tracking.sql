-- Facet interaction tracking for Phase 6 agent optimization
CREATE TABLE IF NOT EXISTS ai_search_facet_clicks (
  id TEXT PRIMARY KEY,
  search_id TEXT,              -- references ai_search_history.id (nullable)
  facet_field TEXT NOT NULL,   -- e.g. "collection_name", "$.tags", "status"
  facet_value TEXT NOT NULL,   -- the value that was clicked/selected
  created_at TEXT DEFAULT (datetime('now'))
);

-- Index for agent weekly analysis (field usage over time)
CREATE INDEX IF NOT EXISTS idx_facet_clicks_field ON ai_search_facet_clicks(facet_field, created_at);
