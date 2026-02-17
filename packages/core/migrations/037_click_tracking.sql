-- Click events table
CREATE TABLE IF NOT EXISTS ai_search_clicks (
  id TEXT PRIMARY KEY,
  search_id TEXT,                -- references ai_search_history.id (nullable for older searches)
  query TEXT NOT NULL,           -- denormalized for fast analytics queries
  mode TEXT,                     -- search mode used
  clicked_content_id TEXT NOT NULL,  -- the content item ID that was clicked
  clicked_content_title TEXT,    -- denormalized title for reporting without joins
  click_position INTEGER NOT NULL,   -- 1-based position in results list (1 = first result)
  created_at TEXT DEFAULT (datetime('now'))
);

-- Indexes for analytics queries
CREATE INDEX IF NOT EXISTS idx_clicks_search_id ON ai_search_clicks(search_id);
CREATE INDEX IF NOT EXISTS idx_clicks_query ON ai_search_clicks(query, created_at);
CREATE INDEX IF NOT EXISTS idx_clicks_content ON ai_search_clicks(clicked_content_id, created_at);
CREATE INDEX IF NOT EXISTS idx_clicks_created ON ai_search_clicks(created_at);
