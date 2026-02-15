CREATE TABLE IF NOT EXISTS ai_search_recommendations (
  id TEXT PRIMARY KEY,
  category TEXT NOT NULL CHECK (category IN ('synonym', 'query_rule', 'low_ctr', 'unused_facet', 'content_gap')),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  supporting_data TEXT NOT NULL,
  action_payload TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'applied', 'dismissed')),
  fingerprint TEXT NOT NULL,
  run_id TEXT NOT NULL,
  applied_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_recommendations_status ON ai_search_recommendations(status);
CREATE INDEX IF NOT EXISTS idx_recommendations_category ON ai_search_recommendations(category);
CREATE INDEX IF NOT EXISTS idx_recommendations_fingerprint ON ai_search_recommendations(fingerprint);
CREATE INDEX IF NOT EXISTS idx_recommendations_created ON ai_search_recommendations(created_at DESC);

CREATE TABLE IF NOT EXISTS ai_search_agent_runs (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed')),
  recommendations_count INTEGER DEFAULT 0,
  duration_ms INTEGER,
  error_message TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  completed_at INTEGER
);
