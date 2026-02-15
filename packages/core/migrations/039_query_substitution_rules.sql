-- Query Substitution Rules
-- Deterministic pre-dispatch query replacement: "if user searches X, replace with Y"
-- Runs before all search modes (FTS5, AI, keyword, hybrid)

CREATE TABLE IF NOT EXISTS ai_search_query_rules (
  id TEXT PRIMARY KEY,
  match_pattern TEXT NOT NULL,
  match_type TEXT NOT NULL DEFAULT 'exact' CHECK (match_type IN ('exact', 'prefix')),
  substitute_query TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  priority INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_query_rules_enabled ON ai_search_query_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_query_rules_priority ON ai_search_query_rules(priority DESC);
