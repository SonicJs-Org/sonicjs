-- Migration 035: Query Synonyms for AI Search Plugin
--
-- Stores bidirectional synonym groups where all terms are equivalent.
-- Searching for any term in a group expands the query to include all terms.

CREATE TABLE IF NOT EXISTS ai_search_synonyms (
  id TEXT PRIMARY KEY,
  terms TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_ai_search_synonyms_enabled ON ai_search_synonyms(enabled);
