-- Migration 034: Ranking Pipeline for AI Search Plugin
--
-- Pipeline config stores an ordered list of scoring stages as JSON.
-- Content scores store popularity/custom values for individual content items.

CREATE TABLE IF NOT EXISTS ai_search_ranking_config (
  id TEXT PRIMARY KEY DEFAULT 'default',
  pipeline_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS ai_search_content_scores (
  content_id TEXT NOT NULL,
  score_type TEXT NOT NULL CHECK (score_type IN ('popularity', 'custom')),
  score REAL NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY (content_id, score_type)
);

CREATE INDEX IF NOT EXISTS idx_content_scores_type ON ai_search_content_scores(score_type);
