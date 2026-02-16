-- Search A/B Testing: experiments table + D1 fallback events table
-- Timestamps set in TypeScript as Date.now() (milliseconds) — no DEFAULT functions

CREATE TABLE IF NOT EXISTS ai_search_experiments (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'draft'
    CHECK (status IN ('draft', 'running', 'paused', 'completed', 'archived')),
  mode TEXT NOT NULL DEFAULT 'ab'
    CHECK (mode IN ('ab', 'interleave', 'bandit')),
  traffic_pct REAL NOT NULL DEFAULT 100,
  split_ratio REAL NOT NULL DEFAULT 0.5,
  variants TEXT NOT NULL,
  metrics TEXT,
  winner TEXT,
  confidence REAL,
  min_searches INTEGER NOT NULL DEFAULT 100,
  started_at INTEGER,
  ended_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_experiments_status ON ai_search_experiments(status);
CREATE INDEX IF NOT EXISTS idx_experiments_created ON ai_search_experiments(created_at DESC);

-- D1 fallback table for experiment events (used when Analytics Engine binding is unavailable, e.g. local dev)
-- Schema mirrors Analytics Engine blobs/doubles but with typed columns
CREATE TABLE IF NOT EXISTS ai_search_experiment_events (
  id TEXT PRIMARY KEY,
  experiment_id TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('search', 'click')),
  variant_id TEXT NOT NULL,
  query TEXT,
  search_mode TEXT,
  user_id TEXT,
  search_id TEXT,
  content_id TEXT,
  results_count INTEGER,
  response_time_ms REAL,
  click_position INTEGER,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exp_events_experiment ON ai_search_experiment_events(experiment_id, event_type);
CREATE INDEX IF NOT EXISTS idx_exp_events_created ON ai_search_experiment_events(created_at DESC);
