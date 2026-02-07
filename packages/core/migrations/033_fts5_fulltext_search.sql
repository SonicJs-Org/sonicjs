-- Migration 033: FTS5 Full-Text Search for AI Search Plugin
--
-- Creates FTS5 virtual table for content full-text search with:
-- - Porter stemming (running/runs/ran -> run)
-- - Unicode support with diacritics/accent folding (cafe matches cafe)
-- - BM25 ranking with field boosting (title > slug > body)
--
-- Tokenizer: porter wraps unicode61 (porter MUST come first as it's a wrapper)
-- - porter: Applies Porter stemming algorithm to output of underlying tokenizer
-- - unicode61: Unicode-aware tokenization with ASCII folding
-- - remove_diacritics 2: Remove diacritics from ALL Unicode characters (level 2 = broadest)
--
-- Column order: Indexed columns first for cleaner bm25() weights

CREATE VIRTUAL TABLE IF NOT EXISTS content_fts USING fts5(
  title,                   -- column 0: Indexed (weight 5x at query time)
  slug,                    -- column 1: Indexed (weight 2x at query time)
  body,                    -- column 2: Main content extracted from JSON (weight 1x)
  content_id UNINDEXED,    -- column 3: Original content ID for JOINs
  collection_id UNINDEXED, -- column 4: Collection ID for filtering
  tokenize='porter unicode61 remove_diacritics 2'
);

-- Sync tracking table for indexing status
CREATE TABLE IF NOT EXISTS content_fts_sync (
  content_id TEXT PRIMARY KEY,
  collection_id TEXT NOT NULL,
  indexed_at INTEGER NOT NULL,
  status TEXT DEFAULT 'indexed'
);

CREATE INDEX IF NOT EXISTS idx_content_fts_sync_collection
  ON content_fts_sync(collection_id);

CREATE INDEX IF NOT EXISTS idx_content_fts_sync_status
  ON content_fts_sync(status);
