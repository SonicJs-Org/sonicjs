-- Migration 0005: Full-text search index (documents_fts)
-- Lexical FTS5 index over the document model. Fed write-time by DocumentProjection
-- (the same batch that projects document_facets), keyed by document_id.
--
-- EXACT 10-column layout (3 indexed + 7 UNINDEXED), matching the design spike this ported
-- from, so the engine's bm25(documents_fts, w0..w9) 10-weight vector maps 1:1.
-- DO NOT add columns (e.g. root_id): FTS5 weights are positional and a column-count change
-- breaks the ported bm25() call with "wrong number of arguments to function bm25()".
-- root_id / deleted_at / visible are intentionally NOT here — results JOIN back to documents
-- on document_id when those are needed; visibility is kept native by deindexing at write time.
--
-- FTS5 has no ALTER TABLE ADD COLUMN: any future column change is a new migration that
-- drops + recreates this table followed by a backfill (scripts/backfill-fts.ts).

CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
  title,                  -- col 0 (indexed)
  slug,                   -- col 1 (indexed)
  body,                   -- col 2 (indexed)
  document_id UNINDEXED,  -- col 3
  type_id UNINDEXED,      -- col 4
  status UNINDEXED,       -- col 5
  created_at UNINDEXED,   -- col 6
  updated_at UNINDEXED,   -- col 7
  tenant_id UNINDEXED,    -- col 8
  is_published UNINDEXED, -- col 9
  tokenize = 'porter unicode61 remove_diacritics 2'
);
