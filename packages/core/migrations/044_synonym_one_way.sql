-- Add one-way synonym support
-- synonym_type: 'bidirectional' (default, existing behavior) or 'one_way'
-- source_term: for one_way, the trigger term that activates expansion (NULL for bidirectional)
ALTER TABLE ai_search_synonyms ADD COLUMN synonym_type TEXT NOT NULL DEFAULT 'bidirectional';
ALTER TABLE ai_search_synonyms ADD COLUMN source_term TEXT;
