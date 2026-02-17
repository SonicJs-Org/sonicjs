-- Add response time tracking to search history for analytics
ALTER TABLE ai_search_history ADD COLUMN response_time_ms INTEGER;

-- Index for zero-result query lookups
CREATE INDEX IF NOT EXISTS idx_ai_search_history_results ON ai_search_history(results_count);
