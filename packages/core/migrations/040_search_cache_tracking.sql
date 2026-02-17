-- Track whether a search result was served from cache
ALTER TABLE ai_search_history ADD COLUMN cached INTEGER DEFAULT 0;
