-- Add import_source column to track which recommendations came from file imports
-- NULL for agent-generated recommendations, filename for imported ones
ALTER TABLE ai_search_recommendations ADD COLUMN import_source TEXT;
