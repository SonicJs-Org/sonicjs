-- Add query parameter handling columns to redirects table
-- Version: 1.0.1
-- Description: Add include_query_params and preserve_query_params columns

ALTER TABLE redirects ADD COLUMN include_query_params INTEGER NOT NULL DEFAULT 0;
ALTER TABLE redirects ADD COLUMN preserve_query_params INTEGER NOT NULL DEFAULT 0;
