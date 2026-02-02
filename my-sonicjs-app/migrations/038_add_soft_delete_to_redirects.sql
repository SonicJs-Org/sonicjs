-- Migration: Add soft delete support to redirects table
-- Adds deleted_at column for soft delete timestamp (NULL = not deleted)

ALTER TABLE redirects ADD COLUMN deleted_at INTEGER DEFAULT NULL;

-- Create index for efficient filtering of non-deleted records
CREATE INDEX IF NOT EXISTS idx_redirects_deleted_at ON redirects(deleted_at);
