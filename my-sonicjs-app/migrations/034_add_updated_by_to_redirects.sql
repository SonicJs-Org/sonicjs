-- Add updated_by column to track who last modified each redirect
ALTER TABLE redirects ADD COLUMN updated_by TEXT REFERENCES users(id);

-- Add index for JOIN performance
CREATE INDEX IF NOT EXISTS idx_redirects_updated_by ON redirects(updated_by);

-- Backfill existing records (set updated_by = created_by for existing redirects)
UPDATE redirects SET updated_by = created_by WHERE updated_by IS NULL;
