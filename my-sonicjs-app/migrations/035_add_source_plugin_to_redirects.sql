-- Add source_plugin column to track which plugin created the redirect
-- NULL = created via admin UI, otherwise contains plugin ID (e.g., 'qr-code')
ALTER TABLE redirects ADD COLUMN source_plugin TEXT;

-- Add index for filtering by source plugin
CREATE INDEX IF NOT EXISTS idx_redirects_source_plugin ON redirects(source_plugin);
