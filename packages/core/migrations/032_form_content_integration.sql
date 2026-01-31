-- Migration 032: Form-Content Integration
-- Adds bridge columns to link forms to collections and submissions to content items

-- Add source_type and source_id to collections for form-derived collections
ALTER TABLE collections ADD COLUMN source_type TEXT DEFAULT 'user';
ALTER TABLE collections ADD COLUMN source_id TEXT;

-- Index for efficient lookup of form-derived collections
CREATE INDEX IF NOT EXISTS idx_collections_source ON collections(source_type, source_id);

-- Add content_id to form_submissions for linking to content items
ALTER TABLE form_submissions ADD COLUMN content_id TEXT REFERENCES content(id);

-- Index for efficient lookup by content_id
CREATE INDEX IF NOT EXISTS idx_form_submissions_content_id ON form_submissions(content_id);

-- Create system user for anonymous form submissions
INSERT OR IGNORE INTO users (id, email, username, first_name, last_name, password_hash, role, is_active, created_at, updated_at)
VALUES ('system-form-submission', 'system-forms@sonicjs.internal', 'system-forms', 'Form', 'Submission', NULL, 'viewer', 0, strftime('%s','now') * 1000, strftime('%s','now') * 1000);
