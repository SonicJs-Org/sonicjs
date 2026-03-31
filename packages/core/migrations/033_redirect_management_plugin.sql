-- Redirect Management Plugin Migration
-- Version: 1.0.0
-- Description: Initialize redirect management plugin with redirects, analytics,
--   Cloudflare Bulk Redirects alignment, source plugin tracking, and soft delete

-- Insert plugin entry into plugins table
INSERT INTO plugins (
  id, name, display_name, description, version, author, category,
  status, settings, installed_at, last_updated
) VALUES (
  'redirect-management',
  'redirect-management',
  'Redirect Management',
  'URL redirect management with exact, wildcard, and regex matching',
  '1.0.0',
  'ahaas',
  'utilities',
  'inactive',
  json('{"enabled": true, "autoOffloadEnabled": false}'),
  strftime('%s', 'now') * 1000,
  strftime('%s', 'now') * 1000
)
ON CONFLICT(id) DO UPDATE SET
  display_name = excluded.display_name,
  description = excluded.description,
  version = excluded.version,
  updated_at = excluded.last_updated;

-- Create redirects table with all columns (Cloudflare-aligned)
CREATE TABLE IF NOT EXISTS redirects (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  destination TEXT NOT NULL,
  match_type INTEGER NOT NULL DEFAULT 0,
  status_code INTEGER NOT NULL DEFAULT 301,
  is_active INTEGER NOT NULL DEFAULT 1,
  preserve_query_string INTEGER DEFAULT 0,
  include_subdomains INTEGER DEFAULT 0,
  subpath_matching INTEGER DEFAULT 0,
  preserve_path_suffix INTEGER DEFAULT 1,
  source_plugin TEXT,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  updated_by TEXT,
  deleted_at INTEGER DEFAULT NULL
);

-- Create indexes for redirects table
CREATE INDEX IF NOT EXISTS idx_redirects_source ON redirects(source);
CREATE INDEX IF NOT EXISTS idx_redirects_active ON redirects(is_active);
CREATE INDEX IF NOT EXISTS idx_redirects_match_type ON redirects(match_type);
CREATE INDEX IF NOT EXISTS idx_redirects_source_plugin ON redirects(source_plugin);
CREATE INDEX IF NOT EXISTS idx_redirects_deleted_at ON redirects(deleted_at);

-- Create redirect_analytics table
CREATE TABLE IF NOT EXISTS redirect_analytics (
  id TEXT PRIMARY KEY,
  redirect_id TEXT NOT NULL REFERENCES redirects(id) ON DELETE CASCADE,
  hit_count INTEGER NOT NULL DEFAULT 0,
  last_hit_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Create UNIQUE index for redirect_analytics table (required for ON CONFLICT)
CREATE UNIQUE INDEX IF NOT EXISTS idx_redirect_analytics_redirect_id ON redirect_analytics(redirect_id);
