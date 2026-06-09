-- Migration 0001: Core Baseline (v3 greenfield)
-- Consolidated from the v2 migration set. Contains auth plus core platform tables
-- that still run alongside the document-model POC.
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  username TEXT NOT NULL UNIQUE,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  password_hash TEXT,
  role TEXT NOT NULL DEFAULT 'viewer',
  avatar TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  last_login_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  phone TEXT,
  bio TEXT,
  avatar_url TEXT,
  timezone TEXT DEFAULT 'UTC',
  language TEXT DEFAULT 'en',
  email_notifications INTEGER DEFAULT 1,
  theme TEXT DEFAULT 'dark',
  two_factor_enabled INTEGER DEFAULT 0,
  two_factor_secret TEXT,
  password_reset_token TEXT,
  password_reset_expires INTEGER,
  email_verified INTEGER DEFAULT 0,
  email_verification_token TEXT,
  invitation_token TEXT,
  invited_by TEXT REFERENCES users(id),
  invited_at INTEGER,
  accepted_invitation_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

CREATE INDEX IF NOT EXISTS idx_users_email_verification_token ON users(email_verification_token);

CREATE INDEX IF NOT EXISTS idx_users_password_reset_token ON users(password_reset_token);

CREATE INDEX IF NOT EXISTS idx_users_invitation_token ON users(invitation_token);

CREATE TABLE IF NOT EXISTS api_tokens (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES users(id),
  permissions TEXT NOT NULL,
  expires_at INTEGER,
  last_used_at INTEGER,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_api_tokens_token ON api_tokens(token);

CREATE TABLE IF NOT EXISTS password_history (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(user_id);

CREATE TABLE IF NOT EXISTS magic_links (
  id TEXT PRIMARY KEY,
  user_email TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  used INTEGER DEFAULT 0,
  used_at INTEGER,
  ip_address TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_magic_links_token ON magic_links(token);

CREATE INDEX IF NOT EXISTS idx_magic_links_email ON magic_links(user_email);

CREATE INDEX IF NOT EXISTS idx_magic_links_expires ON magic_links(expires_at);

CREATE TABLE IF NOT EXISTS otp_codes (
  id TEXT PRIMARY KEY,
  user_email TEXT NOT NULL,
  code TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER DEFAULT 0,
  used_at INTEGER,
  ip_address TEXT,
  user_agent TEXT,
  attempts INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_otp_email_code ON otp_codes(user_email, code);

CREATE INDEX IF NOT EXISTS idx_otp_expires ON otp_codes(expires_at);

CREATE INDEX IF NOT EXISTS idx_otp_used ON otp_codes(used);

CREATE TABLE IF NOT EXISTS user_profiles (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  display_name TEXT,
  bio TEXT,
  company TEXT,
  job_title TEXT,
  website TEXT,
  location TEXT,
  date_of_birth INTEGER,
  data TEXT DEFAULT '{}',
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);

CREATE INDEX IF NOT EXISTS idx_user_profiles_user_id ON user_profiles(user_id);

CREATE TRIGGER IF NOT EXISTS user_profiles_updated_at
AFTER
UPDATE
  ON user_profiles BEGIN
UPDATE
  user_profiles
SET
  updated_at = strftime('%s', 'now') * 1000
WHERE
  id = NEW.id;

END;
-- Plugin system tables (kept as dedicated tables per document-model-poc-plan.md §"Keep dedicated tables")
CREATE TABLE IF NOT EXISTS plugins (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    description TEXT,
    version TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT 'core',
    category TEXT NOT NULL DEFAULT 'core',
    icon TEXT,
    status TEXT DEFAULT 'inactive' CHECK (status IN ('active', 'inactive', 'error')),
    is_core BOOLEAN DEFAULT FALSE,
    settings JSON,
    permissions JSON,
    dependencies JSON,
    download_count INTEGER DEFAULT 0,
    rating REAL DEFAULT 0,
    installed_at INTEGER NOT NULL DEFAULT (unixepoch()),
    activated_at INTEGER,
    last_updated INTEGER NOT NULL DEFAULT (unixepoch()),
    error_message TEXT,
    created_at INTEGER DEFAULT (unixepoch()),
    updated_at INTEGER DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_plugins_status ON plugins(status);
CREATE INDEX IF NOT EXISTS idx_plugins_category ON plugins(category);

-- Plugin sub-tables
CREATE TABLE IF NOT EXISTS plugin_hooks (
  id TEXT PRIMARY KEY,
  plugin_id TEXT NOT NULL REFERENCES plugins(id),
  hook_name TEXT NOT NULL,
  handler_name TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 10,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_plugin_hooks_plugin ON plugin_hooks(plugin_id);

CREATE TABLE IF NOT EXISTS plugin_routes (
  id TEXT PRIMARY KEY,
  plugin_id TEXT NOT NULL REFERENCES plugins(id),
  path TEXT NOT NULL,
  method TEXT NOT NULL,
  handler_name TEXT NOT NULL,
  middleware TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_plugin_routes_plugin ON plugin_routes(plugin_id);

CREATE TABLE IF NOT EXISTS plugin_assets (
  id TEXT PRIMARY KEY,
  plugin_id TEXT NOT NULL REFERENCES plugins(id),
  asset_type TEXT NOT NULL,
  asset_path TEXT NOT NULL,
  load_order INTEGER NOT NULL DEFAULT 100,
  load_location TEXT NOT NULL DEFAULT 'footer',
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_plugin_assets_plugin ON plugin_assets(plugin_id);

CREATE TABLE IF NOT EXISTS plugin_activity_log (
  id TEXT PRIMARY KEY,
  plugin_id TEXT NOT NULL REFERENCES plugins(id),
  action TEXT NOT NULL,
  user_id TEXT,
  details TEXT,
  timestamp INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_plugin_activity_plugin ON plugin_activity_log(plugin_id);

-- Content collection tables (run alongside the document model POC)
CREATE TABLE IF NOT EXISTS collections (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  description TEXT,
  schema TEXT NOT NULL DEFAULT '{}',
  is_active INTEGER NOT NULL DEFAULT 1,
  managed INTEGER NOT NULL DEFAULT 0,
  source_type TEXT DEFAULT 'user',
  source_id TEXT,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_collections_name ON collections(name);
CREATE INDEX IF NOT EXISTS idx_collections_active ON collections(is_active);

CREATE TABLE IF NOT EXISTS content (
  id TEXT PRIMARY KEY,
  collection_id TEXT NOT NULL REFERENCES collections(id),
  slug TEXT NOT NULL,
  title TEXT NOT NULL,
  data TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'draft',
  published_at INTEGER,
  author_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_content_collection ON content(collection_id);
CREATE INDEX IF NOT EXISTS idx_content_author ON content(author_id);
CREATE INDEX IF NOT EXISTS idx_content_status ON content(status);
CREATE INDEX IF NOT EXISTS idx_content_slug ON content(slug);

CREATE TABLE IF NOT EXISTS content_versions (
  id TEXT PRIMARY KEY,
  content_id TEXT NOT NULL REFERENCES content(id),
  version INTEGER NOT NULL,
  data TEXT NOT NULL DEFAULT '{}',
  author_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_content_versions_content ON content_versions(content_id);

CREATE TABLE IF NOT EXISTS media (
  id TEXT PRIMARY KEY,
  filename TEXT NOT NULL,
  original_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size INTEGER NOT NULL,
  width INTEGER,
  height INTEGER,
  folder TEXT NOT NULL DEFAULT 'uploads',
  r2_key TEXT NOT NULL,
  public_url TEXT NOT NULL,
  thumbnail_url TEXT,
  alt TEXT,
  caption TEXT,
  tags TEXT,
  uploaded_by TEXT NOT NULL REFERENCES users(id),
  uploaded_at INTEGER NOT NULL,
  updated_at INTEGER,
  published_at INTEGER,
  scheduled_at INTEGER,
  archived_at INTEGER,
  deleted_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_media_folder ON media(folder);
CREATE INDEX IF NOT EXISTS idx_media_type ON media(mime_type);
CREATE INDEX IF NOT EXISTS idx_media_uploaded_by ON media(uploaded_by);
CREATE INDEX IF NOT EXISTS idx_media_deleted ON media(deleted_at);

CREATE TABLE IF NOT EXISTS workflow_history (
  id TEXT PRIMARY KEY,
  content_id TEXT NOT NULL REFERENCES content(id),
  action TEXT NOT NULL,
  from_status TEXT NOT NULL,
  to_status TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id),
  comment TEXT,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_workflow_history_content ON workflow_history(content_id);

-- System logging tables
CREATE TABLE IF NOT EXISTS system_logs (
  id TEXT PRIMARY KEY,
  level TEXT NOT NULL,
  category TEXT NOT NULL,
  message TEXT NOT NULL,
  data TEXT,
  user_id TEXT REFERENCES users(id),
  session_id TEXT,
  request_id TEXT,
  ip_address TEXT,
  user_agent TEXT,
  method TEXT,
  url TEXT,
  status_code INTEGER,
  duration INTEGER,
  stack_trace TEXT,
  tags TEXT,
  source TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_system_logs_level ON system_logs(level);
CREATE INDEX IF NOT EXISTS idx_system_logs_category ON system_logs(category);
CREATE INDEX IF NOT EXISTS idx_system_logs_created_at ON system_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_system_logs_user_id ON system_logs(user_id);

CREATE TABLE IF NOT EXISTS log_config (
  id TEXT PRIMARY KEY,
  category TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 1,
  level TEXT NOT NULL DEFAULT 'info',
  retention INTEGER NOT NULL DEFAULT 30,
  max_size INTEGER DEFAULT 10000,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO log_config (id, category, enabled, level, retention, max_size, created_at, updated_at) VALUES
  ('auth-config',     'auth',     1, 'info',  30,  10000, unixepoch() * 1000, unixepoch() * 1000),
  ('api-config',      'api',      1, 'info',   7,  50000, unixepoch() * 1000, unixepoch() * 1000),
  ('workflow-config', 'workflow', 1, 'info',  30,  10000, unixepoch() * 1000, unixepoch() * 1000),
  ('plugin-config',   'plugin',   1, 'info',  30,  10000, unixepoch() * 1000, unixepoch() * 1000),
  ('media-config',    'media',    1, 'info',  30,  10000, unixepoch() * 1000, unixepoch() * 1000),
  ('system-config',   'system',   1, 'warn',  30,  10000, unixepoch() * 1000, unixepoch() * 1000),
  ('security-config', 'security', 1, 'warn',  90,  20000, unixepoch() * 1000, unixepoch() * 1000),
  ('error-config',    'error',    1, 'error', 90,  20000, unixepoch() * 1000, unixepoch() * 1000);

-- OAuth accounts
CREATE TABLE IF NOT EXISTS oauth_accounts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  provider_account_id TEXT NOT NULL,
  access_token TEXT,
  refresh_token TEXT,
  token_expires_at INTEGER,
  profile_data TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_accounts_provider_account ON oauth_accounts(provider, provider_account_id);
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id ON oauth_accounts(user_id);
