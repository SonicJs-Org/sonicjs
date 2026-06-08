-- Better Auth integration.
-- Reuses the existing `users` table as Better Auth's user model (no new user
-- table, no FK rewrite). Adds the display-name column Better Auth requires,
-- creates session/account/verification tables, and backfills credential
-- accounts from existing password_hash so legacy users keep logging in.

-- Display name (Better Auth requires user.name for registration)
ALTER TABLE users ADD COLUMN name TEXT;

-- Backfill name from first/last for existing rows
UPDATE users
SET name = TRIM(COALESCE(first_name, '') || ' ' || COALESCE(last_name, ''))
WHERE name IS NULL OR name = '';

-- Sessions (DB-backed, cookie sessions)
CREATE TABLE IF NOT EXISTS session (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_user_id ON session(user_id);
CREATE INDEX IF NOT EXISTS idx_session_token ON session(token);
CREATE INDEX IF NOT EXISTS idx_session_expires_at ON session(expires_at);

-- Accounts (credential + OAuth providers)
CREATE TABLE IF NOT EXISTS account (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_id TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  access_token TEXT,
  refresh_token TEXT,
  access_token_expires_at INTEGER,
  refresh_token_expires_at INTEGER,
  scope TEXT,
  id_token TEXT,
  password TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_account_user_id ON account(user_id);
CREATE INDEX IF NOT EXISTS idx_account_provider ON account(provider_id, account_id);

-- Verification (email verification, password reset, etc.)
CREATE TABLE IF NOT EXISTS verification (
  id TEXT PRIMARY KEY,
  identifier TEXT NOT NULL,
  value TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verification_identifier ON verification(identifier);

-- Backfill credential accounts for existing users so their legacy PBKDF2 hash
-- is verifiable on next login (and transparently upgraded by auth/config.ts).
INSERT OR IGNORE INTO account (id, user_id, account_id, provider_id, password, created_at, updated_at)
SELECT 'cred-' || u.id, u.id, u.id, 'credential', u.password_hash, unixepoch() * 1000, unixepoch() * 1000
FROM users u
WHERE u.password_hash IS NOT NULL AND u.password_hash <> '';
