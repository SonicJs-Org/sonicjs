-- User Profiles Table (Core Migration)
-- Stores extended user profile data separate from auth concerns
-- Required by admin-users.ts for user edit page profile management
--
-- Originally introduced as app-level migration (my-sonicjs-app/migrations/018_user_profiles.sql)
-- in upstream PR #508. Core routes (admin-users.ts) were updated to query this table in PR #512,
-- but no corresponding core migration was added. This migration corrects that gap.
--
-- IF NOT EXISTS guards ensure idempotency for databases that already have the table
-- from the app-level migration.

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

  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);

-- Index for fast user lookups
CREATE INDEX IF NOT EXISTS idx_user_profiles_user_id ON user_profiles(user_id);

-- Trigger to auto-update updated_at timestamp
CREATE TRIGGER IF NOT EXISTS user_profiles_updated_at
  AFTER UPDATE ON user_profiles
BEGIN
  UPDATE user_profiles SET updated_at = strftime('%s', 'now') * 1000 WHERE id = NEW.id;
END;
