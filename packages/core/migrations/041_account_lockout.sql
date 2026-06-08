-- Account lockout: track failed login attempts on the users row.
-- After a configurable threshold (default 5), the account is locked for a
-- rolling window (default 15 minutes).  The login handler checks
-- `locked_until > now()` before attempting credential verification.  A
-- successful login resets both counters.
--
-- Separate from the `security_events` audit log (mig-034) which records
-- *what* happened; these columns drive *whether* a login is permitted.

ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until       INTEGER;

-- Index for the lockout check (login handler filters by email then checks these).
CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users(locked_until) WHERE locked_until IS NOT NULL;
