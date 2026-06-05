-- Better Auth plugin tables for twoFactor and organization (Phase 6).
--
-- twoFactor: stores the TOTP secret, encrypted backup codes, and enrollment
--   status for each user. Added to users with two_factor_enabled (Phase 6).
--   Better Auth manages the records; we only need the DDL.
--
-- organization: multi-tenant teams — organization + member + invitation + team.
--   Activated when the organization plugin is enabled in auth/config.ts.
--   Schema mirrors Better Auth's own expected table structure for D1.

-- ─── twoFactor ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS twoFactor (
  id          TEXT    PRIMARY KEY,
  secret      TEXT    NOT NULL,
  backup_codes TEXT   NOT NULL,
  user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  verified    INTEGER NOT NULL DEFAULT 1,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_two_factor_user_id ON twoFactor(user_id);

-- Column on users to track whether 2FA is enforced for the account.
-- Better Auth reads this to decide if a second factor is required after
-- password verification.
ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0;

-- ─── organization ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS organization (
  id           TEXT    PRIMARY KEY,
  name         TEXT    NOT NULL,
  slug         TEXT    NOT NULL UNIQUE,
  logo         TEXT,
  metadata     TEXT,
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS member (
  id              TEXT    PRIMARY KEY,
  organization_id TEXT    NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
  user_id         TEXT    NOT NULL REFERENCES users(id)         ON DELETE CASCADE,
  role            TEXT    NOT NULL DEFAULT 'member',
  email           TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  UNIQUE(organization_id, user_id)
);

CREATE TABLE IF NOT EXISTS invitation (
  id              TEXT    PRIMARY KEY,
  organization_id TEXT    NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
  email           TEXT    NOT NULL,
  role            TEXT    NOT NULL DEFAULT 'member',
  status          TEXT    NOT NULL DEFAULT 'pending',
  expires_at      INTEGER NOT NULL,
  inviter_id      TEXT    REFERENCES users(id) ON DELETE SET NULL,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS team (
  id              TEXT    PRIMARY KEY,
  name            TEXT    NOT NULL,
  organization_id TEXT    NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_member_org   ON member(organization_id);
CREATE INDEX IF NOT EXISTS idx_member_user  ON member(user_id);
CREATE INDEX IF NOT EXISTS idx_invite_org   ON invitation(organization_id);
CREATE INDEX IF NOT EXISTS idx_invite_email ON invitation(email);
