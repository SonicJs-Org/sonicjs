-- Add active_organization_id to auth_session for Better Auth organization plugin.
-- The organization plugin writes this field when setting the active tenant on a session.
-- Missing column causes a D1 "no such column" error on sign-in (session INSERT fails → 500).
ALTER TABLE auth_session ADD COLUMN active_organization_id TEXT;
