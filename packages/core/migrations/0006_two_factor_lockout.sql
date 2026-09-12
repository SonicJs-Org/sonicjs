-- Migration 0006: Two-factor second-factor lockout columns
--
-- `auth_two_factor` already ships in 0001_core.sql, but only with the four columns Better
-- Auth's twoFactor plugin needs to STORE an enrolment (secret / backup_codes / user_id /
-- verified). It is missing the two columns the plugin writes on every VERIFY once
-- `accountLockout` is enabled, so composing the plugin against the 0001 shape fails at the
-- first `/two-factor/enable` (BA fills schema defaults on create, so the INSERT already
-- names failed_verification_count).
--
-- Deliberately an ALTER in its own migration rather than an edit to 0001: D1 tracks applied
-- migrations by FILENAME in `d1_migrations`, so an edit to 0001 would only reach greenfield
-- installs and silently skip every DB that already ran it. As an ALTER, greenfield and
-- already-migrated installs converge on the same shape.
--
-- There is also a runtime self-heal for these two columns in
-- `MigrationService.ensureSchemaCompatibility()` (PRAGMA table_xinfo + ALTER, the same D45
-- pattern used for the documents `q_*` columns). Belt and braces: a deployment that never
-- ran this migration would otherwise 500 on enrolment instead of repairing itself.

-- Consecutive failed second-factor verifications.
--
-- NOT NULL DEFAULT 0 is load-bearing, not cosmetic. BA compiles the lockout bump to
-- `failed_verification_count = failed_verification_count + 1` (incrementOne), and
-- `NULL + 1` is NULL, which verify-two-factor.mjs then reads back through `?? 0` as zero —
-- forever. A nullable column here means the lockout silently never trips.
ALTER TABLE auth_two_factor ADD COLUMN failed_verification_count INTEGER NOT NULL DEFAULT 0;

-- When the per-account second-factor lockout expires.
--
-- INTEGER (milliseconds), NOT the TEXT/ISO the sibling Infowall port uses. `lockedUntil` is
-- a Better Auth `date` field, and its handling depends on the ADAPTER: the kysely adapter
-- sets `supportsDates: false`, so BA stringifies to ISO before the write. SonicJS is on the
-- **drizzle** adapter (better-auth-cloudflare → drizzleAdapter, provider 'sqlite'), which
-- leaves `supportsDates` at its `true` default, so BA hands drizzle a real `Date` and the
-- column mode does the conversion. Declared here to match
-- `authTwoFactor.lockedUntil = integer('locked_until', { mode: 'timestamp_ms' })` in
-- db/schema.ts — the same declaration auth_session.expires_at already uses.
ALTER TABLE auth_two_factor ADD COLUMN locked_until INTEGER;
