-- Drop OTP and Magic Link plugin tables
-- Migration: 033_drop_otp_and_magic_link_tables
-- Description: Remove magic_links and otp_codes tables (plugins removed in favor of Better Auth extendBetterAuth)

-- Drop magic link auth table and indexes (indexes are dropped with the table in SQLite)
DROP TABLE IF EXISTS magic_links;

-- Drop OTP login table and indexes
DROP TABLE IF EXISTS otp_codes;

-- Remove plugin registry entries so they no longer appear in admin
DELETE FROM plugins WHERE id IN ('magic-link-auth', 'otp-login');
