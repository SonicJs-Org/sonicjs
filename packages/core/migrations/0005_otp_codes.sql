-- Migration 0005: OTP codes table
-- The otp-login plugin (OTPService) INSERT/SELECT/UPDATE/DELETE rows in
-- `otp_codes` on /auth/otp/request, /verify, /resend and the admin activity
-- page. The DDL was dropped with the plugin-management document-model change
-- but the service still requires the table — without it OTP sign-in 500s with
-- `no such table: otp_codes`.
--
-- Columns match the OTPService.OTPCode interface in
-- src/plugins/core-plugins/otp-login-plugin/otp-service.ts.

CREATE TABLE IF NOT EXISTS otp_codes (
  id TEXT PRIMARY KEY,
  user_email TEXT NOT NULL,
  code TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  used_at INTEGER,
  ip_address TEXT,
  user_agent TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_otp_codes_user_email ON otp_codes(user_email);
CREATE INDEX IF NOT EXISTS idx_otp_codes_expires_at ON otp_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_otp_codes_email_code ON otp_codes(user_email, code);
