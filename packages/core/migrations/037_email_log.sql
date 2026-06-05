-- Email log
-- One row per email send attempt routed through the core, provider-agnostic
-- EmailService. Replaces the per-flow ad-hoc sends that wrote nowhere.
-- Timestamps are epoch milliseconds (plain integers).

CREATE TABLE IF NOT EXISTS email_log (
  id TEXT PRIMARY KEY,
  to_email TEXT NOT NULL,            -- comma-joined recipients
  from_email TEXT NOT NULL,
  subject TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',  -- 'pending' | 'sent' | 'failed'
  provider TEXT,                     -- 'resend' | 'sendgrid' | 'console' | custom
  provider_id TEXT,                  -- provider-side message id
  error TEXT,
  flow TEXT,                         -- 'password-reset' | 'otp' | 'magic-link' | 'welcome' | 'test' | ...
  metadata TEXT,                     -- JSON
  failed_at_send INTEGER,            -- epoch ms; set when the send failed immediately
  delivery_state TEXT,               -- populated by the reconciliation cron
  delivery_synced_at INTEGER,        -- epoch ms; reconciliation sync marker
  created_at INTEGER NOT NULL        -- epoch ms
);

CREATE INDEX IF NOT EXISTS idx_email_log_created_at ON email_log(created_at);
CREATE INDEX IF NOT EXISTS idx_email_log_status ON email_log(status);
CREATE INDEX IF NOT EXISTS idx_email_log_to_email ON email_log(to_email);
CREATE INDEX IF NOT EXISTS idx_email_log_flow ON email_log(flow);
CREATE INDEX IF NOT EXISTS idx_email_log_delivery_synced_at ON email_log(delivery_synced_at);
