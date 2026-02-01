-- QR Generator Plugin Migration
-- Version: 1.0.0
-- Description: Initialize QR generator plugin with qr_codes table

-- Insert plugin entry into plugins table
INSERT INTO plugins (
  id,
  name,
  display_name,
  description,
  version,
  author,
  category,
  status,
  settings,
  installed_at,
  last_updated
) VALUES (
  'qr-generator',
  'qr-generator',
  'QR Code Generator',
  'Generate trackable, branded QR codes with customizable styles and error correction',
  '1.0.0',
  'SonicJS Community',
  'utilities',
  'inactive',
  json('{
    "defaultForegroundColor": "#000000",
    "defaultBackgroundColor": "#ffffff",
    "defaultErrorCorrection": "M",
    "defaultSize": 300
  }'),
  strftime('%s', 'now') * 1000,
  strftime('%s', 'now') * 1000
)
ON CONFLICT(id) DO UPDATE SET
  display_name = excluded.display_name,
  description = excluded.description,
  version = excluded.version,
  updated_at = excluded.last_updated;

-- Create qr_codes table
CREATE TABLE IF NOT EXISTS qr_codes (
  id TEXT PRIMARY KEY,
  name TEXT,
  destination_url TEXT NOT NULL,
  foreground_color TEXT NOT NULL DEFAULT '#000000',
  background_color TEXT NOT NULL DEFAULT '#ffffff',
  error_correction TEXT NOT NULL DEFAULT 'M',
  size INTEGER NOT NULL DEFAULT 300,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted_at INTEGER
);

-- Create indexes for qr_codes table
CREATE INDEX IF NOT EXISTS idx_qr_codes_created_by ON qr_codes(created_by);
CREATE INDEX IF NOT EXISTS idx_qr_codes_created_at ON qr_codes(created_at);
CREATE INDEX IF NOT EXISTS idx_qr_codes_deleted_at ON qr_codes(deleted_at);
CREATE INDEX IF NOT EXISTS idx_qr_codes_destination ON qr_codes(destination_url);
