-- Add short_code column to qr_codes table for redirect integration
-- This column stores the 6-character alphanumeric code used in /qr/{code} redirects
-- Phase 3: Redirect Integration

ALTER TABLE qr_codes ADD COLUMN short_code TEXT;

-- Create unique index for fast lookups and collision prevention
-- Partial index only on non-null values since existing records won't have short_code
CREATE UNIQUE INDEX idx_qr_codes_short_code ON qr_codes(short_code) WHERE short_code IS NOT NULL;
