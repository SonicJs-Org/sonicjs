-- Migration: Add logo and shape columns to qr_codes table
-- Version: 1.1.0 (Phase 2: Advanced Styling)

-- Add logo embedding columns (STYLE-03, STYLE-04)
ALTER TABLE qr_codes ADD COLUMN logo_url TEXT DEFAULT NULL;
ALTER TABLE qr_codes ADD COLUMN logo_aspect_ratio REAL DEFAULT NULL;
ALTER TABLE qr_codes ADD COLUMN error_correction_before_logo TEXT DEFAULT NULL;

-- Add shape customization columns (STYLE-05, STYLE-06)
ALTER TABLE qr_codes ADD COLUMN corner_shape TEXT DEFAULT 'square';
ALTER TABLE qr_codes ADD COLUMN dot_shape TEXT DEFAULT 'square';

-- Add eye color column (STYLE-07)
ALTER TABLE qr_codes ADD COLUMN eye_color TEXT DEFAULT NULL;

-- Update plugin version
UPDATE plugins SET version = '1.1.0', last_updated = strftime('%s', 'now') * 1000 WHERE id = 'qr-generator';
