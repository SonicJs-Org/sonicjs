-- Migration: Fix media.uploaded_at units (seconds -> milliseconds)
-- Description: Media uploads historically stored `uploaded_at` in epoch SECONDS
--   (Math.floor(Date.now()/1000)) while the admin renderers read it as epoch
--   MILLISECONDS (new Date(uploaded_at)). Existing uploads therefore display as
--   January 1970 and sort below newer rows. The upload routes now store
--   milliseconds (Date.now()), matching the rest of core (content tables use
--   Date.now()). Normalize legacy seconds-valued rows to milliseconds.
--
--   The 100000000000 (1e11) threshold is ~1973 in milliseconds, so this only
--   touches the broken seconds-valued rows and is safe to re-run (already-ms
--   rows are far above the threshold and are skipped).
-- Created: 2026-06-13

UPDATE media
SET uploaded_at = uploaded_at * 1000
WHERE uploaded_at IS NOT NULL
  AND uploaded_at < 100000000000;
