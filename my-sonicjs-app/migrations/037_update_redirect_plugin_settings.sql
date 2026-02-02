-- Migration: Update redirect-management plugin author and add autoOffloadEnabled setting
-- This updates the plugin metadata after the Cloudflare Bulk Redirects integration

UPDATE plugins
SET
  author = 'ahaas',
  settings = json_set(
    COALESCE(settings, '{}'),
    '$.autoOffloadEnabled',
    json('false')
  )
WHERE id = 'redirect-management';
