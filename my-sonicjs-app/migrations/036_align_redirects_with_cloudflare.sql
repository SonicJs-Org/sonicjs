-- Migration 036: Align redirects table with Cloudflare Bulk Redirects options
--
-- Changes:
-- 1. Rename preserve_query_params → preserve_query_string (Cloudflare alignment)
-- 2. Remove include_query_params (not a Cloudflare option) - column remains but unused
-- 3. Add include_subdomains column (Cloudflare: include_subdomains)
-- 4. Add subpath_matching column (Cloudflare: subpath_matching)
-- 5. Add preserve_path_suffix column (Cloudflare: preserve_path_suffix, default true)
--
-- Note: SQLite does not support DROP COLUMN, so include_query_params remains but is unused.
-- Note: SQLite does not support RENAME COLUMN in older versions, so we add new column and migrate data.

-- Step 1: Add preserve_query_string column (copy of preserve_query_params)
ALTER TABLE redirects ADD COLUMN preserve_query_string INTEGER DEFAULT 0;

-- Step 2: Copy existing data from preserve_query_params to preserve_query_string
UPDATE redirects SET preserve_query_string = COALESCE(preserve_query_params, 0);

-- Step 3: Add new Cloudflare-aligned columns
ALTER TABLE redirects ADD COLUMN include_subdomains INTEGER DEFAULT 0;
ALTER TABLE redirects ADD COLUMN subpath_matching INTEGER DEFAULT 0;
ALTER TABLE redirects ADD COLUMN preserve_path_suffix INTEGER DEFAULT 1;

-- Note: The old columns (include_query_params, preserve_query_params) remain in the table
-- but will be ignored by the application. Future migrations can clean these up.
