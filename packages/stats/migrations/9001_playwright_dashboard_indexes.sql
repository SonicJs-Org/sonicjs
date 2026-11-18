-- Stats-only migration (numbered 9xxx to stay clear of core's 000N sequence).
--
-- Playwright dashboard looks up runs and test attempts by json_extract(data, '$.run_id').
-- Without an index every lookup scans all playwright_tests documents (~70k on
-- stats.sonicjs.com), and the run-details page's per-row lookups exceeded D1's CPU limit.
-- Partial expression indexes: the expression must match the query text
-- json_extract(data, '$.run_id') and the query must filter type_id = '<literal>'.
CREATE INDEX IF NOT EXISTS idx_pw_tests_run_id
  ON documents(json_extract(data, '$.run_id'), is_published, deleted_at)
  WHERE type_id = 'playwright_tests';

CREATE INDEX IF NOT EXISTS idx_pw_runs_run_id
  ON documents(json_extract(data, '$.run_id'), is_published, deleted_at)
  WHERE type_id = 'playwright_runs';
