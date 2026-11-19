-- Add a (run_id, test_id) index so the "final attempt" NOT EXISTS probe used by the dashboard's
-- Top Failing panel resolves in 1-3 rows instead of every attempt in the run (measured on
-- stats.sonicjs.com: 4.9M rows read / 5.8s before, ~99k / 170ms after).
-- Keep idx_pw_tests_run_id (9001) too: for run_id-only lookups the planner prefers
-- idx_docs_type_published over this wider index and scans every test row.
CREATE INDEX IF NOT EXISTS idx_pw_tests_run_test
  ON documents(json_extract(data, '$.run_id'), json_extract(data, '$.test_id'), is_published, deleted_at)
  WHERE type_id = 'playwright_tests';
