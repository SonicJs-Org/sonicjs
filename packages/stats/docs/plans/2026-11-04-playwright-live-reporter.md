# Playwright Live Reporter Implementation Plan

**Goal:** Stream E2E test results to the stats dashboard in real time — one file-batch at a time — so the run detail page updates as tests finish rather than waiting for the full run to complete.

**Architecture:**
- A custom Playwright `Reporter` class opens a run on `onBegin`, flushes each file's tests to the API as they complete, and seals the run on `onEnd`.
- Three new API endpoints handle the lifecycle: start / append-tests / complete.
- The dashboard detects `run_status = 'running'` and auto-refreshes the run detail page every 5 s.

**Tech Stack:** TypeScript, Hono, D1, Playwright Reporter API (`@playwright/test`), Cloudflare Workers

**Worktree:** `../sonicjs-pw-live-reporter` on branch `feat/playwright-live-reporter`

---

## Task 1 — New ingest endpoint: `POST /v1/playwright-runs/start`

**Objective:** Create a "running" run record in D1 and return the internal doc ID so the reporter can reference it.

**File:** `packages/stats/src/routes/playwright-ingest.ts`

Add a `POST /start` route (before the existing `POST /`).

Accepts:
```json
{
  "run_id": "local-1234567890",
  "project": "sonicjs",
  "branch": "main",
  "commit_sha": "abc123",
  "commit_message": "...",
  "ci_provider": "local",
  "ci_run_url": "",
  "triggered_by": "manual",
  "source": "local",
  "started_at": "2026-11-04T10:00:00.000Z"
}
```

Returns `{ success: true, run_id: "local-1234567890" }` with status 201.

Inserts into `documents` with:
- `type_id = 'playwright_runs'`
- `is_published = 1`
- `data` JSON includes `run_status: 'running'` (no `finished_at` yet, all counts = 0)

**Commit:** `feat(stats): add POST /v1/playwright-runs/start endpoint`

---

## Task 2 — New ingest endpoint: `POST /v1/playwright-runs/:run_id/tests`

**Objective:** Append a batch of test results to an existing run. Used after each file finishes.

**File:** `packages/stats/src/routes/playwright-ingest.ts`

Add a `POST /:run_id/tests` route.

Accepts: `{ tests: Array<{ test_id, test_title, test_file, project_name, status, duration_ms, retry, is_flaky, error_message }> }`

Behaviour:
- Uses the existing test insert logic (batch D1 inserts) — reuse helper function extracted from the existing `POST /`
- Returns `{ success: true, tests_stored: N }`

Does NOT update run aggregate counts (that happens on `/complete`).

**Commit:** `feat(stats): add POST /v1/playwright-runs/:run_id/tests endpoint`

---

## Task 3 — New ingest endpoint: `POST /v1/playwright-runs/:run_id/complete`

**Objective:** Seal the run — compute final counts from stored tests, write `finished_at`, set `run_status = 'complete'`.

**File:** `packages/stats/src/routes/playwright-ingest.ts`

Add a `POST /:run_id/complete` route.

Accepts:
```json
{
  "finished_at": "2026-11-04T10:05:00.000Z",
  "duration_ms": 300000,
  "run_status": "complete"
}
```

Behaviour:
- Queries D1 for all tests belonging to `run_id` to recompute pass/fail/skip/flaky counts (same final-attempt logic as existing `POST /`)
- Updates the run document's `data` JSON with final counts, `finished_at`, `run_status`, `duration_ms`
- Returns `{ success: true, summary: { total, passed, failed, skipped, flaky } }`

**Commit:** `feat(stats): add POST /v1/playwright-runs/:run_id/complete endpoint`

---

## Task 4 — Mount new routes in `index.ts`

**Objective:** Wire the three new endpoints so the Worker exposes them.

**File:** `packages/stats/src/index.ts`

The existing mount is:
```typescript
app.route('/v1/playwright-runs', playwrightIngest)
```

The new routes live on the same `playwrightIngest` Hono instance, so no change needed to `index.ts` — just verify `POST /v1/playwright-runs/start` and `POST /v1/playwright-runs/:run_id/tests` resolve correctly.

Type-check: `cd packages/stats && npm run type-check`

**Commit:** `chore(stats): type-check new ingest routes`

---

## Task 5 — Custom Playwright reporter `tests/e2e/stats-live-reporter.ts`

**Objective:** Implement the streaming reporter that calls the three new endpoints.

**File:** `tests/e2e/stats-live-reporter.ts` (new file)

```typescript
import type { Reporter, FullConfig, Suite, TestCase, TestResult, FullResult } from '@playwright/test/reporter'

export default class StatsLiveReporter implements Reporter {
  // ... implementation below
}
```

**Key behaviour:**

**`onBegin(config, rootSuite)`**
- Read API key from `PLAYWRIGHT_STATS_API_KEY` env or `.dev.vars` fallback (same logic as teardown)
- Skip entirely if no key (non-fatal)
- Detect `source`: `GITHUB_ACTIONS=true` → `'ci'`, else `'local'`
- Build `run_id`: same logic as the shell script (`GITHUB_RUN_ID` or `local-<Date.now()>`)
- Walk suite tree to build `filePendingCount: Map<string, number>` — count of tests per file (needed to know when a file is done)
- POST `/v1/playwright-runs/start` → store `run_id`
- `fileBuffer: Map<string, TestPayload[]>` to accumulate results per file

**`onTestEnd(test, result)`**
- If no API key, return
- Build test payload from `test` (title path, file, id) and `result` (status, duration, retry, errors)
- Push to `fileBuffer[test.location.file]`
- Decrement `filePendingCount[test.location.file]`
- If count reaches 0: `flush(file)` — POST the buffer to `/:run_id/tests`, clear buffer

**`async onEnd(result)`**
- If no API key, return
- Flush any remaining buffer (tests that didn't trigger a file flush)
- POST `/:run_id/complete` with `{ finished_at, duration_ms, run_status: result.status === 'passed' ? 'complete' : 'failed' }`
- Log `✓ Live stats complete` or `⚠ ...` on failure

**Error handling:** Every `fetch` call is wrapped in `try/catch`. Errors log a warning, never throw. Reporter failures must never affect test results.

**Commit:** `feat(stats): add StatsLiveReporter Playwright reporter`

---

## Task 6 — Register reporter in `playwright.config.ts`

**Objective:** Load `StatsLiveReporter` for all runs (local + CI). The reporter self-disables when no API key is set, so it's safe to include unconditionally.

**File:** `tests/playwright.config.ts`

```typescript
reporter: [
  ['list'],
  ['html', { outputFolder: resolve(here, '../playwright-report'), open: 'never' }],
  ['json', { outputFile: resolve(here, '../test-results/results.json') }],
  ['junit', { outputFile: resolve(here, '../test-results/junit.xml') }],
  ['./e2e/stats-live-reporter.ts'],   // ← add this
],
```

Since the reporter self-disables when `PLAYWRIGHT_STATS_API_KEY` is absent, no env-var guard needed in config.

**Commit:** `feat(stats): register StatsLiveReporter in playwright.config.ts`

---

## Task 7 — Remove redundant teardown + CI step reporting

**Objective:** The live reporter handles all reporting now. Remove the teardown logic and the GitHub Actions upload step to avoid double-reporting.

**Files:**
- `tests/e2e/global-teardown.ts` — remove the stats reporting block (keep the cleanup log line)
- `.github/workflows/pr-tests.yml` — remove the "Upload Playwright results to stats" step

**Note:** Keep `report-playwright.sh` and `npm run e2e:report` for manual/debugging use — just don't call them automatically.

**Commit:** `refactor(stats): remove teardown/CI batch reporting, superseded by live reporter`

---

## Task 8 — Dashboard: `run_status` badge + auto-refresh on run detail

**Objective:** Show a "● Live" badge on in-progress runs and auto-refresh the run detail page.

**File:** `packages/stats/src/plugins/playwright-dashboard/routes/admin.ts`

**Recent Runs table:**
- Add `json_extract(data, '$.run_status') AS run_status` to the recent runs query
- In the row render, if `run_status = 'running'`: show an animated `<span class="animate-pulse ...">● Live</span>` badge instead of/alongside the status dot
- Sort running runs to the top: `ORDER BY CASE WHEN json_extract(data, '$.run_status') = 'running' THEN 0 ELSE 1 END, created_at DESC`

**Run detail page:**
- Add `run_status` to the run metadata query
- If `run_status = 'running'`: inject `<meta http-equiv="refresh" content="5">` in the `<head>` area (use `renderAdminLayoutCatalyst`'s `extraHead` param if available, else inline a `<script>setTimeout(() => location.reload(), 5000)</script>` in the content)
- Show a "● Running — updates every 5s" banner at the top of the detail page

**Commit:** `feat(stats): live badge and auto-refresh on run detail for running status`

---

## Task 9 — Type-check, smoke test, push PR

**Objective:** Verify everything compiles, deploy to production, smoke-test a real run, push PR.

```bash
cd packages/stats && npm run type-check
npm run deploy  # deploy to sonicjs-stats worker

# Smoke test: run 1 e2e test locally and watch it appear live
cd /Users/lane/Dev/refs/sonicjs
npm run e2e -- --grep "smoke"

# Check dashboard — should see a 'running' row appear, then flip to 'complete'

# Push PR
cd ../sonicjs-pw-live-reporter
git push -u origin feat/playwright-live-reporter
gh pr create --title "feat(stats): real-time E2E run dashboard via live Playwright reporter" \
  --body "..."
```

---

## Summary of Files Changed

| File | Action |
|------|--------|
| `packages/stats/src/routes/playwright-ingest.ts` | Add `/start`, `/:run_id/tests`, `/:run_id/complete` routes |
| `tests/e2e/stats-live-reporter.ts` | New — custom Playwright reporter |
| `tests/playwright.config.ts` | Register live reporter |
| `tests/e2e/global-teardown.ts` | Remove stats reporting block |
| `.github/workflows/pr-tests.yml` | Remove upload step |
| `packages/stats/src/plugins/playwright-dashboard/routes/admin.ts` | Live badge + auto-refresh |
