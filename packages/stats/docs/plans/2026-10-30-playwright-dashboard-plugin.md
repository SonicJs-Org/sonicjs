# Playwright Dashboard Plugin — Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Build a new `playwright-dashboard` plugin for the stats.sonicjs.com app that ingests Playwright CI/CD run results via a GitHub Actions step, stores per-test results with retry info in D1, and renders a dashboard showing run history, flaky test detection, and failure trends over time.

**Architecture:** A new SonicJS plugin (`playwright-dashboard`) following the exact same pattern as the existing `stats-dashboard` plugin. Data ingestion via a new `/v1/playwright-runs` POST endpoint (bearer-token authenticated). Dashboard at `/admin/playwright` with server-rendered HTML + Chart.js. Two new collections: `playwright_runs` (one row per CI run) and `playwright_tests` (one row per test result per run). A GitHub Actions composite action script that parses Playwright's JSON reporter output and POSTs it.

**Tech Stack:** TypeScript, Hono, Cloudflare Workers, D1 (SQLite), Chart.js 4.x, GitHub Actions

**Inspiration:** [Piwi](https://github.com/PiwiTests/piwi) — we borrow its concepts of run history, flaky scoring, and failure grouping, but NOT traces, locator healing, AI diagnosis, or browser/IDE extensions.

---

## Existing Codebase Context

The implementer MUST understand this before writing any code:

### Project location
```
/Users/lane/Dev/refs/sonicjs/packages/stats/
```

### Key files
- `src/index.ts` — App entry point. Creates the SonicJS app, registers collections, registers plugins, defines custom routes.
- `src/plugins/stats-dashboard/index.ts` — Existing plugin example. Uses `definePlugin()` from `@sonicjs-cms/core`. Registers admin routes + injects sidebar menu item.
- `src/plugins/stats-dashboard/routes/admin.ts` — Existing dashboard. A single Hono route that queries D1, aggregates data, renders HTML with Chart.js via `renderAdminLayoutCatalyst()`.
- `src/collections/events.collection.ts` — Example collection definition using `CollectionConfig`.
- `src/collections/installs.collection.ts` — Another example collection.
- `wrangler.toml` — Cloudflare Workers config. D1 binding is `DB`, KV binding is `CACHE_KV`.
- `package.json` — Dependencies: `@sonicjs-cms/core`, `hono`, `wrangler`.

### How data is stored
All data goes into a single `documents` table in D1. Collections are distinguished by `type_id`. The `data` column is a JSON string containing the collection-specific fields. Rows have: `id`, `root_id`, `type_id`, `is_published`, `status`, `title`, `data` (JSON), `published_at`, `created_at`, `updated_at`, `tenant_id`, `deleted_at`.

### How the existing ingestion endpoint works (`/v1/events`)
```typescript
app.post('/v1/events', async (c) => {
  const body = await c.req.json<{ data?: Record<string, unknown> }>()
  // ... validates, writes directly to D1 via db.prepare().bind().run()
  return c.json({ success: true }, 201)
})
```
No auth on this endpoint. The new `/v1/playwright-runs` endpoint MUST require a bearer token.

### How plugins register
```typescript
import { definePlugin } from '@sonicjs-cms/core'

export const myPlugin = definePlugin({
  id: 'my-plugin',
  version: '1.0.0',
  name: 'My Plugin',
  description: '...',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },
  register(app) {
    // Add middleware, routes, etc.
    app.use('/admin/*', async (c, next) => { /* inject menu items */ })
    app.route('/admin/my-route', myRoutes)
  },
  menu: [{ label: 'My Page', path: '/admin/my-route', icon: 'chart-bar', order: 1, permissions: ['admin'] }],
})
```

### How the admin dashboard renders HTML
Uses `renderAdminLayoutCatalyst()` from `@sonicjs-cms/core`:
```typescript
return c.html(renderAdminLayoutCatalyst({
  title: 'Page Title',
  pageTitle: 'Page Title',
  currentPath: '/admin/my-route',
  version: c.get('appVersion'),
  user: user ? { name: user.email.split('@')[0], email: user.email, role: user.role } : undefined,
  scripts: ['https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js'],
  content: htmlString,
  dynamicMenuItems: c.get('pluginMenuItems'),
}))
```

### Important D1/Workers constraints
- D1 max row size: ~10MB (we'll stay well under)
- Workers CPU time limit: 30s (paid plan). Keep queries efficient.
- No JOINs across different tables in D1... but we're using ONE `documents` table filtered by `type_id`, so this is fine.
- Use `json_extract(data, '$.field')` for querying JSON columns in SQLite/D1.

---

## Data Model

### Collection: `playwright_runs` (type_id = `'playwright_runs'`)

One row per CI run. The `data` JSON column contains:

```typescript
interface PlaywrightRunData {
  // Identity
  run_id: string            // Unique run ID (GitHub run_id + attempt, or UUID)
  project: string           // e.g. "sonicjs" — for future multi-project support
  branch: string            // git branch name
  commit_sha: string        // git commit SHA (short or full)
  commit_message?: string   // first line of commit message (optional, truncated to 200 chars)

  // CI metadata
  ci_provider: string       // "github_actions"
  ci_run_url?: string       // Full URL to the GitHub Actions run
  triggered_by?: string     // "push", "pull_request", "schedule", "manual"

  // Aggregates (denormalized for fast dashboard queries)
  total: number
  passed: number
  failed: number
  skipped: number
  flaky: number             // tests that failed then passed on retry
  duration_ms: number       // total wall-clock time of the run

  // Timestamps
  started_at: string        // ISO timestamp
  finished_at: string       // ISO timestamp
}
```

### Collection: `playwright_tests` (type_id = `'playwright_tests'`)

One row per test result per run. The `data` JSON column contains:

```typescript
interface PlaywrightTestData {
  run_id: string            // FK to playwright_runs.run_id
  test_id: string           // Playwright test ID (stable across runs)
  test_title: string        // Full test title including describe blocks
  test_file: string         // Relative file path (e.g. "tests/api/posts.spec.ts")
  project_name?: string     // Playwright project name (e.g. "chromium", "firefox")

  // Result
  status: 'passed' | 'failed' | 'skipped' | 'timedOut' | 'interrupted'
  duration_ms: number
  retry: number             // 0 = first attempt, 1 = first retry, etc.
  is_flaky: boolean         // true if this test failed on a prior attempt but passed on retry

  // Error (only for failures)
  error_message?: string    // Truncated to 500 chars
  error_snippet?: string    // First 300 chars of the relevant code/stack location
}
```

---

## API Authentication

The `/v1/playwright-runs` endpoint requires a bearer token. The token is stored as a Cloudflare Workers secret:

```bash
# Set the secret (one-time setup)
wrangler secret put PLAYWRIGHT_API_KEY
# Value: generate with `openssl rand -hex 32`
```

For local dev, add to `.dev.vars`:
```
PLAYWRIGHT_API_KEY=dev-test-key-change-me
```

Validation middleware:
```typescript
function requirePlaywrightAuth() {
  return async (c: Context, next: () => Promise<void>) => {
    const authHeader = c.req.header('Authorization')
    const token = authHeader?.replace('Bearer ', '')
    const expected = c.env.PLAYWRIGHT_API_KEY
    if (!expected || !token || token !== expected) {
      return c.json({ error: 'Unauthorized' }, 401)
    }
    return next()
  }
}
```

Also add the type to the Bindings. Check if `@sonicjs-cms/core` exports its `Bindings` type — if so, you may need to augment it or cast. Look at how the existing code handles `c.env.DB`. If `Bindings` is too strict, use `(c.env as any).PLAYWRIGHT_API_KEY`.

---

## Task Breakdown

### Task 1: Create the `playwright_runs` collection

**Objective:** Define the collection config file for Playwright runs.

**Files:**
- Create: `src/collections/playwright-runs.collection.ts`

**Code:**
```typescript
/**
 * Playwright Runs Collection
 *
 * Stores one row per Playwright CI/CD run with aggregated results.
 */
import type { CollectionConfig } from "@sonicjs-cms/core";

export default {
  name: "playwright_runs",
  displayName: "Playwright Runs",
  description: "CI/CD Playwright test run summaries",
  icon: "🎭",

  schema: {
    type: "object",
    properties: {
      run_id: {
        type: "string",
        title: "Run ID",
        required: true,
        maxLength: 200,
        helpText: "Unique identifier for this CI run",
      },
      project: {
        type: "string",
        title: "Project",
        maxLength: 100,
        helpText: "Project name (e.g. sonicjs)",
      },
      branch: {
        type: "string",
        title: "Branch",
        maxLength: 200,
      },
      commit_sha: {
        type: "string",
        title: "Commit SHA",
        maxLength: 40,
      },
      commit_message: {
        type: "string",
        title: "Commit Message",
        maxLength: 200,
      },
      ci_provider: {
        type: "string",
        title: "CI Provider",
        maxLength: 50,
      },
      ci_run_url: {
        type: "string",
        title: "CI Run URL",
        maxLength: 500,
      },
      triggered_by: {
        type: "string",
        title: "Triggered By",
        maxLength: 50,
      },
      total: { type: "number", title: "Total Tests" },
      passed: { type: "number", title: "Passed" },
      failed: { type: "number", title: "Failed" },
      skipped: { type: "number", title: "Skipped" },
      flaky: { type: "number", title: "Flaky" },
      duration_ms: { type: "number", title: "Duration (ms)" },
      started_at: { type: "string", title: "Started At" },
      finished_at: { type: "string", title: "Finished At" },
    },
    required: ["run_id"],
  },

  listFields: ["run_id", "branch", "total", "passed", "failed", "flaky", "started_at"],
  searchFields: ["run_id", "branch", "commit_sha"],
  defaultSort: "createdAt",
  defaultSortOrder: "desc",
  managed: true,
  isActive: true,
} satisfies CollectionConfig;
```

**Verify:** `npm run type-check` passes.

**Commit:** `git add src/collections/playwright-runs.collection.ts && git commit -m "feat(playwright): add playwright_runs collection"`

---

### Task 2: Create the `playwright_tests` collection

**Objective:** Define the collection config file for individual test results.

**Files:**
- Create: `src/collections/playwright-tests.collection.ts`

**Code:**
```typescript
/**
 * Playwright Tests Collection
 *
 * Stores one row per test result per run, including retry information.
 */
import type { CollectionConfig } from "@sonicjs-cms/core";

export default {
  name: "playwright_tests",
  displayName: "Playwright Tests",
  description: "Individual Playwright test results per run",
  icon: "🧪",

  schema: {
    type: "object",
    properties: {
      run_id: {
        type: "string",
        title: "Run ID",
        required: true,
        maxLength: 200,
        helpText: "FK to playwright_runs",
      },
      test_id: {
        type: "string",
        title: "Test ID",
        maxLength: 500,
        helpText: "Playwright stable test ID (consistent across runs)",
      },
      test_title: {
        type: "string",
        title: "Test Title",
        maxLength: 500,
      },
      test_file: {
        type: "string",
        title: "Test File",
        maxLength: 300,
      },
      project_name: {
        type: "string",
        title: "Playwright Project",
        maxLength: 100,
        helpText: "e.g. chromium, firefox, webkit",
      },
      status: {
        type: "select",
        title: "Status",
        required: true,
        enum: ["passed", "failed", "skipped", "timedOut", "interrupted"],
        enumLabels: ["Passed", "Failed", "Skipped", "Timed Out", "Interrupted"],
      },
      duration_ms: { type: "number", title: "Duration (ms)" },
      retry: {
        type: "number",
        title: "Retry Attempt",
        helpText: "0 = first attempt, 1 = first retry, etc.",
      },
      is_flaky: {
        type: "boolean",
        title: "Is Flaky",
        helpText: "True if test failed on earlier attempt but passed on retry",
      },
      error_message: {
        type: "string",
        title: "Error Message",
        maxLength: 500,
      },
      error_snippet: {
        type: "string",
        title: "Error Snippet",
        maxLength: 300,
      },
    },
    required: ["run_id", "status"],
  },

  listFields: ["run_id", "test_title", "status", "duration_ms", "retry", "is_flaky"],
  searchFields: ["run_id", "test_id", "test_title", "test_file"],
  defaultSort: "createdAt",
  defaultSortOrder: "desc",
  managed: true,
  isActive: true,
} satisfies CollectionConfig;
```

**Verify:** `npm run type-check` passes.

**Commit:** `git add src/collections/playwright-tests.collection.ts && git commit -m "feat(playwright): add playwright_tests collection"`

---

### Task 3: Register the new collections in the app entry point

**Objective:** Import and register both new collections so D1 auto-sync creates their type_id entries.

**Files:**
- Modify: `src/index.ts`

**Changes to make (patch, don't rewrite the whole file):**

1. Add imports after the existing collection imports (after line 13):
```typescript
import playwrightRunsCollection from './collections/playwright-runs.collection'
import playwrightTestsCollection from './collections/playwright-tests.collection'
```

2. Add to the `registerCollections` array (after line 21, inside the array):
```typescript
  playwrightRunsCollection,
  playwrightTestsCollection,
```

The result should look like:
```typescript
registerCollections([
  installsCollection,
  eventsCollection,
  playwrightRunsCollection,
  playwrightTestsCollection,
])
```

**Verify:** `npm run type-check` passes. `npm run dev` starts without errors. Check that D1 local creates the types by running a quick test query.

**Commit:** `git add src/index.ts && git commit -m "feat(playwright): register playwright collections"`

---

### Task 4: Create the Playwright ingestion API endpoint

**Objective:** Build the `/v1/playwright-runs` POST endpoint that accepts Playwright JSON results, validates the API key, parses the data, computes aggregates, and inserts rows for both the run and individual test results.

**Files:**
- Create: `src/routes/playwright-ingest.ts`
- Modify: `src/index.ts` (to mount the route)

**Create `src/routes/playwright-ingest.ts`:**

```typescript
import { Hono } from 'hono'
import type { Context } from 'hono'

// Type for the Hono app — match what's used in the existing codebase
const playwrightIngest = new Hono()

/**
 * Bearer token auth middleware.
 * Reads PLAYWRIGHT_API_KEY from Workers secret / .dev.vars.
 */
function requirePlaywrightAuth() {
  return async (c: Context, next: () => Promise<void>) => {
    const authHeader = c.req.header('Authorization')
    const token = authHeader?.replace('Bearer ', '')
    const expected = (c.env as any).PLAYWRIGHT_API_KEY as string | undefined
    if (!expected || !token || token !== expected) {
      return c.json({ error: 'Unauthorized' }, 401)
    }
    return next()
  }
}

/**
 * Truncate a string to maxLen chars, appending "…" if truncated.
 */
function truncate(s: string | undefined | null, maxLen: number): string | undefined {
  if (!s) return undefined
  return s.length > maxLen ? s.slice(0, maxLen - 1) + '…' : s
}

/**
 * Payload shape from the GitHub Actions script.
 * This matches what our `report-playwright.sh` script will send.
 */
interface IngestPayload {
  run: {
    run_id: string
    project: string
    branch: string
    commit_sha: string
    commit_message?: string
    ci_provider: string
    ci_run_url?: string
    triggered_by?: string
    started_at: string
    finished_at: string
    duration_ms: number
  }
  tests: Array<{
    test_id: string
    test_title: string
    test_file: string
    project_name?: string
    status: 'passed' | 'failed' | 'skipped' | 'timedOut' | 'interrupted'
    duration_ms: number
    retry: number
    is_flaky: boolean
    error_message?: string
    error_snippet?: string
  }>
}

playwrightIngest.post('/', requirePlaywrightAuth(), async (c) => {
  try {
    const body = await c.req.json<IngestPayload>()

    if (!body.run?.run_id || !Array.isArray(body.tests)) {
      return c.json({ error: 'Missing required fields: run.run_id, tests[]' }, 400)
    }

    const db = (c.env as any).DB as D1Database
    const now = Math.floor(Date.now() / 1000)

    // Compute aggregates from the test results.
    // For aggregate counts, only use the FINAL attempt of each test
    // (highest retry number per test_id+project_name combo).
    const finalResults = new Map<string, typeof body.tests[number]>()
    for (const t of body.tests) {
      const key = `${t.test_id}::${t.project_name ?? ''}`
      const existing = finalResults.get(key)
      if (!existing || t.retry > existing.retry) {
        finalResults.set(key, t)
      }
    }

    let passed = 0, failed = 0, skipped = 0, flaky = 0
    for (const t of finalResults.values()) {
      if (t.status === 'passed') passed++
      else if (t.status === 'failed' || t.status === 'timedOut' || t.status === 'interrupted') failed++
      else if (t.status === 'skipped') skipped++
      if (t.is_flaky) flaky++
    }
    const total = finalResults.size

    // Insert the run row
    const runId = crypto.randomUUID()
    const runData = {
      run_id: body.run.run_id,
      project: body.run.project || 'sonicjs',
      branch: body.run.branch,
      commit_sha: body.run.commit_sha,
      commit_message: truncate(body.run.commit_message, 200),
      ci_provider: body.run.ci_provider || 'github_actions',
      ci_run_url: body.run.ci_run_url,
      triggered_by: body.run.triggered_by,
      total, passed, failed, skipped, flaky,
      duration_ms: body.run.duration_ms,
      started_at: body.run.started_at,
      finished_at: body.run.finished_at,
    }

    const runTitle = `${runData.project} — ${runData.branch} — ${passed}/${total} passed`

    await db.prepare(
      `INSERT INTO documents
         (id, root_id, type_id, is_published, status, title, data, published_at, created_at, updated_at)
       VALUES (?, ?, 'playwright_runs', 1, 'published', ?, ?, ?, ?, ?)`
    ).bind(runId, runId, runTitle, JSON.stringify(runData), now, now, now).run()

    // Insert test rows in batches (D1 batch API to avoid per-statement overhead)
    const stmts: D1PreparedStatement[] = []
    for (const t of body.tests) {
      const testDocId = crypto.randomUUID()
      const testData = {
        run_id: body.run.run_id,
        test_id: t.test_id,
        test_title: truncate(t.test_title, 500),
        test_file: truncate(t.test_file, 300),
        project_name: t.project_name,
        status: t.status,
        duration_ms: t.duration_ms,
        retry: t.retry ?? 0,
        is_flaky: t.is_flaky ?? false,
        error_message: truncate(t.error_message, 500),
        error_snippet: truncate(t.error_snippet, 300),
      }
      const testTitle = `${t.test_title} [${t.status}]`
      stmts.push(
        db.prepare(
          `INSERT INTO documents
             (id, root_id, type_id, is_published, status, title, data, published_at, created_at, updated_at)
           VALUES (?, ?, 'playwright_tests', 1, 'published', ?, ?, ?, ?, ?)`
        ).bind(testDocId, testDocId, testTitle, JSON.stringify(testData), now, now, now)
      )
    }

    // D1 batch — up to 500 statements per batch
    const BATCH_SIZE = 500
    for (let i = 0; i < stmts.length; i += BATCH_SIZE) {
      await db.batch(stmts.slice(i, i + BATCH_SIZE))
    }

    return c.json({
      success: true,
      run_id: body.run.run_id,
      tests_stored: body.tests.length,
      summary: { total, passed, failed, skipped, flaky },
    }, 201)
  } catch (err) {
    console.error('[playwright] /v1/playwright-runs insert failed:', err)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export { playwrightIngest }
```

**Modify `src/index.ts` — mount the route:**

1. Add import (near the top, with other imports):
```typescript
import { playwrightIngest } from './routes/playwright-ingest'
```

2. Add route BEFORE the `export default app` line:
```typescript
app.route('/v1/playwright-runs', playwrightIngest)
```

**Verify:**
1. `npm run type-check` passes
2. `npm run dev` starts
3. Test with curl (add `PLAYWRIGHT_API_KEY=dev-test-key` to `.dev.vars` first):
```bash
curl -X POST http://localhost:8787/v1/playwright-runs \
  -H "Authorization: Bearer dev-test-key" \
  -H "Content-Type: application/json" \
  -d '{
    "run": {
      "run_id": "test-run-001",
      "project": "sonicjs",
      "branch": "main",
      "commit_sha": "abc1234",
      "ci_provider": "github_actions",
      "started_at": "2026-10-30T10:00:00Z",
      "finished_at": "2026-10-30T10:05:00Z",
      "duration_ms": 300000
    },
    "tests": [
      {"test_id": "t1", "test_title": "should create a post", "test_file": "tests/api/posts.spec.ts", "status": "passed", "duration_ms": 1200, "retry": 0, "is_flaky": false},
      {"test_id": "t2", "test_title": "should handle auth", "test_file": "tests/api/auth.spec.ts", "status": "failed", "duration_ms": 5000, "retry": 0, "is_flaky": false, "error_message": "Expected 200 but got 401"},
      {"test_id": "t2", "test_title": "should handle auth", "test_file": "tests/api/auth.spec.ts", "status": "passed", "duration_ms": 4500, "retry": 1, "is_flaky": true}
    ]
  }'
# Expected: 201 with { success: true, run_id: "test-run-001", tests_stored: 3, summary: { total: 2, passed: 2, failed: 0, skipped: 0, flaky: 1 } }
```

4. Test auth rejection:
```bash
curl -X POST http://localhost:8787/v1/playwright-runs \
  -H "Content-Type: application/json" \
  -d '{}'
# Expected: 401 { error: "Unauthorized" }
```

**Commit:** `git add src/routes/playwright-ingest.ts src/index.ts && git commit -m "feat(playwright): add authenticated ingestion endpoint"`

---

### Task 5: Create the Playwright Dashboard plugin shell

**Objective:** Create the plugin definition file that registers the admin routes and injects the sidebar menu item. Follow the exact pattern of `src/plugins/stats-dashboard/index.ts`.

**Files:**
- Create: `src/plugins/playwright-dashboard/index.ts`

**Code:**
```typescript
import { definePlugin } from '@sonicjs-cms/core'
import { playwrightAdminRoutes } from './routes/admin'

const PLAYWRIGHT_ICON = '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>'

export const playwrightDashboardPlugin = definePlugin({
  id: 'playwright-dashboard',
  version: '1.0.0',
  name: 'Playwright Dashboard',
  description: 'CI/CD Playwright run history, flaky test detection, and failure trends.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },

  register(app) {
    // Inject Playwright into sidebar menu for all admin pages.
    app.use('/admin/*', async (c, next) => {
      const existing = ((c as any).get('pluginMenuItems') ?? []) as Array<{ label: string; path: string; icon: string }>
      if (!existing.some((m) => m.path === '/admin/playwright')) {
        (c as any).set('pluginMenuItems', [
          ...existing,
          { label: 'Playwright', path: '/admin/playwright', icon: PLAYWRIGHT_ICON },
        ] as any)
      }
      return next()
    })
    app.route('/admin/playwright', playwrightAdminRoutes as any)
  },

  menu: [
    {
      label: 'Playwright',
      path: '/admin/playwright',
      icon: 'check-circle',
      order: 1,
      permissions: ['admin'],
    },
  ],
})
```

**Verify:** File compiles (may get an import error for `./routes/admin` which doesn't exist yet — that's fine, we create it in the next task).

**Commit:** `git add src/plugins/playwright-dashboard/index.ts && git commit -m "feat(playwright): add plugin shell"`

---

### Task 6: Register the Playwright Dashboard plugin in the app entry point

**Objective:** Import and register the new plugin so it appears in the admin sidebar.

**Files:**
- Modify: `src/index.ts`

**Changes:**

1. Add import:
```typescript
import { playwrightDashboardPlugin } from './plugins/playwright-dashboard'
```

2. Add to the plugins register array:
```typescript
plugins: {
  autoLoad: false,
  register: [statsDashboardPlugin as any, playwrightDashboardPlugin as any],
}
```

**Verify:** `npm run type-check` passes (once the routes file from Task 7 exists).

**Commit:** `git add src/index.ts && git commit -m "feat(playwright): register playwright-dashboard plugin"`

---

### Task 7: Build the Playwright Dashboard admin route — Run History page (main page)

**Objective:** Create the main dashboard page showing: KPI cards (total runs, pass rate, flaky count, avg duration), a run history chart (pass/fail over time), and a table of recent runs with links to detail view.

**Files:**
- Create: `src/plugins/playwright-dashboard/routes/admin.ts`

**This is the largest task.** Follow the exact same pattern as `src/plugins/stats-dashboard/routes/admin.ts`:
- Use `Hono` with `requireAuth()` middleware
- Use `renderAdminLayoutCatalyst()` for layout
- Use Chart.js 4.x for charts
- Use the same Tailwind/Catalyst CSS classes for cards, tables, KPIs
- Query D1 directly via `c.env.DB`

**The route handler for `GET /` (the main page):**

```typescript
import { Hono } from 'hono'
import { requireAuth } from '@sonicjs-cms/core'
import { renderAdminLayoutCatalyst } from '@sonicjs-cms/core'
import type { Bindings, Variables } from '@sonicjs-cms/core'

const adminRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

adminRoutes.use('*', requireAuth())
adminRoutes.use('*', async (c, next) => {
  const user = c.get('user')
  if (user?.role !== 'admin') return c.text('Access denied', 403)
  return next()
})

// ── Helpers ──────────────────────────────────────────────────────────────
const RUNS_WHERE = `type_id = 'playwright_runs' AND is_published = 1 AND deleted_at IS NULL`
const TESTS_WHERE = `type_id = 'playwright_tests' AND is_published = 1 AND deleted_at IS NULL`

function esc(v: unknown): string {
  return String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function jsonForScript(v: unknown): string {
  return JSON.stringify(v).replace(/</g, '\\u003c').replace(/>/g, '\\u003e')
}

interface Row { [k: string]: any }
const rowsOf = (r: { results?: unknown[] } | null): Row[] => (r?.results ?? []) as Row[]

const PALETTE = ['#6366f1', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#ec4899', '#84cc16']

// ── Main dashboard (GET /) ───────────────────────────────────────────────
adminRoutes.get('/', async (c) => {
  const db = c.env.DB
  const user = c.get('user')

  const [
    recentRunsR,
    totalRunsR,
    passRateR,
    flakyTotalR,
    avgDurationR,
    dailyRunsR,
    topFlakyR,
    topFailingR,
  ] = await Promise.all([
    // 1. Recent runs (last 50)
    db.prepare(
      `SELECT json_extract(data, '$.run_id') AS run_id,
              json_extract(data, '$.branch') AS branch,
              json_extract(data, '$.commit_sha') AS commit_sha,
              json_extract(data, '$.commit_message') AS commit_message,
              json_extract(data, '$.ci_run_url') AS ci_run_url,
              json_extract(data, '$.triggered_by') AS triggered_by,
              json_extract(data, '$.total') AS total,
              json_extract(data, '$.passed') AS passed,
              json_extract(data, '$.failed') AS failed,
              json_extract(data, '$.skipped') AS skipped,
              json_extract(data, '$.flaky') AS flaky,
              json_extract(data, '$.duration_ms') AS duration_ms,
              json_extract(data, '$.started_at') AS started_at,
              json_extract(data, '$.finished_at') AS finished_at
       FROM documents WHERE ${RUNS_WHERE}
       ORDER BY created_at DESC LIMIT 50`
    ).all(),

    // 2. Total run count
    db.prepare(
      `SELECT COUNT(*) AS count FROM documents WHERE ${RUNS_WHERE}`
    ).first(),

    // 3. Overall pass rate (across all runs)
    db.prepare(
      `SELECT
         SUM(CAST(json_extract(data, '$.passed') AS INTEGER)) AS total_passed,
         SUM(CAST(json_extract(data, '$.total') AS INTEGER)) AS total_tests
       FROM documents WHERE ${RUNS_WHERE}`
    ).first(),

    // 4. Total flaky test occurrences
    db.prepare(
      `SELECT SUM(CAST(json_extract(data, '$.flaky') AS INTEGER)) AS total_flaky
       FROM documents WHERE ${RUNS_WHERE}`
    ).first(),

    // 5. Average run duration
    db.prepare(
      `SELECT AVG(CAST(json_extract(data, '$.duration_ms') AS REAL)) AS avg_ms
       FROM documents WHERE ${RUNS_WHERE}`
    ).first(),

    // 6. Runs per day (last 30 days) — for the trend chart
    db.prepare(
      `SELECT date(datetime(created_at, 'unixepoch')) AS day,
              COUNT(*) AS runs,
              SUM(CASE WHEN CAST(json_extract(data, '$.failed') AS INTEGER) = 0 THEN 1 ELSE 0 END) AS green_runs,
              SUM(CASE WHEN CAST(json_extract(data, '$.failed') AS INTEGER) > 0 THEN 1 ELSE 0 END) AS red_runs,
              AVG(CAST(json_extract(data, '$.passed') AS REAL) / MAX(CAST(json_extract(data, '$.total') AS REAL), 1) * 100) AS avg_pass_rate
       FROM documents WHERE ${RUNS_WHERE}
         AND created_at >= unixepoch('now', '-30 days')
       GROUP BY day ORDER BY day ASC`
    ).all(),

    // 7. Top 10 flakiest tests (most is_flaky=true occurrences across all runs)
    db.prepare(
      `SELECT json_extract(data, '$.test_title') AS test_title,
              json_extract(data, '$.test_file') AS test_file,
              COUNT(*) AS flaky_count,
              COUNT(DISTINCT json_extract(data, '$.run_id')) AS affected_runs
       FROM documents WHERE ${TESTS_WHERE}
         AND json_extract(data, '$.is_flaky') = 1
       GROUP BY json_extract(data, '$.test_id')
       ORDER BY flaky_count DESC LIMIT 10`
    ).all(),

    // 8. Top 10 most-failing tests (final attempts only, status=failed)
    db.prepare(
      `SELECT json_extract(data, '$.test_title') AS test_title,
              json_extract(data, '$.test_file') AS test_file,
              json_extract(data, '$.error_message') AS error_message,
              COUNT(*) AS fail_count
       FROM documents WHERE ${TESTS_WHERE}
         AND json_extract(data, '$.status') = 'failed'
       GROUP BY json_extract(data, '$.test_id')
       ORDER BY fail_count DESC LIMIT 10`
    ).all(),
  ])

  // ── Aggregate data ──────────────────────────────────────────────────
  const recentRuns = rowsOf(recentRunsR)
  const totalRuns = Number((totalRunsR as Row | null)?.count ?? 0)
  const pr = (passRateR ?? {}) as Row
  const overallPassRate = Number(pr.total_tests) > 0
    ? Math.round((Number(pr.total_passed) / Number(pr.total_tests)) * 100)
    : 0
  const totalFlaky = Number((flakyTotalR as Row | null)?.total_flaky ?? 0)
  const avgDuration = Math.round(Number((avgDurationR as Row | null)?.avg_ms ?? 0) / 1000)

  const dailyRuns = rowsOf(dailyRunsR) as { day: string; runs: number; green_runs: number; red_runs: number; avg_pass_rate: number }[]
  const topFlaky = rowsOf(topFlakyR) as { test_title: string; test_file: string; flaky_count: number; affected_runs: number }[]
  const topFailing = rowsOf(topFailingR) as { test_title: string; test_file: string; error_message: string; fail_count: number }[]

  // ── Chart data ──────────────────────────────────────────────────────
  const charts = {
    daily: {
      labels: dailyRuns.map(r => r.day),
      green: dailyRuns.map(r => Number(r.green_runs)),
      red: dailyRuns.map(r => Number(r.red_runs)),
      passRate: dailyRuns.map(r => Math.round(Number(r.avg_pass_rate))),
    },
  }

  // ── KPI helper (copy from stats-dashboard) ─────────────────────────
  const kpi = (label: string, value: string, sub: string, color = 'text-zinc-950 dark:text-white') => `
    <div class="rounded-lg bg-white dark:bg-zinc-800 p-5 ring-1 ring-zinc-950/5 dark:ring-white/10">
      <p class="text-xs font-medium uppercase tracking-wide text-zinc-500 dark:text-zinc-400">${label}</p>
      <p class="mt-2 text-2xl font-semibold ${color}">${value}</p>
      <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">${sub}</p>
    </div>`

  const card = (title: string, sub: string, body: string) => `
    <div class="rounded-lg bg-white dark:bg-zinc-800 ring-1 ring-zinc-950/5 dark:ring-white/10">
      <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
        <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">${title}</h2>
        ${sub ? `<p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">${sub}</p>` : ''}
      </div>
      <div class="p-6">${body}</div>
    </div>`

  // ── Format duration ────────────────────────────────────────────────
  function fmtDuration(ms: number): string {
    const s = Math.round(ms / 1000)
    if (s < 60) return `${s}s`
    const m = Math.floor(s / 60)
    return `${m}m ${s % 60}s`
  }

  // ── Render ─────────────────────────────────────────────────────────
  const content = `
<div class="space-y-8">
  <div>
    <h1 class="text-2xl font-semibold text-zinc-950 dark:text-white">Playwright CI/CD</h1>
    <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Test run history, flaky detection, and failure trends</p>
  </div>

  <!-- KPI row -->
  <div class="grid grid-cols-2 gap-4 sm:grid-cols-4">
    ${kpi('Total Runs', totalRuns.toLocaleString(), 'all time')}
    ${kpi('Pass Rate', overallPassRate + '%', 'across all runs', overallPassRate >= 90 ? 'text-emerald-600 dark:text-emerald-400' : overallPassRate >= 70 ? 'text-amber-600 dark:text-amber-400' : 'text-red-600 dark:text-red-400')}
    ${kpi('Flaky Tests', totalFlaky.toLocaleString(), 'total flaky occurrences', totalFlaky > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400')}
    ${kpi('Avg Duration', avgDuration > 0 ? fmtDuration(avgDuration * 1000) : '—', 'per run')}
  </div>

  <!-- Daily trend chart -->
  ${card('Run Trend (Last 30 Days)', 'Green (all pass) vs red (has failures) runs per day',
    dailyRuns.length > 0
      ? '<canvas id="chartDaily" height="240"></canvas>'
      : '<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No runs yet. Send your first Playwright run to see the trend.</div>'
  )}

  <!-- Flaky + Failing side by side -->
  <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
    ${card('🔄 Top Flaky Tests', 'Tests that fail then pass on retry — sorted by frequency', topFlaky.length === 0
      ? '<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No flaky tests detected yet.</div>'
      : `<div class="overflow-x-auto"><table class="w-full text-sm">
          <thead class="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
            <tr><th class="py-2 text-left font-medium">Test</th><th class="py-2 text-right font-medium">Flaky Count</th><th class="py-2 text-right font-medium">Runs Affected</th></tr>
          </thead>
          <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
          ${topFlaky.map(r => `<tr>
            <td class="py-2 pr-4"><div class="text-zinc-700 dark:text-zinc-300">${esc(r.test_title)}</div><div class="text-xs text-zinc-400 font-mono">${esc(r.test_file)}</div></td>
            <td class="py-2 text-right font-semibold text-amber-600 dark:text-amber-400">${Number(r.flaky_count)}</td>
            <td class="py-2 text-right text-zinc-500">${Number(r.affected_runs)}</td>
          </tr>`).join('')}
          </tbody></table></div>`
    )}

    ${card('❌ Top Failing Tests', 'Most frequently failing tests (final attempt)', topFailing.length === 0
      ? '<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No failures recorded yet.</div>'
      : `<div class="overflow-x-auto"><table class="w-full text-sm">
          <thead class="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
            <tr><th class="py-2 text-left font-medium">Test</th><th class="py-2 text-left font-medium">Error</th><th class="py-2 text-right font-medium">Fails</th></tr>
          </thead>
          <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
          ${topFailing.map(r => `<tr>
            <td class="py-2 pr-4"><div class="text-zinc-700 dark:text-zinc-300">${esc(r.test_title)}</div><div class="text-xs text-zinc-400 font-mono">${esc(r.test_file)}</div></td>
            <td class="py-2 pr-4 text-xs text-zinc-500 dark:text-zinc-400 max-w-xs truncate">${esc(r.error_message)}</td>
            <td class="py-2 text-right font-semibold text-red-600 dark:text-red-400">${Number(r.fail_count)}</td>
          </tr>`).join('')}
          </tbody></table></div>`
    )}
  </div>

  <!-- Recent Runs table -->
  ${card('Recent Runs', 'Last 50 CI/CD runs', recentRuns.length === 0
    ? '<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No runs yet.</div>'
    : `<div class="overflow-x-auto"><table class="w-full text-sm">
        <thead class="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
          <tr>
            <th class="py-2 text-left font-medium">Status</th>
            <th class="py-2 text-left font-medium">Branch</th>
            <th class="py-2 text-left font-medium">Commit</th>
            <th class="py-2 text-right font-medium">Passed</th>
            <th class="py-2 text-right font-medium">Failed</th>
            <th class="py-2 text-right font-medium">Flaky</th>
            <th class="py-2 text-right font-medium">Duration</th>
            <th class="py-2 text-left font-medium">When</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
        ${recentRuns.map(r => {
          const failed = Number(r.failed)
          const flakyN = Number(r.flaky)
          const statusDot = failed > 0
            ? '<span class="inline-block w-2.5 h-2.5 rounded-full bg-red-500" title="Has failures"></span>'
            : flakyN > 0
              ? '<span class="inline-block w-2.5 h-2.5 rounded-full bg-amber-500" title="Flaky"></span>'
              : '<span class="inline-block w-2.5 h-2.5 rounded-full bg-emerald-500" title="All passed"></span>'
          const commitLink = r.ci_run_url
            ? `<a href="${esc(r.ci_run_url)}" target="_blank" rel="noopener" class="hover:text-indigo-600 dark:hover:text-indigo-400">${esc(String(r.commit_sha).slice(0,7))}</a>`
            : esc(String(r.commit_sha).slice(0,7))
          return `<tr>
            <td class="py-2 pr-2">${statusDot}</td>
            <td class="py-2 pr-4 font-mono text-xs text-zinc-700 dark:text-zinc-300">${esc(r.branch)}</td>
            <td class="py-2 pr-4 font-mono text-xs">${commitLink}${r.commit_message ? ` <span class="text-zinc-400">${esc(String(r.commit_message).slice(0, 50))}</span>` : ''}</td>
            <td class="py-2 text-right text-emerald-600 dark:text-emerald-400">${r.passed}/${r.total}</td>
            <td class="py-2 text-right ${failed > 0 ? 'text-red-600 dark:text-red-400 font-semibold' : 'text-zinc-400'}">${r.failed}</td>
            <td class="py-2 text-right ${flakyN > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-zinc-400'}">${r.flaky}</td>
            <td class="py-2 text-right text-zinc-500">${fmtDuration(Number(r.duration_ms))}</td>
            <td class="py-2 text-xs text-zinc-400">${r.started_at ? new Date(r.started_at).toLocaleDateString() : '—'}</td>
          </tr>`
        }).join('')}
        </tbody></table></div>`
  )}
</div>

<script>
(function () {
  if (typeof Chart === 'undefined') return;
  var D = ${jsonForScript(charts)};
  var P = ${jsonForScript(PALETTE)};
  var dark = document.documentElement.classList.contains('dark');
  var grid = dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)';
  var tick = dark ? '#a1a1aa' : '#52525b';
  Chart.defaults.color = tick;
  Chart.defaults.font.size = 11;

  // Daily stacked bar (green/red runs) + pass rate line
  var el = document.getElementById('chartDaily');
  if (el && D.daily.labels.length) {
    new Chart(el, {
      type: 'bar',
      data: {
        labels: D.daily.labels,
        datasets: [
          { label: 'Green runs', data: D.daily.green, backgroundColor: '#10b981', stack: 'runs' },
          { label: 'Red runs', data: D.daily.red, backgroundColor: '#ef4444', stack: 'runs' },
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'top', labels: { boxWidth: 12 } } },
        scales: {
          x: { grid: { display: false }, ticks: { color: tick, maxRotation: 60 }, stacked: true },
          y: { grid: { color: grid }, ticks: { color: tick }, beginAtZero: true, stacked: true },
        }
      }
    });
  }
})();
</script>`

  return c.html(
    renderAdminLayoutCatalyst({
      title: 'Playwright',
      pageTitle: 'Playwright CI/CD',
      currentPath: '/admin/playwright',
      version: c.get('appVersion'),
      user: user
        ? { name: user.email.split('@')[0] || 'Admin', email: user.email, role: user.role }
        : undefined,
      scripts: ['https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js'],
      content,
      dynamicMenuItems: c.get('pluginMenuItems'),
    })
  )
})

export { adminRoutes as playwrightAdminRoutes }
```

**Verify:**
1. `npm run type-check` passes
2. `npm run dev` starts
3. Navigate to `http://localhost:8787/admin/playwright` (after logging in) — page renders with empty state
4. Ingest a test run (curl from Task 4), refresh — KPIs, chart, and table populate

**Commit:** `git add src/plugins/playwright-dashboard/ && git commit -m "feat(playwright): add dashboard with run history, flaky detection, failure trends"`

---

### Task 8: Create the GitHub Actions script for reporting Playwright results

**Objective:** Create a shell script that runs as a GitHub Actions step. It reads Playwright's JSON reporter output, transforms it into our API format, and POSTs it to `stats.sonicjs.com/v1/playwright-runs`.

**Files:**
- Create: `scripts/report-playwright.sh`

**How it works:**
1. Playwright must be configured with the JSON reporter: `reporter: [['json', { outputFile: 'test-results/results.json' }]]`
2. The script reads `test-results/results.json`, extracts runs + test results using `jq`, and POSTs to the API.

**Code:**
```bash
#!/usr/bin/env bash
#
# report-playwright.sh — Send Playwright JSON results to stats.sonicjs.com
#
# Required env vars:
#   PLAYWRIGHT_STATS_API_KEY  — Bearer token for authentication
#   PLAYWRIGHT_STATS_URL      — Base URL (default: https://stats.sonicjs.com)
#
# Optional env vars (auto-detected in GitHub Actions):
#   GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, GITHUB_REF_NAME, GITHUB_SHA,
#   GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_EVENT_NAME
#
# Usage:
#   PLAYWRIGHT_STATS_API_KEY=xxx bash scripts/report-playwright.sh [path/to/results.json]
#
set -euo pipefail

RESULTS_FILE="${1:-test-results/results.json}"
STATS_URL="${PLAYWRIGHT_STATS_URL:-https://stats.sonicjs.com}"
API_KEY="${PLAYWRIGHT_STATS_API_KEY:-}"

if [ -z "$API_KEY" ]; then
  echo "⚠️  PLAYWRIGHT_STATS_API_KEY not set — skipping stats upload"
  exit 0
fi

if [ ! -f "$RESULTS_FILE" ]; then
  echo "⚠️  Results file not found: $RESULTS_FILE — skipping stats upload"
  exit 0
fi

if ! command -v jq &>/dev/null; then
  echo "❌ jq is required but not installed"
  exit 1
fi

# GitHub Actions metadata (auto-detected)
RUN_ID="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
BRANCH="${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')}"
COMMIT_SHA="${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo 'unknown')}"
COMMIT_MSG="$(git log -1 --format=%s 2>/dev/null | head -c 200 || echo '')"
CI_RUN_URL=""
if [ -n "${GITHUB_SERVER_URL:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ] && [ -n "${GITHUB_RUN_ID:-}" ]; then
  CI_RUN_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
fi
TRIGGERED_BY="${GITHUB_EVENT_NAME:-manual}"

# Parse the Playwright JSON output and build our payload.
# Playwright JSON format has: config, suites[] (nested), each suite has specs[],
# each spec has tests[], each test has results[].
#
# We flatten everything into individual test results.
PAYLOAD=$(jq -c --arg run_id "$RUN_ID" \
  --arg project "sonicjs" \
  --arg branch "$BRANCH" \
  --arg commit_sha "$COMMIT_SHA" \
  --arg commit_message "$COMMIT_MSG" \
  --arg ci_run_url "$CI_RUN_URL" \
  --arg triggered_by "$TRIGGERED_BY" '
{
  run: {
    run_id: $run_id,
    project: $project,
    branch: $branch,
    commit_sha: $commit_sha,
    commit_message: $commit_message,
    ci_provider: "github_actions",
    ci_run_url: $ci_run_url,
    triggered_by: $triggered_by,
    started_at: (.stats.startTime // now | todate),
    finished_at: (now | todate),
    duration_ms: (.stats.duration // 0)
  },
  tests: [
    .. | objects | select(.testId? != null and .results? != null) |
    .testId as $test_id |
    (.titlePath | join(" > ")) as $full_title |
    (.location.file // "unknown") as $file |
    (.projectName // null) as $proj |
    .results | to_entries[] |
    {
      test_id: $test_id,
      test_title: $full_title,
      test_file: $file,
      project_name: $proj,
      status: .value.status,
      duration_ms: .value.duration,
      retry: .key,
      is_flaky: (
        if .key > 0 and .value.status == "passed" then true
        else false end
      ),
      error_message: (
        if .value.errors and (.value.errors | length) > 0
        then (.value.errors[0].message // "" | .[0:500])
        else null end
      ),
      error_snippet: (
        if .value.errors and (.value.errors | length) > 0
        then (.value.errors[0].snippet // "" | .[0:300])
        else null end
      )
    }
  ]
}' "$RESULTS_FILE")

echo "📊 Uploading Playwright results to $STATS_URL..."

HTTP_CODE=$(curl -s -o /tmp/pw-stats-response.json -w "%{http_code}" \
  -X POST "$STATS_URL/v1/playwright-runs" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

if [ "$HTTP_CODE" -eq 201 ]; then
  echo "✅ Results uploaded successfully"
  cat /tmp/pw-stats-response.json
else
  echo "⚠️  Upload failed with HTTP $HTTP_CODE (non-fatal)"
  cat /tmp/pw-stats-response.json 2>/dev/null || true
fi

# Never fail the CI pipeline because stats upload failed
exit 0
```

**Make it executable:**
```bash
chmod +x scripts/report-playwright.sh
```

**Verify manually:**
1. Run Playwright locally with JSON reporter to generate `test-results/results.json`:
   ```bash
   cd /path/to/sonicjs
   npx playwright test --reporter=json > test-results/results.json 2>/dev/null || true
   ```
2. Test the script against local dev:
   ```bash
   PLAYWRIGHT_STATS_API_KEY=dev-test-key \
   PLAYWRIGHT_STATS_URL=http://localhost:8787 \
   bash packages/stats/scripts/report-playwright.sh test-results/results.json
   ```

**Commit:** `git add scripts/report-playwright.sh && git commit -m "feat(playwright): add GitHub Actions reporting script"`

---

### Task 9: Add the reporting step to the SonicJS GitHub Actions E2E workflow

**Objective:** Add a step to the existing E2E CI workflow that runs `report-playwright.sh` after tests complete.

**Files:**
- Modify: The existing GitHub Actions workflow file that runs Playwright tests. Find it with:
  ```bash
  find .github/workflows -name "*.yml" -o -name "*.yaml" | xargs grep -l "playwright" -i
  ```

**What to add:**

1. Ensure Playwright uses the JSON reporter. In the test step, add `--reporter=json,list` or add to `playwright.config.ts`:
   ```typescript
   reporter: [
     ['list'],
     ['json', { outputFile: 'test-results/results.json' }],
   ],
   ```

2. Add a step AFTER the test step (even if tests fail — use `if: always()`):
   ```yaml
   - name: Upload Playwright results to stats
     if: always()
     env:
       PLAYWRIGHT_STATS_API_KEY: ${{ secrets.PLAYWRIGHT_STATS_API_KEY }}
       PLAYWRIGHT_STATS_URL: https://stats.sonicjs.com
     run: bash packages/stats/scripts/report-playwright.sh test-results/results.json
   ```

3. **Do NOT forget:** The `PLAYWRIGHT_STATS_API_KEY` GitHub Actions secret must be created. Document this but do NOT create it yourself — Lane will set that up:
   ```
   # Lane needs to add this secret to the repo:
   # Settings > Secrets and variables > Actions > New repository secret
   # Name: PLAYWRIGHT_STATS_API_KEY
   # Value: (same value set via `wrangler secret put PLAYWRIGHT_API_KEY`)
   ```

**Verify:**
1. Push a test branch, trigger CI, verify the upload step runs
2. Check stats.sonicjs.com/admin/playwright shows the new run

**Commit:** `git commit -m "ci: add Playwright stats reporting step to E2E workflow"`

---

### Task 10: Add seed data script for local development

**Objective:** Create a script that seeds the local D1 database with fake Playwright runs so the dashboard can be developed and tested without waiting for real CI runs.

**Files:**
- Create: `scripts/seed-playwright.mjs`

**Code:**
```javascript
#!/usr/bin/env node
/**
 * Seed local D1 with fake Playwright run data for development.
 * Run: node packages/stats/scripts/seed-playwright.mjs
 */

const API_KEY = process.env.PLAYWRIGHT_STATS_API_KEY || 'dev-test-key'
const BASE_URL = process.env.PLAYWRIGHT_STATS_URL || 'http://localhost:8787'

const BRANCHES = ['main', 'feat/auth', 'fix/api-cors', 'feat/media-upload', 'chore/deps']
const TEST_FILES = [
  'tests/api/posts.spec.ts',
  'tests/api/auth.spec.ts',
  'tests/api/media.spec.ts',
  'tests/admin/login.spec.ts',
  'tests/admin/collections.spec.ts',
  'tests/e2e/content-editing.spec.ts',
]
const TESTS = [
  'should create a new post',
  'should update an existing post',
  'should delete a post',
  'should return 401 for unauthenticated requests',
  'should login with valid credentials',
  'should upload a file',
  'should list all collections',
  'should handle pagination',
  'should filter by status',
  'should create a new user',
  'should handle concurrent edits',
  'should validate required fields',
]

function randomChoice(arr) { return arr[Math.floor(Math.random() * arr.length)] }
function randomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min }

async function seedRun(daysAgo) {
  const date = new Date(Date.now() - daysAgo * 86400000)
  const runId = `seed-${date.toISOString().slice(0,10)}-${randomInt(1, 999)}`
  const branch = randomChoice(BRANCHES)

  const tests = []
  const numTests = randomInt(8, TESTS.length)
  for (let i = 0; i < numTests; i++) {
    const status = Math.random() < 0.85 ? 'passed' : Math.random() < 0.7 ? 'failed' : 'skipped'
    const testEntry = {
      test_id: `test-${i}`,
      test_title: TESTS[i % TESTS.length],
      test_file: randomChoice(TEST_FILES),
      project_name: 'chromium',
      status,
      duration_ms: randomInt(500, 15000),
      retry: 0,
      is_flaky: false,
      error_message: status === 'failed' ? `Expected 200 but received ${randomChoice([401, 403, 500, 502])}` : undefined,
    }
    tests.push(testEntry)

    // Simulate retries + flaky
    if (status === 'failed' && Math.random() < 0.4) {
      tests.push({
        ...testEntry,
        status: 'passed',
        retry: 1,
        is_flaky: true,
        duration_ms: randomInt(500, 15000),
        error_message: undefined,
      })
    }
  }

  const payload = {
    run: {
      run_id: runId,
      project: 'sonicjs',
      branch,
      commit_sha: Math.random().toString(16).slice(2, 9),
      commit_message: `${randomChoice(['fix', 'feat', 'chore', 'test'])}: ${randomChoice(['update deps', 'fix auth bug', 'add media endpoint', 'refactor API', 'improve tests'])}`,
      ci_provider: 'github_actions',
      ci_run_url: `https://github.com/SonicJs-Org/sonicjs/actions/runs/${randomInt(10000, 99999)}`,
      triggered_by: randomChoice(['push', 'pull_request']),
      started_at: date.toISOString(),
      finished_at: new Date(date.getTime() + randomInt(120000, 600000)).toISOString(),
      duration_ms: randomInt(120000, 600000),
    },
    tests,
  }

  const resp = await fetch(`${BASE_URL}/v1/playwright-runs`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  })

  const result = await resp.json()
  console.log(`  ${resp.status === 201 ? '✅' : '❌'} ${runId} (${branch}) — ${result.summary?.passed ?? '?'}/${result.summary?.total ?? '?'} passed`)
}

async function main() {
  console.log(`🎭 Seeding Playwright runs to ${BASE_URL}...\n`)
  // Seed 30 days of runs (1-3 per day)
  for (let daysAgo = 30; daysAgo >= 0; daysAgo--) {
    const runsToday = randomInt(1, 3)
    for (let r = 0; r < runsToday; r++) {
      await seedRun(daysAgo)
    }
  }
  console.log('\n✅ Done! Visit /admin/playwright to see the dashboard.')
}

main().catch(console.error)
```

**Verify:**
1. Start local dev: `npm run dev`
2. Run the seed: `node scripts/seed-playwright.mjs`
3. Visit `http://localhost:8787/admin/playwright` — dashboard should be fully populated

**Commit:** `git add scripts/seed-playwright.mjs && git commit -m "feat(playwright): add seed script for local development"`

---

### Task 11: Set the Cloudflare Workers secret for the API key

**Objective:** Set the `PLAYWRIGHT_API_KEY` secret on the deployed Workers instance.

**Steps:**
1. Generate a key:
   ```bash
   openssl rand -hex 32
   ```
2. Set it on the Worker:
   ```bash
   cd packages/stats
   npx wrangler secret put PLAYWRIGHT_API_KEY
   # Paste the generated key when prompted
   ```
3. Add to `.dev.vars` for local dev:
   ```
   PLAYWRIGHT_API_KEY=dev-test-key-change-me
   ```
4. **Leave a note for Lane** to add the same key as `PLAYWRIGHT_STATS_API_KEY` GitHub Actions secret on the `SonicJs-Org/sonicjs` repo.

**Commit:** No code change — just secret setup. Add `.dev.vars` to `.gitignore` if not already there.

---

### Task 12: Deploy and verify end-to-end

**Objective:** Deploy the updated stats worker and verify the full pipeline works.

**Steps:**
1. Deploy:
   ```bash
   cd packages/stats
   npm run deploy
   ```
2. Verify the dashboard loads: `https://stats.sonicjs.com/admin/playwright`
3. Verify auth works:
   ```bash
   # Should 401
   curl -s -o /dev/null -w "%{http_code}" -X POST https://stats.sonicjs.com/v1/playwright-runs
   # Should 201
   curl -s -X POST https://stats.sonicjs.com/v1/playwright-runs \
     -H "Authorization: Bearer <real-key>" \
     -H "Content-Type: application/json" \
     -d '{"run":{"run_id":"deploy-test","project":"sonicjs","branch":"main","commit_sha":"abc","ci_provider":"manual","started_at":"2026-10-30T00:00:00Z","finished_at":"2026-10-30T00:01:00Z","duration_ms":60000},"tests":[{"test_id":"t1","test_title":"deploy check","test_file":"test.ts","status":"passed","duration_ms":100,"retry":0,"is_flaky":false}]}'
   ```
4. Verify the existing stats dashboard at `/admin/dashboard` still works (no regression).

**Commit:** No code change — deployment verification.

---

## Summary of all new files

```
packages/stats/
├── src/
│   ├── collections/
│   │   ├── playwright-runs.collection.ts    ← NEW (Task 1)
│   │   └── playwright-tests.collection.ts   ← NEW (Task 2)
│   ├── routes/
│   │   └── playwright-ingest.ts             ← NEW (Task 4)
│   ├── plugins/
│   │   └── playwright-dashboard/
│   │       ├── index.ts                     ← NEW (Task 5)
│   │       └── routes/
│   │           └── admin.ts                 ← NEW (Task 7)
│   └── index.ts                             ← MODIFIED (Tasks 3, 4, 6)
├── scripts/
│   ├── report-playwright.sh                 ← NEW (Task 8)
│   └── seed-playwright.mjs                  ← NEW (Task 10)
└── .dev.vars                                ← MODIFIED (Task 11)
```

## Manual setup Lane must do (not automatable)
1. `wrangler secret put PLAYWRIGHT_API_KEY` — set the API key on the Worker
2. Add `PLAYWRIGHT_STATS_API_KEY` as a GitHub Actions secret on `SonicJs-Org/sonicjs`
3. Add the JSON reporter to the Playwright config if not already present
