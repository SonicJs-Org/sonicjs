# Playwright E2E suite

## Run against disposable local Workers/D1

From the repository root, use the lockfile and matching browser:

```bash
npm ci
npx playwright install chromium
npm run build:core
export E2E_DISPOSABLE_TARGET=1
export E2E_PERSIST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sonicjs-e2e.XXXXXX")"
(cd my-sonicjs-app && npx wrangler d1 migrations apply DB --local --persist-to "$E2E_PERSIST_DIR")
npm run e2e -- --workers=2 --retries=0
```

The main config launches **local** Wrangler on port 8787 (the ordinary `npm run dev`
uses a directory-derived port and is not the E2E server command). Do not point at
production, a shared developer server, or somebody else's preview. Do not run
`npm run setup:db` for this recipe: it may create remote worktree resources.
`E2E_PERSIST_DIR` must be absolute and must match the migration, server and `d1Exec`
paths. Without it, Wrangler uses the existing app-local state, so prefer the isolated recipe.
Stop other servers on 8787 before a controlled run; local server reuse remains enabled
for interactive debugging, but CI refuses server reuse.

Wrangler loads ignored `my-sonicjs-app/.dev.vars` when present. Authentication requires
`BETTER_AUTH_SECRET` of at least 16 characters, `ENABLE_SEED_ADMIN=true` and an explicit
non-production environment. Use the sample app's preview/test configuration only;
never print secrets or commit `.dev.vars`. Migrations and code-defined collections
(including `blog_post` and `e2e_test`) are prerequisites. Global setup seeds the admin
and welcome content, checks a real admin session, zero pending migrations and an
authenticated content page. Setup errors fail the run before specs start; mutations
are never retried by setup. No browser is launched for API readiness.

```bash
# Affected spec, isolated test, concurrency/repetition checks
npm run e2e -- 83-json-field-viewer --workers=2 --repeat-each=3 --retries=0
npm run e2e -- 83-json-field-viewer --grep 'edited JSON saves' --retries=0
npm run e2e -- 39-slug-generation --grep 'detect duplicate slugs' --repeat-each=3 --workers=2 --retries=0

# Full suite, not smoke; three consecutive clean runs are the acceptance target
npm run e2e -- --workers=2 --retries=0
# CI policy: two workers, one diagnostic retry, retry recoveries also fail CI
CI=true npm run e2e

# Use an ALREADY RUNNING, owned server (BASE_URL is honored)
npx playwright test --config tests/playwright-no-server.config.ts

# Fast runner-contract tests need no application/database/secrets
npx playwright test --config tests/playwright.infrastructure.config.ts --workers=2 --repeat-each=5 --retries=0
npm run test --workspace=@sonicjs-cms/core -- src/__tests__/e2e-infrastructure.test.ts

# Smoke is for debugging, never a full-regression replacement
npm run e2e:smoke
bash scripts/lint-e2e-tags.sh
bash scripts/lint-e2e-no-skip.sh
npm run type-check
npm test
```

## Ownership, isolation and authentication

- Import `test`/`expect` from `./fixtures`. `resourceId` is a fresh UUID allocation per
  test attempt; `uniqueTestId()` also works in focused setup helpers. Never use only
  timestamps, worker numbers, fixed slugs or a prior test's output as prerequisites.
- Create prerequisites explicitly, preferably through supported APIs unless their UI
  creation flow is what the test covers. Check HTTP/application success and capture
  the returned resource ID before yielding from the fixture.
- Delete only recorded IDs in fixture `finally` blocks, including after failed assertions.
  Fail on cleanup errors. JSON-viewer tests demonstrate per-test ownership and start
  from version 1 independently. Duplicate-slug detection creates its own prerequisite
  via API and cleans up only that record.
- Global setup/teardown no longer invoke pattern-based `/test-cleanup` sweeps. Legacy
  specs still have incomplete ownership/cleanup: a disposable database remains required.
  The unused `clearTestData`/`cleanupTestUsers` helpers are not safe cleanup patterns.
- API authentication already caches session cookies per worker. Identity is checked
  before reuse; session-check transport/5xx errors are failures, not evidence of logout.
  A successful global seed is shared with workers to avoid repeated seed hashing.
  Sign-in transport failures are not blindly retried. Real UI authentication coverage
  remains in `02-authentication` and the auth-specific specs.
- The shared admin is **not** safe for concurrent credential/role/session/2FA mutations.
  Such tests must create disposable users. Cache reuse is not account isolation.
- Settings/plugin mutations must snapshot original state and restore it in `finally`
  while holding the same narrowly named lock used by conflicting writers/readers.
  Existing tags/restoration are not proof the whole suite is isolated; audit new consumers.

## Synchronization and locks

Page `goto`/`reload` default to `domcontentloaded`. Explicit load states/timeouts are
honored. Navigation errors are neither suppressed nor automatically replayed; there
is no worker-wide latch that silently changes future tests' semantics. Native
`waitForURL`, `waitForNavigation` and `waitForLoadState` keep Playwright's contracts.
Use observable role/label/test-id readiness instead of `networkidle` or fixed sleeps.

Arm response/navigation waits **before** the triggering action. XHR helpers match
method, origin and exact pathname, check success, and await the complete body.
HTTP completion alone is not an HTMX DOM swap: assert the resulting success banner,
DOM state or redirect before navigating away. Save tests must reload or read
independently and assert persisted values; typed input is not persistence evidence.
`saveNewContent` requires the expected `HX-Redirect` rather than waiting blindly when
an HTTP-200 application-error banner is returned.

`@lock-*` tags acquire sorted, deduplicated, same-host directory locks. Ownership tokens
prevent an old holder releasing a replacement lock. Delayed heartbeats/old mtimes no
longer authorize stealing a live lock. Acquisition is bounded and includes owner
metadata in failure messages; `lock-waits` JSON attachments measure contention.
An orphaned lock is deliberately **not** removed automatically: after stopping every
runner targeting that environment, inspect the named directory/owner and remove it.
Filesystem locks cannot coordinate separate CI runners. Do not shard a deployment.
Two file-level workers remain the CI default; within-file parallelism stays disabled.

## CI and diagnostics

`pr-tests.yml` keeps the full suite unfiltered. Trusted same-repository runs deploy a
run/attempt-named Worker and D1 database, apply migrations and run a separate readiness
step. No branch-named database is deleted or reused. Cleanup targets only the allocated
run name. Existing R2/KV bindings are still shared; cross-job isolation is **not complete**
until those resources are separately provisioned/namespaced. Do not introduce sharding.

Fork and Dependabot runs execute the full suite on isolated local Workers/D1 without
Cloudflare/Codecov secrets, persisted checkout credentials or privileged npm caches.
The existing external-environment approval gate remains. Changes to a
`pull_request_target` workflow take effect only after landing in the base branch.
Remote execution and GitHub environment settings must be verified separately; local
validation does not certify deployed-preview behavior or fork security configuration.

Artifacts `e2e-<run_id>-<attempt>` include:

- `playwright-report/index.html` — readable report (`npx playwright show-report`).
- `test-results/results.json` and `junit.xml` — attempt/outcome machine-readable results.
- Failed-attempt `trace.zip`, screenshots, retry video, error-context and lock-wait attachments.
- `e2e-logs/playwright.log`, deployment log and checkout/run metadata when available.

Open traces with `npx playwright show-trace path/to/trace.zip`. Diagnose the **first**
attempt and distinguish setup from assertion failures. A retry recovery is not an
infrastructure diagnosis. CI fails on recovered flakes as well as final failures.
Artifacts upload under `always()`; hard runner termination can still prevent final
report creation/upload. Traces can contain disposable session cookies and test data:
retain briefly, restrict artifact access and never add `.dev.vars` or raw credentials.
See `docs/testing/e2e-infrastructure-audit.md` for measured evidence and limitations.
