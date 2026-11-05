# Flakiness.io Testing Dashboard Implementation Plan

> **For Hermes:** Use the subagent-driven-development skill to implement this plan task-by-task; use Codex for all coding. This document is a plan, not authorization to implement, deploy, merge, or delete data.

**Goal:** Send SonicJS test results to Flakiness.io and replace the custom Playwright dashboard on `stats.sonicjs.com`, while preserving independent test artifacts and unrelated installation/demo analytics.

**Architecture:** Use the official Playwright and Vitest reporter plugins, with a small shared configuration layer—not a new SonicJS runtime plugin or custom dashboard. CI test jobs generate reports without Flakiness credentials; a separate trusted uploader publishes those reports using GitHub OIDC. Configured developers can opt into direct local uploads.

**Tech Stack:** TypeScript, Playwright, Vitest, GitHub Actions, official `@flakiness/playwright` / `@flakiness/vitest` reporters, pinned `flakiness` CLI; existing Cloudflare Workers/D1 only for the legacy dashboard retirement.

**Prepared:** November 5, 2026.

---

## 1. Decisions and boundaries

1. **Use existing reporter plugins.** Do not build another ingestion API, dashboard, CMS plugin settings UI, or Cloudflare proxy. Flakiness provides native reporters for both existing runners.[2][3]
2. **One Flakiness project linked to `SonicJs-Org/sonicjs`.** The actual `org/project` identifier must come from project setup; do not assume it matches the GitHub organization. GitHub App installation alone does not link a project.[1]
3. **Cover every active test entry point, not just CMS E2E.** Include unit/integration, smoke, marketing-site, infrastructure, and developer/no-server runs. Keep a checked-in coverage inventory so new configurations cannot silently omit reporting.
4. **Completed-run dashboard, not live streaming.** The Playwright reporter uploads in `onExit`; Vitest uploads after completion. Do not promise the existing live, test-by-test progress display. If live progress is essential, stop before cutover and resolve that product requirement rather than building undocumented streaming behavior.[2][3]
5. **Keep native evidence.** Preserve Playwright JSON/JUnit/HTML, traces, screenshots, logs, Vitest output, and Codecov coverage. Flakiness reporting is not a replacement for CI's test exit status or required checks.
6. **No silent policy changes.** Preserve test discovery, skips/quarantines, retries, workers, fixture locks, disposable-target guards, timeouts, and existing deployment ownership safeguards. No sharding/rebalancing in this migration.
7. **Retire only test analytics.** The stats domain, Worker, shared D1 database, installation telemetry, demo-login telemetry, and unrelated stats dashboard remain.
8. **No historical import by default.** Archive existing Playwright data read-only; begin a new history in Flakiness. Backfill is separate work after verifying schema, commit identity, duplicate handling, and retention.

## 2. Verified repository baseline

Inspected checkout: `/Users/lane/Dev/refs/sonicjs`, `main`, SHA `5439f91d3903006902cf34c99dfec46b4fea6927`. Rebase and repeat inventory before implementation; related reporter/dashboard worktrees exist and are not equivalent to main.

- Root `package.json` delegates `npm test` and `npm run test:cov` to core. There is no `tests/package.json`.
- Lockfile resolves Playwright **1.63.0** and Vitest **4.1.11**. npm registry inspection returned `@flakiness/playwright` **2.0.3**, `@flakiness/vitest` **1.12.0**, and `flakiness` **0.327.0**. These are candidate exact pins, not installed or tested dependencies.
- Main E2E registers list/HTML/JSON/JUnit plus `tests/e2e/stats-live-reporter.ts`.
- Smoke and infrastructure configurations override reporters; www uses only HTML. Editing the base E2E config alone will miss these suites.
- Effective core Vitest config is `packages/core/vitest.config.ts`; SDK has `packages/sdk/vitest.config.ts`; root `vitest.config.ts` is separate. Root Vitest currently includes only root `src/**`, so new reporting contract tests need an explicit configuration.
- `.github/workflows/pr-tests.yml` is named **PR Tests**. It triggers on `pull_request_target` and selected pushes, checks out PR head SHA for PRs, runs core coverage and full CMS E2E, and uploads native artifacts under `always()`.
- The workflow currently has both live reporter credentials and a final `report-playwright.sh` upload. `GITHUB_SHA` is not necessarily the checked-out/tested commit under `pull_request_target`.
- Retry-green is not currently forbidden by configuration: `failOnFlakyTests` is commented out. Keep this migration separate from changing that policy; still expose recovered retries as flaky.
- Main's `packages/stats/src/routes/playwright-ingest.ts` implements batch ingestion. Do not assume the live endpoint/hardening work in other worktrees is merged or needed for this migration.
- `packages/stats/src/index.ts` registers both installation and Playwright collections/plugins in the same service. Shared `documents` tables must not be dropped.

**Inspection limitation:** a grouped workspace-manifest/workflow inventory was blocked by an unanswered execution-consent prompt. It was not executed or retried. The configurations and principal workflows above were inspected separately, but the complete workspace test-script inventory remains a mandatory Task 1 gate. This plan does not claim every workspace suite is already identified.

Pre-existing untracked plan/report artifacts in the checkout are unrelated and must be left untouched.

## 3. Reporting coverage contract

| Test entry point | Config / integration point | Report identity |
|---|---|---|
| `npm test`, `npm run test:cov`, core targeted runs | `packages/core/vitest.config.ts` | `core-unit` |
| SDK unit/integration tests | `packages/sdk/vitest.config.ts`; confirm manifest script | `sdk-unit` |
| Direct root Vitest runs | `vitest.config.ts` | `root-unit` |
| `npm run e2e`, UI, targeted main-config runs | `tests/playwright.config.ts` | `cms-e2e` |
| `npm run e2e:smoke`, smoke UI | `tests/playwright.smoke.config.ts` | `cms-smoke` |
| `npm run e2e:www` | `tests/playwright.www.config.ts` | `www-e2e` |
| Runner/browser infrastructure tests | `tests/playwright.infrastructure.config.ts` | `runner-contracts` |
| Existing-server developer tests | `tests/playwright-no-server.config.ts` | `cms-e2e`, actual target mode |
| New reporting contract tests | New `tests/reporting/vitest.config.ts` | `reporting-contracts` |
| Other workspace/demo test commands | Discover and list in Task 1 before closing scope | Named suite per actual runner/config |

Type-checking, linting, builds, and deployments remain GitHub workflow checks; do not fabricate test cases for them. Existing exclusions/quarantines remain documented exclusions, not reported passes. A suite prevented from starting by an earlier failure is **not run**, not zero-test success.

For any discovered runner without a native reporter, assess JUnit output first. Flakiness has a separate JUnit converter; use that only for uncovered runners, never as a second upload of a suite already covered natively.[4]

## 4. Configuration and data contract

### Dependencies and compatibility

Add exact, reviewed devDependency pins to root `package.json` and `package-lock.json`; inspect package manifests/peer compatibility and fresh-install behavior before committing. Playwright's documented minimum is 1.57; Vitest's is 4.0. Current locked runner versions meet those minimums, but this is not an integration test.[2][3]

Do not upgrade either runner as part of installation. Check all importing Node execution contexts against the reporters' Node engine requirement: `^20.17.0 || >=22.9.0` (registry metadata). CI currently selects Node 22.

### Small shared configuration module

Create `tests/reporting/options.ts` with factories for runner options and absolute, repository-rooted output paths. Keep vendor reporter lifecycle code untouched. Test policy with a supplied environment object rather than reading global process state throughout tests.

- Repository variable: `FLAKINESS_PROJECT`, actual configured project slug.
- Local opt-in: `SONICJS_TEST_UPLOAD=1` plus locally supplied `FLAKINESS_ACCESS_TOKEN`; no token in source, CMS settings, or `.dev.vars` fallback.
- CI: **always `disableUpload: true`**, regardless of mutable local opt-in settings. Test jobs get neither Flakiness access tokens nor `id-token: write`.
- No credentials: still generate local reports and print a concise upload-disabled notice.
- Outputs: `test-results/flakiness/<suite>/<invocation>/`, one directory per actual invocation. Include job/shard/attempt disambiguators when applicable; never share mutable output directories between concurrent runs.
- Preserve standard terminal reporters and existing machine-readable/native artifacts.
- Vitest: set `includeTaskLocation: true`, retain `default`, and preflight duplicate full test names. Do not silently use unstable automatic renaming.[3]

Illustrative vendor configuration inside the shared factories (not a complete patch):

```ts
// Playwright reporter entry, appended alongside existing native reporters.
['@flakiness/playwright', {
  flakinessProject: process.env.FLAKINESS_PROJECT,
  outputFolder: absoluteSuiteOutputDirectory,
  disableUpload: isCI || !localUploadOptIn,
  open: 'never',
}]

// Vitest test configuration, merged without changing include/exclude/coverage.
{
  includeTaskLocation: true,
  reporters: [
    'default',
    ['@flakiness/vitest', {
      flakinessProject: process.env.FLAKINESS_PROJECT,
      outputFolder: absoluteSuiteOutputDirectory,
      disableUpload: isCI || !localUploadOptIn,
    }],
  ],
}
```

### Identity and metadata

Use stable `FK_ENV_SUITE`, `FK_ENV_TARGET` (`local-worker`, `preview-worker`, `www`), and `FK_ENV_SOURCE` (`local`, `ci`). These properties split histories, so do **not** put changing run IDs, SHAs, branch names, preview URLs, PR numbers, or timestamps into `FK_ENV_*`.[7]

Use titles/CI links and a sidecar manifest for changing invocation metadata: producer workflow/run ID/attempt, job, shard, suite, actual `git rev-parse HEAD`, PR association, sanitized target URL, start/end, and producer step outcome. Preserve Playwright project/browser identity. Verify the vendor's recorded commit matches the actual checkout; do not blindly replace it with `GITHUB_SHA`.

## 5. CI publishing and security

Use the documented two-workflow artifact handoff as the basis, extended to all CI reports rather than exposing OIDC to PR-controlled test processes.[5]

### Producer: `.github/workflows/pr-tests.yml`

- Retain existing test commands, failure propagation, deployment conditions, and cleanup.
- Set report-generation metadata before each test step; no uploader credentials.
- Upload all generated report directories and their manifests under `always()`, including unit reports when subsequent E2E never starts.
- Artifact names include producer run ID, run attempt, job, and suite. Preserve relative report/attachment structure and native evidence; start with existing seven-day GitHub retention.
- Handle failing tests and partial reports explicitly. Hard-killed/cancelled jobs may not produce a usable vendor report; mark missing/interrupted evidence in the workflow summary, never infer success.
- Keep old stats reporting only for the bounded comparison period; never add new privileges to preserve it.

### Consumer: new `.github/workflows/flakiness-upload.yml`

- Trigger `workflow_run` on **`PR Tests`**, `types: [completed]`; also support any additional producer workflows identified in Task 1.
- Validate repository, producer workflow ID/path, event, run ID, attempt, and allowed producer outcomes using GitHub metadata. Cover `push` and the existing **`pull_request_target`** trigger; do not copy a fork example that handles only `pull_request`.
- Use a fresh runner, job-scoped `actions: read`, `contents: read`, `id-token: write`; no Cloudflare/npm-publish secrets, privileged caches, or PR checkout/dependency installation.
- If repository helpers are needed, check out only the trusted default-branch revision, with persisted credentials disabled. Install the exact pinned CLI independently of artifact contents; pin Actions to reviewed immutable revisions.
- Download artifacts only from the exact triggering run/attempt. Treat all archives, report fields, and manifests as untrusted input.
- Before publishing, validate schema, size limits, allowed filenames, report/attachment containment, no absolute or `..` paths, no symlinks, and no executable hooks. New `scripts/testing/validate-flakiness-artifacts.mjs` performs these checks.
- Force the destination project and endpoint from trusted workflow configuration. Artifact-supplied project/endpoint fields cannot redirect credentials or uploads.
- Resolve and validate tested SHA/PR association using trusted GitHub run/event/PR data. `workflow_run.head_sha` and `GITHUB_SHA` alone are insufficient for this repository's `pull_request_target` checkout. Test real event payloads and stale PR updates; if identity cannot be established, fail closed rather than attributing results to the base commit. Fork-generated evidence is still untrusted evidence, not proof of test honesty.
- Publish using `flakiness upload --project "$FLAKINESS_PROJECT" --endpoint https://flakiness.io <validated-directory>` through the pinned CLI. The CLI accepts report directories and supports GitHub OIDC.[6]
- Record each returned run URL and delivery outcome in the job summary. Read back the exact uploaded run and verify SHA, suite, counts, and artifacts before declaring delivery successful. The API finalizes then processes reports; upload acceptance alone is not dashboard verification.[8]
- Use concurrency keyed by producer run/attempt. Test whether resubmission is idempotent; do not assume a retry after an ambiguous response is safe. Maintain delivery evidence per report, and make an upload-only rerun possible without rerunning tests.
- Set bounded timeouts. Upload failures are visible in the separate reporting workflow; they cannot rewrite a failed test result or make existing test checks green. Do not make the new vendor check required until rollout is proven.

**Existing security debt:** main's test job already executes PR code before later deployment steps guarded by mutable environment state. This migration must not expand that trust. Coordinate broader workflow hardening separately; do not claim it has been repaired by adding an isolated uploader.

## 6. Implementation tasks

For every code-producing task: write focused failing tests, run them and confirm the intended failure, implement minimally, rerun the same tests, then commit explicitly staged files. Split the numbered substeps into small work units; do not combine reporter wiring, trust-boundary changes, and backend deletion into one unreviewable commit.

### Task 1 — Freeze scope and prepare the first isolated worktree

**Files:** Create `docs/testing/flakiness-coverage.md`; inspect every tracked workspace `package.json`, test config, workflow, and runner invocation script.

1. Start from a fresh main snapshot in dedicated branch/worktree `feat/flakiness-reporters`; preserve all existing worktrees and dirty artifacts.
2. Complete the blocked workspace inventory with user-authorized read access. Enumerate actual scripts, runner versions, CI callers, config inheritance, and reporter CLI overrides. Populate the coverage matrix, including suites not currently run in CI.
3. Search for `--reporter` / `--reporters` overrides and reporting scripts; these can bypass configured plugins.
4. Record baseline collected test identities and current exclusions using credentials-free collection. Collect Playwright through the JSON/list reporter and Vitest through its list output; preserve multiplicities, not just totals.
5. Coordinate the existing `sonicjs-1157` and live-reporter workstreams so obsolete ingestion work is not merged after cutover.

**Gate:** every active test entry point has an explicit reporter destination or a justified exclusion. No claim of “all testing” before this inventory is complete.

### Task 2 — Add a reporting contract harness and dependency pins

**Files:** Modify root `package.json`, `package-lock.json`, `.gitignore`; create `tests/reporting/vitest.config.ts`, `tests/reporting/options.test.ts`, and fixtures under `tests/reporting/fixtures/`.

1. Add `test:reporting` → `vitest run --config tests/reporting/vitest.config.ts` and a configuration that selects only reporting contract tests.
2. Write policy tests: local/no token, explicit local upload, CI override, absolute per-suite paths, repeated invocations, and no secret fallback.
3. Confirm failures before creating `tests/reporting/options.ts`; install reviewed exact vendor versions without runner upgrades.
4. Ignore generated report artifacts; fresh `npm ci` must succeed with the lockfile.

**Verify:** `npm run test:reporting`; `npm run type-check`. A clean-install check uses CI-equivalent Node/npm and must not depend on pre-existing `node_modules`.

### Task 3 — Wire every Playwright configuration

**Files:** Modify all five `tests/playwright*.config.ts` variants listed in the matrix, including no-server inheritance; create `tests/reporting/playwright-wiring.test.ts` and focused fixtures.

1. Write configuration-contract tests proving every effective reporter list contains the vendor reporter exactly once, all existing native reporters remain, and infrastructure still owns no server/setup/teardown.
2. Add the shared factory to base, smoke, www, infrastructure, and no-server behavior without duplicate inheritance.
3. Write focused subprocess fixtures for pass, final failure, retry recovery, skip/expected failure, setup failure, timeout/interruption, and attachments. Test actual report JSON and original process exit codes, not only mocked options.
4. Isolate synthetic fixtures from production suites; upload-disabled tests must make no external requests. Test reporter/report-directory failures and bounded behavior.

**Verify:** `npm run test:reporting`; Playwright collection identity matches baseline for each config. Real fixtures prove reporting preserves attempts and failure meanings; unsupported vendor behavior becomes an explicit cutover blocker.

### Task 4 — Wire Vitest and remaining test runners

**Files:** Modify `packages/core/vitest.config.ts`, `packages/sdk/vitest.config.ts`, root `vitest.config.ts`, `tests/reporting/vitest.config.ts`, plus any additional configs confirmed by Task 1; create `tests/reporting/vitest-wiring.test.ts`.

1. Test configuration wiring, default terminal output preservation, task locations, and independent output paths from root and workspace working directories.
2. Exercise passing/failing/retried/skipped tests, import/setup errors, and watch reruns with native reporters. Audit duplicate full names; resolve only actual collisions with reviewed test changes, not wholesale renaming.
3. Add native integration or a single JUnit-conversion path for any remaining active runner. Pin that converter if needed; avoid legacy deprecated CLI conversion commands.[4][6]
4. Ensure adding the reporting-contract suite does not recursively discover/run itself through core or root test globs.

**Verify:** `npm run test:reporting`; `npm test -- --run`; `npm run test:cov`; SDK via `npx vitest run --config packages/sdk/vitest.config.ts --root packages/sdk` after confirming resolved config/root behavior. Document actual discovered workspace scripts instead of inventing them.

### Task 5 — Add artifact and provenance validation

**Files:** Create `scripts/testing/validate-flakiness-artifacts.mjs`, `scripts/testing/upload-flakiness.mjs`, `tests/reporting/artifact-validation.test.ts`, and sanitized event/report fixtures.

1. RED tests for malformed reports, traversal/symlinks, excess sizes, unknown suites, mismatched run/attempt/commit, missing attachments, hostile endpoint/project overrides, stale PR heads, and forged success manifests.
2. Implement schema/path validation against the pinned report schema; never execute artifact code or trust manifests over GitHub step outcomes.
3. Test upload invocation with a stub CLI/network boundary, no live credentials, bounded timeouts, partial delivery, and ambiguous retry outcomes.
4. Keep producer report identity/CI links intact when the consumer workflow has a different run ID and checkout SHA.

**Verify:** `npm run test:reporting`; tests demonstrate that malicious artifacts are rejected before any privileged upload call.

### Task 6 — Add the isolated upload workflow

**Files:** Modify `.github/workflows/pr-tests.yml`; create `.github/workflows/flakiness-upload.yml`; add workflow contract tests under `tests/reporting/`.

1. Test that producer jobs have no new Flakiness credentials/OIDC permission; consumer cannot check out PR code or install PR dependencies.
2. Add per-suite `always()` artifact preservation, including early unit failures. Add consumer trigger and immutable authorization/metadata validation.
3. Validate workflows with `actionlint`; tests cover push, same-repo PR, fork `pull_request_target`, Dependabot, cancelled/skipped suites, and workflow rerun attempts.
4. Confirm rollout trigger constraints: arbitrary feature-branch pushes are not currently enabled. The `pull_request_target` workflow comes from base; a new `workflow_run` consumer must exist on the default branch before it triggers. Review/merge additive infrastructure in stages; do not bypass this by granting OIDC to the current test job.

**Verify:** `npm run test:reporting`; `actionlint .github/workflows/pr-tests.yml .github/workflows/flakiness-upload.yml`; real producer artifacts and consumer logs after the additive workflow is available on main.

### Task 7 — Configure the service and prove end-to-end delivery

**External setup, with Lane's approval:** create/link project, install GitHub App for the selected repository, set repository variable `FLAKINESS_PROJECT`, confirm access controls, timezone, retention, plan capacity, and upload limits. OIDC requires both project/repository binding and job permission.[1]

1. Inspect traces/screenshots/logs for session cookies, test credentials, PII, and private URLs. Use disposable seeded data and approve project visibility before any real upload. Keep tokens and secrets out of all `FK_ENV_*` values.
2. Configure result and attachment retention intentionally; they are separate settings bounded by the organization's plan.[9]
3. Publish representative unit, CMS E2E, smoke, www, and infrastructure evidence, including a controlled failing fixture and retry recovery. For suites not ordinarily in CI, use an explicit reviewed producer/manual run rather than claiming they already run there.
4. Read back exact dashboard/CLI runs: actual tested SHA, PR link, suite/environment, test identities, retries, skips, failure diagnostics, trace/screenshot availability, and source workflow URL.
5. Test a vendor outage, absent authentication, failed upload, and upload-only retry. Confirm native artifacts survive and test exit codes remain unchanged.

**Gate:** save real run URLs and count comparisons for every inventoried suite. No account, quota, upload, or dashboard success is asserted until exercised.

### Task 8 — Compare, switch, and stop old ingestion

**Files:** Modify `tests/playwright.config.ts`, `.github/workflows/pr-tests.yml`, root `package.json`; update `docs/testing/flakiness-coverage.md`.

1. Compare Flakiness against native JSON/JUnit and old stats over representative local, main, same-repo PR, and fork runs. A practical target is three consecutive representative executions per active suite; expensive full-suite repeats require purpose, not repetition for its own sake.
2. Reconcile unique tests separately from attempts. Explicitly verify retry-green is flaky, not clean; setup errors/aborted runs cannot become successful empty runs.
3. Remove registration of `stats-live-reporter.ts`, the old stats upload step, and `PLAYWRIGHT_STATS_*` env wiring. Replace/document `e2e:report` as explicit upload of an existing validated Flakiness report, or remove it with a documented replacement command.
4. Stop dual publishing at this point. Keep backend data and rollback capability until the soak/acceptance gate is signed off.

### Task 9 — Retire the old Playwright dashboard safely

**Files:** Remove obsolete `tests/e2e/stats-live-reporter.ts`, `packages/stats/scripts/report-playwright.sh`, `packages/stats/scripts/seed-playwright.mjs`, and Playwright-only ingest/collection/dashboard implementation when no references remain. Modify `packages/stats/src/index.ts`, `packages/stats/src/admin-menu.ts`, `tests/e2e/global-teardown.ts`, and docs.

1. RED regression tests prove installation/demo analytics, `/v1/events`, `/stats-health`, and the unrelated stats admin menu still work after Playwright registrations are removed.
2. Replace legacy `/admin/playwright` entry points with an authenticated deprecation page/link to the configured Flakiness project for an announced transition period; no old D1 aggregate queries. Validate fixed destination and preserve auth/core-plugin menu behavior.
3. Preserve `packages/stats/src/plugins/stats-dashboard/**`, `installs`/`events`, telemetry producers, and E2E specs `97-stats-dashboard-fixes.spec.ts` / `100-demo-login-stats.spec.ts`.
4. Archive Playwright records selectively by `playwright_runs` / `playwright_tests` type, with a verified backup/count, before any separately approved deletion. Never drop shared tables, the Worker, database, or domain.
5. Revoke `PLAYWRIGHT_STATS_API_KEY` and Worker `PLAYWRIGHT_API_KEY` only after all old producers are stopped and rollback no longer needs them. Do not inspect or copy secret values into the plan/logs.
6. Keep `deploy-stats.yml`: it deploys unrelated telemetry too. Deploy retirement only after typecheck/regression gates and approval.

### Task 10 — Final acceptance, docs, and handoff

**Files:** Update `docs/testing.md`, `tests/e2e/README.md`, `packages/stats/README.md`, and the coverage inventory; mark historical dashboard plans superseded without erasing them.

Run and archive actual exit statuses/artifacts for:

```bash
npm ci
npm run test:reporting
npm run type-check
npm run test:cov
npm run build:core
npx tsc --noEmit --project packages/stats/tsconfig.json
actionlint .github/workflows/pr-tests.yml .github/workflows/flakiness-upload.yml
```

For CMS acceptance, allocate a fresh owned `E2E_PERSIST_DIR`, unset inherited `BASE_URL`/`E2E_REUSE_SERVER`, apply local D1 migrations using that same path, and set `E2E_DISPOSABLE_TARGET=1`. Then run:

```bash
npm run e2e -- --workers=2 --retries=0
npm run e2e:smoke
npm run e2e:www
npx playwright test --config=tests/playwright.infrastructure.config.ts --workers=2 --retries=0
```

Run no-server mode only against an owned prepared disposable server. Archive each invocation before subsequent runs overwrite native output. Also execute every additional active runner discovered in Task 1. Run targeted stats-worker regressions against an owned disposable stats target; conditional skips on the CMS app are not proof that the preserved dashboard works.

Document local credential setup, opt-in/disable behavior, all suite commands, direct report viewing, upload-only recovery, artifact location, privacy/retention, and the completed-run limitation. Verify final-head CI/E2E and independent review. No test deletions, new skips, weakened assertions, or retry-based claims of clean acceptance.

## 7. Rollout, rollback, and completion

**Suggested PRs, each with its own branch/worktree:**

1. `feat/flakiness-reporters`: additive native reporters, shared policy, coverage inventory, contract tests; old dashboard remains.
2. `ci/flakiness-publishing`: trusted uploader, artifact/provenance checks, service trial and cutover; staged default-branch workflow activation as required.
3. `chore/retire-playwright-dashboard`: removal of old producers/backend UI after accepted evidence and soak, preserving analytics and historical data.

Keep branches based on the latest merged predecessor; monitor every published PR through verified checks/E2E. Merges/releases require Lane's approval, all checks passing, and the standing after-8-PM-PST window.

**Rollback:** disable publishing/consumer workflow, retain native artifacts, and revert reporter/cutover commits. Restore legacy reporter/ingest wiring only if its credentials and backend are still valid. Data deletion is outside the initial migration precisely so rollback does not require reconstructing history.

**Done means:**

- Every active inventoried test entry point generates a correctly attributed Flakiness report.
- Configured local runs and CI runs—including forks—have verified delivery or an explicit, visible missing/delivery-failed outcome.
- Native test outcomes/artifacts and existing CI requirements are preserved.
- Actual hosted runs demonstrate counts, attempts, flaky classification, failure diagnostics, and attachment access.
- No uploader identity/secrets are exposed to PR-controlled tests.
- Old test-result ingestion/dashboard is retired without breaking unrelated stats telemetry or deleting shared data.
- Documentation names the new dashboard and does not promise live progress or imported historical results.

**Pending decisions before hosted rollout:** actual project slug/access; public/private report visibility; data/attachment retention and capacity; acceptance of post-run rather than live progress. These do not block writing this plan, but do block unapproved external setup/cutover.

## Sources

Source identifiers are generated from the research ledger; repository findings above are tied to the inspected SHA and exact local paths. URLs are presented as code for literal reference.

```text
[1] https://docs.flakiness.io/getting-started
[2] https://github.com/flakiness/playwright
[3] https://github.com/flakiness/vitest
[4] https://github.com/flakiness/junit-xml
[5] https://docs.flakiness.io/ci/github-actions-open-source
[6] https://docs.flakiness.io/cli/commands
[7] https://docs.flakiness.io/ci/configuring-environments
[8] https://docs.flakiness.io/api/upload-api
[9] https://docs.flakiness.io/settings/data-retention
```
