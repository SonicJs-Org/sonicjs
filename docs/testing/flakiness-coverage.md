# Flakiness runner coverage inventory

Inventory base: `7b6ecb7b8cd9728f2edc75316445feac311f3707`, branch
`feat/flakiness-reporters`, collected 2026-11-05. This first change inventories
coverage only. Reporter wiring and service cutover are future work. No claim of
complete reporting coverage is made: the CLI verifier and manual API collection
remain explicit exclusions, and WWW discovery currently fails.

## Locked tools and prerequisite

Root npm lock resolves `@playwright/test`, `playwright`, and `playwright-core`
to **1.63.0**, Vitest and `@vitest/coverage-v8` to **4.1.11**. Manifest ranges
(`^1.53.1`, `^4.1.9`) are not resolved versions. The starter advertises
`vitest ^4.0.15`; generated projects resolve their own dependencies. The sample's
separate pnpm lock references Vitest 4.1.12; root npm CI uses `package-lock.json`,
not that lock. Collection used Node 22.23.1 and npm 10.9.8 installed by parent.

Baseline `npm ci` failed with missing nested esbuild 0.28.2/platform entries,
also observed by parent in main CI run 42110926037. Prerequisite lock repair
adds only 27 missing entries under Vitest; all existing package metadata,
versions, dependency ranges and top-level lock fields remain unchanged. Parent's
repaired install log ends with `added 1202 packages in 26s`. Installation can
regenerate the migration bundle timestamp; that unrelated change is excluded.

## Workspace commands and destinations

All ten tracked package manifests were inspected, including non-workspace
starter/demo manifests. Commands below are actual scripts, not inferred tests.
Watch/UI variants retain the same destination as their batch runner.

| Manifest / entry point | Actual command or delegation | Planned destination / disposition |
| --- | --- | --- |
| root `test`, `test:cov`, `test:watch` | `npm run test --workspace=@sonicjs-cms/core`; `npm run test:cov --workspace=@sonicjs-cms/core`; `npm run test:watch --workspace=@sonicjs-cms/core` | `core-unit` |
| core `test`, `test:cov`, `test:watch` | `vitest run`; `vitest run --coverage`; `vitest` | `core-unit` |
| SDK `test`, `test:watch` | `vitest run`; `vitest` | `sdk-unit`; active local runner, no workflow caller |
| root direct Vitest config | `vitest` / `vitest run --config vitest.config.ts` from root | `root-unit`; currently zero discoveries, not a passed suite |
| root `e2e`, `e2e:ui` | `playwright test --config=tests/playwright.config.ts` optionally `--ui` | `cms-e2e` |
| root `e2e:smoke`, `e2e:smoke:ui` | `playwright test --config=tests/playwright.smoke.config.ts` optionally `--ui` | `cms-smoke` |
| root `e2e:www` | `playwright test --config=tests/playwright.www.config.ts` | `www-e2e`, discovery blocker below |
| direct no-server config | `playwright test --config=tests/playwright-no-server.config.ts` | `cms-e2e`, same actual target as main: `BASE_URL` or `http://localhost:8787`; only server ownership differs |
| direct infrastructure config | `playwright test --config=tests/playwright.infrastructure.config.ts` | `runner-contracts` |
| future reporting contract config | Not present at inventory base | reserve `reporting-contracts`; do not include in baseline totals |
| create-app `test` | `node test-cli.js` | Genuine standalone manual CLI verifier; excluded from Vitest/Playwright adapters, remains uncovered by proposed reporter wiring |
| sample app `test`, `test:watch` | `vitest --run`; `vitest` | Active script entry points, but no local Vitest config; ancestor root config/include is relative to invocation cwd. Collection exits 1 on Playwright API in contact-form spec; reporting destination deferred pending dedicated config/runner decision, explicitly uncovered |
| starter `test`, `test:watch` | `vitest --run`; `vitest` | Generated project scaffolding, no tracked test/config; not repository suite; consumer-owned reporting |
| stats, templates, WWW, employee-directory | No test scripts | Excluded: builds, lint, type checks, preview and deployment are not tests |

`packages/create-app/test-cli.js` spawns the CLI with `--template=starter`,
`--database=test-db`, `--bucket=test-media`, `--include-example`, `--skip-install`,
`--skip-git`, `--skip-cloudflare`; checks generated files and DB/R2/CACHE_KV
configuration, and cleans its generated directory. It is an active verifier
with exit status, not a dead documentation example. It has no collection mode,
so was not executed in this collection-only task. No node:test runner or Jest,
Mocha, Newman automation was found among tracked invocations.

The sample's `src/plugins/contact-form/test/contact.spec.ts` imports Playwright,
contains two browser tests, but lies outside all five Playwright testDirs.
The sample Vitest command does discover it through the inherited config, but
collection fails with `Playwright Test did not expect test.describe() to be called here.`
This is a broken active script path, not a dead test. It remains explicitly
uncovered until an intentional browser config or test migration exists;
do not claim CMS collection covers it. Starter commands likewise do not create
tests. `tests/postman/` is a manual Postman collection with request assertions
and authentication pre-request scripts; no active Newman/CI caller, excluded
from these adapters. Archived HTML reports are artifacts, not entry points.

## Effective configurations

| Config | Discovery / inheritance | Existing reporting and policy |
| --- | --- | --- |
| `packages/core/vitest.config.ts` | Independent; cwd core; `src/**/*.{test,spec}.{js,ts}`; explicit quarantines preserved | Default Vitest test reporter; coverage text/json/html; Node/globals |
| `packages/sdk/vitest.config.ts` | Independent; cwd SDK; default Vitest discovery | Default reporter; Node/globals |
| root `vitest.config.ts` | Independent, not a workspace aggregator; root `src/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}` | Default test reporter; coverage text/json/html and 90% thresholds; no root src tests |
| `tests/playwright.config.ts` | `tests/e2e`; Chromium; global setup/teardown | list/html/json/junit plus stats-live-reporter; local workers 1/retries 0; CI workers 2/retries 1 local or 3 remote; file-level parallelism |
| `tests/playwright-no-server.config.ts` | Spreads main; only `webServer: undefined` | Inherits main reporters, discovery, setup and policy |
| `tests/playwright.smoke.config.ts` | Spreads main; `.*smoke.spec.ts` | Replaces reporters with list/html/json/junit; retries 0, workers 1, timeout 30s; inherits setup/server |
| `tests/playwright.infrastructure.config.ts` | Spreads main; only `126-runner-contracts.spec.ts` | Replaces reporter with list; removes setup/teardown/server; retries 0 |
| `tests/playwright.www.config.ts` | Independent; `tests/www`; Chromium | HTML only; fully parallel; CI workers 4/retries 2, local workers 1/retries 0; own WWW server/URL |

Core quarantines are exact config exclusions (19 explicit test files, plus
node_modules/dist patterns), not newly skipped tests. Preserve them and the root
coverage exclusions when wiring reporters. Coverage `reporter` keys refer to
coverage formats, not test-result reporter plugins. SDK does not inherit core.
Passing core config from root without changing cwd is ambiguous: its relative
include remains rooted at invocation cwd; use the package cwd below.

## Workflow callers, scripts and reporter bypasses

All eight tracked workflows inspected: `pr-tests.yml`, `update-badges.yml`,
`deploy-demo-cms.yml`, `deploy-demo.yml`, `deploy-stats.yml`, `deploy-www.yml`,
`publish.yml`, `release-announce.yml`. Only `pr-tests.yml` executes test runners:
`npm run test:cov` delegates to core, then
`npx playwright test --config=tests/playwright.config.ts 2>&1 | tee e2e-logs/playwright.log`.
It installs Chromium separately. Trusted preview uses provisioned remote
resources/BASE_URL; untrusted path runs the local full suite. SDK, smoke, WWW,
no-server and infrastructure have no current CI runner invocation.
`update-badges.yml` greps source to count calls, not runner collection/execution.
Other workflows build/deploy/publish/announce; no additional test runner.

`pr-tests.yml` calls `scripts/lint-e2e-no-skip.sh` (static policy check) and
`scripts/lint-e2e-tags.sh`; the latter invokes
`npx playwright test --config tests/playwright.config.ts --grep-invert "$TAGS" --list`
and intentionally ignores runner exit status while inspecting text. This is a
collection-only policy check, excluded from uploaded test runs. It currently
uses configured reporters: future wiring must keep list-only invocations from
creating misleading execution runs or credential fallback. Do not change it here.

Root `e2e:report` and CI call
`bash packages/stats/scripts/report-playwright.sh test-results/results.json`:
legacy ingestion, not a runner. `tests/e2e/stats-live-reporter.ts` streams results
and can fall back to `.dev.vars`; no credential files were read in this task.
Both ingestion paths remain untouched. Seed/report scripts are not extra tests.

Tracked `--reporter`/`--reporters` override search found only documentation or
tool permissions: `.claude/settings.local.json` permits a verbose Vitest command;
`docs/ai/plans/coverage-improvement-batch2-plan.md` shows `--reporter=verbose`;
`packages/stats/docs/plans/2026-10-30-playwright-dashboard-plugin.md` shows
`--reporter=json` and `--reporter=json,list`. None is an active workflow override.
CLI overrides replace config reporters and will bypass adapters unless explicitly
preserved. This baseline deliberately uses `--reporter=json` to prevent legacy
stats fallback. No active `--reporters` invocation found.

Unmerged #1158 (`fix/1157-reporter-hardening`) and live-reporter workstreams need
parent coordination before eventual cutover. Do not close/comment/modify them
here; obsolete ingestion work must not merge after cutover without reconciliation.
Future adapter candidates are exact pins `@flakiness/playwright@2.0.3` and
`@flakiness/vitest@1.12.0`, additive alongside native and legacy reporters. CI must
disable upload; local upload requires explicit opt-in, token and project. Stable
suite/target/source metadata and absolute reports outside Playwright outputDir
belong to subsequent implementation, not this inventory.

## Reproducible baseline and limits

Run from repository root after parent installs locked dependencies:

```sh
PATH=/Users/lane/.nvm/versions/node/v22.23.1/bin:$PATH \
  python3 scripts/collect-flakiness-baseline.py \
  /Users/lane/.hermes/cache/scratch/sonicjs-flakiness-evidence/baseline
```

Helper launches the installed CLI directly without npx/network; clean child env
contains PATH, evidence HOME and NO_COLOR only. It invokes all five Playwright
configs with `test --list --reporter=json`, and `vitest list --json` from core,
SDK, root and sample (the latter audits its broken active script). It does not run tests, setup, teardown, applications or servers.
Vitest collection evaluates test modules; their import-time output is archived.
No auth keys, .dev.vars reads/copies or uploads are needed. Outputs are deliberately
outside git; the absolute CLI paths in raw commands are machine-specific.

Evidence root: `/Users/lane/.hermes/cache/scratch/sonicjs-flakiness-evidence/baseline`.
Each suite has raw `.stdout.json`, `.stderr.log`, and normalized `.identities.json`;
`collection-summary.json` records argv/cwd/exits/errors, multiplicities and duplicate
names. `source-hashes.json` preserves SHA-256 inventory of tracked JS/TS sources,
shell scripts, manifests, lock, runner configs and workflows for later comparisons.
Hashes reflect the observed working tree, including the parent-generated migration
bundle timestamp and repaired lock; they are not claimed to be pristine base hashes.
Use normalized repository-relative file/project/full-title tuples as identities;
retain multiplicity rather than deduplicating. Raw absolute paths are not stable IDs.

| Collection | Exit | Collected identities | Unique file/project/full-name identities |
| --- | ---: | ---: | ---: |
| core-unit | 0 | 2068 | 2068 |
| sdk-unit | 0 | 68 | 68 |
| root-unit | 0 | 0 | 0 |
| cms-e2e | 0 | 756 | 756 |
| cms-no-server | 0 | 756 | 756 |
| cms-smoke | 0 | 28 | 28 |
| runner-contracts | 0 | 2 | 2 |
| www-e2e | 1 | 0 (failed discovery) | 0 |
| sample-unit-audit | 1 | unavailable (collection error; no JSON) | unavailable |

No duplicate full names (project/title), or duplicate file/project/full-name identities, within any collected invocation. Every listed Playwright test has static `expectedStatus: passed`; none is marked skipped or expected-failing at collection.
Main/no-server intentionally repeat the same 756 identities; smoke and runner
contracts overlap main, so summing invocation totals is not unique repository
coverage. Playwright `expectedStatus` records statically skipped/expected-failing
tests, not outcomes. Runtime conditional skips cannot be inferred from listing.
Vitest JSON list exposes names/files, not skip/todo modes or execution outcomes;
its totals include discovered declarations without proving any ran or passed.
Root exit 0 with empty list is specifically not a successful test suite.

Sample collection confirms its active Vitest entry point fails on the contact-form
Playwright import; stdout is empty and the parser error is retained in the summary,
not misreported as a zero-test success.

WWW discovery fails because `tests/www/01-marketing-home.spec.ts` imports missing
`tests/www/utils/test-helpers`. Preserve failure; no test moves, import fixes or
exclusions applied. Full type-check/unit/E2E execution is intentionally outside
this collection-only task. Baseline establishes identities for subsequent reporter
comparison, not application correctness or complete reporting coverage.
