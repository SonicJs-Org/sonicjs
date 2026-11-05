# Flakiness runner coverage inventory

Inventory base: `7b6ecb7b8cd9728f2edc75316445feac311f3707`, branch
`feat/flakiness-reporters`, collected 2026-11-05. Baseline identities remain immutable. Tasks 2–4 add local reporter wiring;
service cutover remains future work. Current staged behavior and validation are
recorded below; WWW discovery, sample collection, and the local CLI installation
have explicit blockers. Manual API collection remains excluded.

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
| reporting contract config | `npm run test:reporting` | `reporting-contracts`; separate discovery, absent from immutable baseline totals |
| create-app `test` | `vitest run --config vitest.config.ts`, delegates unchanged `node test-cli.js` | `create-app-cli`; one real verifier, local missing-dependency failure retained |
| sample app `test`, `test:watch` | `vitest --run`; `vitest` | `sample-unit`; local config deliberately inherits root discovery/excludes/coverage relative to cwd. Genuine Playwright-import collection failure reported, exit 1; no tests skipped/moved |
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
This is a broken active script path, not a dead test. Task4 now records this collection failure under `sample-unit`; browser execution
remains blocked until an intentional browser config or test migration exists;
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

## Task 3: Playwright integration evidence

The main, smoke, WWW and infrastructure configurations append the shared official
reporter tuple. No-server inherits main's tuple once and retains its CMS target.
Main keeps list/HTML/JSON/JUnit and the existing stats reporter; smoke keeps its
four native reporters; WWW keeps HTML; infrastructure keeps list and no application
lifecycle. A source comparison against Task2 verifies every non-reporting config
byte remains unchanged. Targets are local-worker/preview-worker for CMS, www for
marketing and none for infrastructure. Config imports create no directories or
execution manifests. `--list` omits the vendor: version 2.0.3 otherwise writes a
synthetic run report during collection. Upload policy remains the shared factory's.

Focused fixtures live under `tests/reporting/fixtures` with `.case.ts` names and
explicit config matches, outside production discovery. Actual subprocess contracts
exercise pass, final fail, two-attempt recovery, static/runtime skip, expected
failure, setup/import failure, timeout, SIGINT, file/buffer attachments and native
JSON/JUnit/HTML. Children load a network-denial hook covering fetch, HTTP(S), TLS
and socket connects; a separate probe verifies denial. Actual Vitest output and
two sequential Playwright reports/attachments survive clearing the same native
outputDir. Shared flakiness root is never cleaned. Native report directories must
be siblings of the vendor directory because the vendor removes its own directory.
File collisions and unwritable directories produce bounded reporter errors while
expected test failure retains exit 1.

**Cutover blocker:** pinned Playwright reporter 2.0.3 drops the interrupted attempt
from vendor JSON on SIGINT. Native JSON records `interrupted`, process exits 130,
but vendor test has an empty attempts array. Contract explicitly characterizes this
loss; it does not establish complete interruption reporting. No vendor lifecycle
patch or replacement wrapper applied. Setup/import errors survive as unattributed
errors; expected failures retain failed status plus expectedStatus=failed and exit 0.

Evidence: `/Users/lane/.hermes/cache/scratch/sonicjs-flakiness-evidence/task3`.
Configuration, subprocess and interruption RED logs precede implementations;
preservation was an immediately passing characterization. Final contract/typecheck
logs record actual outcomes. `after-playwright/` retains fresh collection output;
`multiplicity-comparison.json` verifies unchanged file/project/title multiplicities
for every successful baseline invocation. Counts remain core 2068, SDK 68, CMS and
no-server 756 each, smoke 28, runner 2, root 0. WWW and sample retain their existing
collection errors. This verifies focused wiring, not a completed migration or full
application E2E correctness.


## Task 4: Vitest and remaining active runners

Official `@flakiness/vitest` **1.12.0** now accompanies the default terminal reporter
in core, SDK, root, reporting contracts, sample, and create-app CLI configs.
`includeTaskLocation: true` is enabled for actual runs. Core/root includes,
excludes, coverage formats and thresholds are unchanged; SDK discovery stays
relative to invocation cwd. Production discovery cannot recurse into reporting
contracts or `.case.ts` child fixtures. Runner pins remain 4.1.11 / 1.63.0.

The create-app wrapper executes the existing `test-cli.js` in its original package
cwd, inherits its stdout/stderr, rejects its failure/signal, and leaves generated
project cleanup with that verifier. It adds no invented build/typecheck cases.
The original verifier is unchanged. Both direct and wrapped executions currently
exit 1 because the local install lacks `@sindresorhus/merge-streams` (execa runtime
dependency). The wrapper records a real failed test. Successful scaffold checks
remain unverified until parent repairs installation and reruns both commands;
this is an explicit acceptance blocker, not a passing CLI claim. No converter
package or alternative JUnit ingestion path was introduced.

`vitest-integration.ts` observes documented reporter hooks alongside the official
reporter. Every `onTestRunStart`, including watch reruns, allocates an independent
absolute repository `flakiness-reports/<suite>/<invocation>/` folder and applies
stable suite/target/source metadata and the actual checked-out commit. The initial
configuration reserves a folder; actual start time is recorded at the start hook.
Native pinned reporter watch behavior is verified separately: it creates fresh
per-run internal state but rewrites the same configured output folder. Integration
updates only its public options at the start hook; official reporter still owns
all attempts and report generation. Real pass→fail watch fixtures prove both
native overwrite behavior and integrated independent reports with one attempt each.

Collection preflight uses vendor identity semantics: environment name
(`project.name || 'vitest'`), relative filename, and ordered ancestor/test titles.
Duplicate identities fail clearly and force upload disabled before vendor
finalization. Distinct filenames remain distinct identities. No auto-renaming,
broad suite renaming, exclusions, or fabricated attempts are enabled. A colliding
output path remains a visible nonzero runner failure even when assertions pass.

Independent Playwright metadata reporter now prints the disabled-upload notice,
records actual start/end and suite outcome, and sanitizes the effective project's
baseURL (credentials/query/fragment removed). Both integrations reuse the shared
manifest writer at `<invocation>/invocation.json`; official reporters receive
`<invocation>/vendor/` as `outputFolder`, so cleanup preserves lifecycle evidence.
Archive `invocationFolder` to retain both metadata and vendor reports.
Playwright native JSON/JUnit/HTML/attachments and legacy stats wiring stay intact.
Vitest may exit 130 before its end hook: an exit observer completes the sidecar
without intercepting signals or changing exits. Hard kill cannot finalize a
manifest; a missing end time is incomplete evidence. **Cutover blocker retained:**
Playwright reporter 2.0.3 drops interrupted attempts while native JSON and completed
sidecar record interruption/exit 130. Vitest SIGINT can leave no vendor report at
all; completed sidecar records interruption. Neither vendor report is rewritten.

### Local commands and evidence

Use Node **22.23.1**, npm **10.9.8**, installed repository dependencies; no account
or credentials required for local reports:

```sh
npm run test:reporting
npm test -- --run
npm run test:cov
(cd packages/sdk && npx --no-install vitest run --config vitest.config.ts)
npx --no-install vitest run --config vitest.config.ts
(cd my-sonicjs-app && npm test)
(cd packages/create-app && node test-cli.js)
(cd packages/create-app && npm test)
```

Task4 evidence: `/Users/lane/.hermes/cache/scratch/sonicjs-flakiness-evidence/task4`.
`red-wiring.log` records failing contracts before wiring; `green-wiring.log` records
GREEN. Real subprocess tests cover pass, final fail, retry recovery, skip, import,
setup, duplicates, invalid output, SIGINT and watch. Children receive a credential
allowlist environment (no vendor/stats secrets), CI disables upload, and outbound
fetch/HTTP/HTTPS/socket calls are denied. Contract discovery is independent and
reports itself without recursively discovering subprocess fixtures.

`reporting-final.log` records **73 passed contracts**, six files, exit 0.
`npm run type-check` and targeted integration/config TypeScript checks exit 0.
`verification-summary.log` and saved `*-list.stdout.json` compare identity
multiplicities against immutable baseline: core **2,068**, SDK **68**, root **0**,
all unchanged, list exit 0. Actual core and coverage runs exit 0: **2,068 passed,
247 skipped**, 148 passed files / 6 skipped files. SDK exits 0: **68 passed**, six
files. Root actual run exits **1**, zero tests; this is not a passing suite. Sample
exits **1**, one failed contact-form collection, zero executed tests; official
report includes the real import error. CLI original and wrapper both exit **1**
with the missing dependency described above. Coverage/Codecov wiring is unchanged.

### Staged operation and future cutover gates

Reports remain local by default. Inspect `report.json`, `attachments/` and sibling
manifest; official report output prints its viewing command (`npx flakiness show
<folder>` requires the separately available Flakiness viewer; no viewer dependency
or install is added here). Existing native viewing still works with
`npx playwright show-report playwright-report` and `npx playwright show-trace
<path/to/trace.zip>`; coverage HTML remains in the runner's coverage directory.

Direct local upload requires **all three** externally provisioned values:
`SONICJS_TEST_UPLOAD=1`, `FLAKINESS_ACCESS_TOKEN`, `FLAKINESS_PROJECT`. Supply through
local environment only. Account/project/token provisioning is external setup and
is not performed or authorized here. CI always sets reporter `disableUpload`,
including credential-bearing/OIDC contexts; no OIDC integration is enabled.
There is no publishing workflow, standalone uploader, or live Flakiness progress
integration. No legacy history import occurred. Existing dashboard, stats-live
reporter, API credentials and reporting scripts remain active and unchanged.

Reports can contain source, assertion output, traces and test data. Hosted privacy,
access and retention approval is pending; local token opt-in does not certify
hosted approval. Historical dashboard plans remain applicable until cutover; this
section is only a future supersession link. Separate roll-forward publishing and
retirement PRs require real hosted service evidence, resolved interruption and
collection blockers, successful CLI verification, and user decisions on hosted
privacy/retention, history, progress and dashboard retirement. No deletion,
account setup, upload, deployment or workflow service configuration belongs to
this additive phase.
