# E2E infrastructure audit — draft PR #1146

Status: **incomplete; not a reliability sign-off**. Initial implementation snapshot:
`b1563d988b0f1f6207ceea75f2e477f8fe91adfb`. Follow-up investigation is tracked on the
`sonicjs-prs` board. No merge/release or manual remote provisioning is authorized.

## Prioritized plan

1. Preserve failure integrity: reproduce swallowed navigation/response errors and fix
   exact synchronization, setup checks, ownership and unsafe lock behavior.
2. Resolve remaining first-attempt failures without retries or weakened persistence assertions.
3. Complete preview resource/build isolation and fork/secret/cache boundary verification.
4. Verify artifact paths, finish documentation and controlled fault-injection evidence.
5. Run qualifying full-suite repetitions at two workers, then CI policy and final reviews.

## Baseline and measurements

All historical CI figures below were read from actual Actions logs and downloaded HTML
reports. They are different revisions/environments, **not** a comparable before/after
performance experiment. The local run used macOS, Node 24.11.1, Playwright 1.63.0,
Wrangler 4.130.0 and an isolated local persist directory; CI specifies Node 22 and a
remote preview. The pre-existing local migration-bundle edit was preserved and used by
the local build, so this is also not a pristine-checkout comparison.

| Run | Workers / retries | Total outcomes | First-attempt failures | Retry recoveries | Final failures | Duration |
|---|---|---|---:|---:|---:|---:|
| CI 40743324775, Oct 28 | 2 / 3 | 754: 690 expected, 33 flaky, 31 skipped | 33 | 33 | 0 | report 3314.574s; E2E step 3316s; job 3561s |
| CI 40743342140, Oct 28 | 2 / 3 | 754: 668 expected, 52 flaky, 3 unexpected, 31 skipped | 55 | 52 | 3 | report 6357.972s; E2E step 6359s; job 6566s |
| CI 40743350563, Oct 28 | 2 / 3 | cancelled; no complete summary | unavailable | unavailable | unavailable | E2E step 8807s; job hit 150-minute cap |
| Initial local full suite, Oct 29 | 2 / 0 | 756: 746 passed, 2 failed, 8 skipped | 2 | 0 | 2 | report 496.61144s |

The two additional selected tests are runner-contract regressions. The local/remote
skip difference was not introduced by new skips: existing deployment-dependent guards
remain. No claim is made that those existing skips satisfy full deployed coverage.

Historical successful-run slowest specs by **summed reported test-body duration**, not
spec wall time: database-tools 258.329s, two-factor-admin-reset 171.995s,
authentication-api 170.382s, content-duplicate 167.346s, content 162.026s.
Historical authentication request steps: 764 / 910, summed duration 950.468s / 2205.970s
for the successful / failed runs. Those sums overlap other work and are not wall time.
A successful-run authentication before-hook reached 81.977s; a failed-run database-tools
before-hook reached 104.043s. Hook totals can overlap nested hooks and must not be summed.

Unavailable: historical lock queue time, CPU/worker utilization, attributable network versus
server latency, and a comparable pristine before/after local full-suite baseline.
New `lock-waits` attachments establish a measurement seam, but no aggregate utilization
or contention improvement has yet been demonstrated. No worker increase or sharding was made.

## Evidence-based findings and fixes

- **Navigation wrapper false success (reproduced):** an explicit `load` timeout resolved
  successfully under the old wrapper. The browser regression was red before the fix.
  Removed broad catches, worker-wide state downgrades and navigation/reload replay.
- **Response helper defects (reproduced):** substring matching accepted a neighboring
  endpoint and document readiness accepted HTTP 500. Unit tests were red, then green.
  Helpers now match exact method/origin/path, check success and await body completion.
- **JSON persistence synchronization (trace evidence):** CI's first retry showed a reload
  GET while the save PUT was unresolved, followed by old persisted version 1. The test
  now waits for the PUT and resulting success banner, then reopens and asserts version 2.
  Each test owns a unique record and cleans up by returned ID. The version assertion remains.
- **Duplicate-slug prerequisites:** fixed slug reused across runs and UI prerequisite
  creation returned an HTTP-200 error banner in the historical failing trace. Replaced
  the prerequisite with uniquely named API-created content and ID-scoped cleanup; duplicate
  status and native invalidity checks remain. This does not prove every historical failure
  was caused by a collision. A new exact-label locator was wrong and was corrected to
  the actual named title input; subsequent duplicate detection passed 3/3 at two workers.
- **Lock correctness:** old mtime-based reclamation could steal an active stalled lease;
  release could remove a replacement. Added owner tokens, deduplication, ordering and
  queue attachments. Locks no longer auto-steal. Orphans require confirmed runner shutdown
  before manual removal. They coordinate one host, not independent runners.
- **Setup/authentication integrity:** seed/session/migration failures previously logged
  and continued. Setup now fails early, uses an API context, avoids broad cleanup sweeps,
  and shares successful seeding with workers. Session checks and sign-in transport errors
  propagate instead of silently creating another session.
- **Local server ownership:** ordinary app dev chooses a hashed port, while the config
  expected 8787. The E2E server now has an explicit port/persist path. A later repetition
  reused a disappearing server and cascaded into connection refusals; server reuse is now
  explicit opt-in locally and prohibited in CI. Attribution of the disappearing process
  itself is unavailable; the isolated follow-up still reproduced the modal failure.
- **Artifact paths:** JSON/HTML reporter relative paths resolved under `tests/` during
  initial execution. Changed main reporter paths/outputDir to explicit repository-root
  paths. A follow-up verified actual `test-results/results.json`, `junit.xml` and
  `playwright-report/index.html` exist. Old generated directories are excluded from commits.

## Open regression: nested-array deletion confirmation

The original full run failed because `#delete-repeater-item-confirm` stayed open after
confirmation. Original test code repeatedly clicked Confirm inside `toPass`, potentially
replaying a side effect. Follow-up now waits for component definition/active animations,
clicks once and still requires the dialog to close and deletion to persist after save.

Evidence:
- Original affected-pair repetition: duplicate slug 3/3 passed; nested deletion 2/3 passed,
  1/3 failed, two workers and no retries; 25.8s total.
- Initial ten-repeat readiness probe: 10 failed, including connection refusals from the
  disappearing reused server. This run does **not** establish a ten-case modal failure rate.
- Fresh owned-server nested-only probe: 4 passed, 1 failed, five repeats, two workers,
  retries disabled; 15.6s. The modal stayed open even with readiness/animation handling.

The readiness hypothesis is insufficient. Product dialog lifecycle versus remaining test
synchronization is unresolved. Do not dismiss this as infrastructure or weaken the close,
item-count or persisted-deletion assertions. No product fix has been applied.

## Validation record and gaps

Commands were run from the repository root unless stated otherwise. Application runs used:
`E2E_DISPOSABLE_TARGET=1` and
`E2E_PERSIST_DIR=/Users/lane/.hermes/cache/scratch/sonicjs-e2e-validation/state`.

- `npx tsup` from `packages/core`: built successfully without regenerating the unrelated
  migration bundle. Local `wrangler d1 migrations apply DB --local --persist-to ...`: passed.
- `npm run type-check`: passed before draft publication.
- `npm test`: latest draft snapshot 2061 passed, 247 existing skips; 147 files passed,
  6 skipped. This includes seven infrastructure and three preview-wrapper unit tests.
- `bash scripts/lint-e2e-tags.sh` and `bash scripts/lint-e2e-no-skip.sh`: passed.
- `npx playwright test --config tests/playwright.infrastructure.config.ts --repeat-each=5 --workers=2 --retries=0`:
  10 passed, 3.6s; preceded by the explicit-load regression failing against the old wrapper.
- `npx playwright test --config tests/playwright.config.ts 83-json-field-viewer --repeat-each=3 --retries=0 --workers=2`:
  12 passed, 10.3s after fixing an ambiguous success-banner locator; persisted version checks remain.
- `npx playwright test --config tests/playwright.config.ts --retries=0 --workers=2`:
  746 passed, 2 failed, 8 skipped, 496.61144s; before final slug locator/report-path corrections.
- `npx playwright test --config tests/playwright.config.ts 39-slug-generation 57-nested-array-serialization-scope --grep 'detect duplicate slugs|persist nested child deletion' --repeat-each=3 --retries=0 --workers=2`:
  5 passed, 1 failed, 25.8s.
- `npx playwright test --config tests/playwright.config.ts 39-slug-generation --grep 'detect duplicate slugs' --retries=0 --workers=1`:
  passed alone, 3.9s with a fresh owned server; subsequent type/unit/tag/no-skip gates passed.
- `npx playwright test --config tests/playwright.config.ts 57-nested-array-serialization-scope --grep 'persist nested child deletion' --repeat-each=5 --retries=0 --workers=2`:
  4 passed, 1 failed, 15.6s with explicitly owned server.
- Preview-wrapper bundling: `npx wrangler deploy ../tests/e2e/preview-worker.ts --config wrangler.toml --dry-run --outdir ...`
  from `my-sonicjs-app` passed. The first dry run without explicit config failed; it did not deploy.
- Workflow YAML parsed and all 14 embedded Bash steps passed syntax checks; not equivalent
  to an Actions runtime or fork-security validation.

Not yet completed: passing isolated nested-delete reproduction, controlled broken-save
fault injection/removal, three consecutive clean full-suite runs at two workers, a passing
full CI-policy run, verified complete resource cleanup, and final independent review.

## CI rollout blocker and remaining isolation

Draft PR: https://github.com/SonicJs-Org/sonicjs/pull/1146.
Initial PR CI run `40936494888` failed after 3m4s **before test execution**:
the existing base-branch `pull_request_target` workflow does not provide
`E2E_DISPOSABLE_TARGET=1`. New head config correctly refused setup. CodeRabbit skipped
the draft. Do not weaken target consent or call skipped review completed.

Workflow edits on the PR head cannot fix the running base-branch workflow until a safe
rollout is separately authorized. Do not merge a failing PR to bypass the gate.
The current draft names Worker/D1 by run and attempt but still has shared R2/KV bindings.
The test-only preview wrapper has build-identity/keyed-storage-cleanup groundwork and
unit tests, **but is not integrated into provisioning or readiness**. Complete ownership
for every resource and partial-failure cleanup before claiming cross-job isolation.

See `tests/e2e/README.md` for execution, ownership, authentication, diagnostics and stale
lock procedures. Local logs/reports are retained under the scratch validation directory;
no generated reports, traces, `.dev.vars` or unrelated migration edits belong in commits.
