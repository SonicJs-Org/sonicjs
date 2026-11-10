# Flakiness publishing

`PR Tests` produces reports without Flakiness credentials or OIDC permissions.
Unit coverage runs alongside preview setup. Trusted CMS execution retains main's
four non-locked shards followed by serial locked tests; fork/Dependabot execution
retains the full local suite. Native reports, deployment ownership checks and
cleanup remain in place.

Each producing job uploads `flakiness-reports/`, preserving the suite directory
inside the archive. Artifact names include suite, job, shard where applicable,
producer run ID and attempt. The consumer merges these artifacts into one root
and validates the complete attempt before any upload. An executed suite/shard
with missing, invalid, interrupted or empty evidence fails publishing explicitly;
other evidence is not used to declare that attempt complete. Skipped producer
jobs are recorded as not run. After the pinned runtime and helper dependencies
are installed, complete trusted provenance validation allows an attempt with no
executed suites to succeed explicitly with "nothing to publish; suites not run",
without producer report artifacts, CLI invocation or OIDC upload authentication.
Setup or installation failures still fail the consumer job. This never bypasses
cancelled, stale-head or unauthorized producer rejection. A failure after upload
starts does not prevent the remaining validated invocations from being attempted. Publishing cannot change
the producer's test conclusions.

The separate `producer-identity` job's `authorize:...` name records run ID,
attempt, event, PR number, original head repository and tested SHA. This is immutable GitHub job metadata from a job
that executes a fixed echo, with no checkout or dependencies. The consumer reads
exact-attempt run/jobs API metadata, including every page, checks the workflow
ID/path and repository, and compares a live PR against this historical identity.
Run PR associations are dynamic branch matches, not historical snapshots. Only
entries matching the recorded original PR number are checked for SHA/repository
consistency; unrelated PRs, including PRs to other base branches, are ignored.
This supports fork runs with empty `pull_requests` arrays. Live PR data never
supplies missing history. Missing authorization metadata, changed repositories,
stale heads, cancelled runs and incomplete rerun metadata fail closed. Older
producer runs without this authorization metadata cannot be published by this
consumer. "Re-run failed jobs" is unsupported: reused authorization identity and
artifacts retain the old attempt. Require a full new producer attempt after
activation, with every job and authorization identity recreated.

`Flakiness Upload` checks out only main with persisted credentials disabled. It
installs the independent locked runtime with lifecycle scripts disabled and
copies a fixed helper allowlist into that prefix. It does not install root/PR
dependencies or execute report hooks. Only this consumer job has `actions: read`
and `id-token: write`. `vars.FLAKINESS_UPLOAD_ENABLED == 'true'` is an additional fail-closed job gate;
missing, false or other values leave the consumer disabled. Parent/user must
separately approve privacy/project and the Task 7 rollout gates before setting
this variable. Merging this additive PR does not authorize activation or complete
the migration. No repository variable changes are part of this implementation.
`FLAKINESS_PROJECT` must be a configured repository
variable naming the approved project. The endpoint is fixed to
`https://flakiness.io`; artifacts cannot select either destination. CLI execution
uses absolute paths, a private working directory, a fresh HOME and an explicit
environment allowlist. Untrusted schema/path/attachment inputs are validated and
copied into immutable private snapshots before credentials reach the CLI.
The CLI uses only explicit access-token auth or the two GitHub OIDC request
variables; it receives no ambient `GITHUB_*` context or producer upload opt-out.
Pinned CLI 0.327.0 / SDK 3.6.0 source and isolated SDK initialization confirm this
initialization contract, not hosted authentication or acceptance.

Delivery state is written before each child starts and retained as a seven-day
consumer artifact. Credential-bearing HOME/TMPDIR caches use an explicit private
caller-owned root outside the ledger, with no OS-temp fallback. Cleanup after
normal execution is best effort for credential retention, never an artifact
boundary. An always-run exporter stages only flat regular `checkpoint.json` and
`<64 lowercase hex>.json` records. Recognized names that are directories, symlinks,
hardlinks or unreadable cause the entire export to fail; unknown names and
temporary writes are excluded. The whole filtered export is published
atomically so an interrupted export cannot expose a checkpoint without all
records. Only that export is archived, including when the uploader is killed
before cleanup. Credential scratch is never archived. Upload-only reruns restore the previous consumer attempt's
ledger and require a successful restore action plus its completed version-2
checkpoint. The seal contains the exact sorted set of recognized record names
and each file's SHA256 of bytes. Before unsealing, the helper verifies the exact
set and digests, rejecting missing, extra, changed, linked or nonregular records.
The exporter also verifies the staged inventory against any seal, so a partial
export cannot publish a usable seal. Version 1 is rejected: the consumer has never
been activated and no production legacy ledger exists. Missing/expired history
or an abrupt termination without a checkpoint blocks reruns. Started, ambiguous, accepted and
nonzero-exit deliveries are never automatically resubmitted: a CLI failure can
occur after remote acceptance. Content changes under an existing identity also
block delivery. A rerun can safely retry an ordinary preflight failure that
produced a checkpoint without submitting anything. An OS spawn error before any
child starts is recorded as `not-started`, fails that consumer attempt and may be
retried with identical content from a restored completed checkpoint after fixing
the runtime. Errors after spawn remain ambiguous; nonzero exits remain blocked. Do not delete ledger entries
to force a retry; reconcile against the service first. Concurrency serializes
consumers for each producer run/attempt. This is not a claim of server-side
idempotency.

Consumer reruns use the original run's workflow YAML but check out the current
`main` helpers. This intentionally permits fixing the runtime and recovering a
sealed preflight or `not-started` delivery without re-executing producer tests.
Helper changes must keep the existing workflow environment contract backward
compatible. Incompatible environment/contract changes require a full new producer
attempt and a new consumer run with matching YAML; do not rerun an old consumer
with incompatible helpers or pin an unreviewed helper SHA to force recovery.

CLI receipt URLs are reported as `accepted-unverified`; ambiguous/failed/blocked
results fail the publishing job. Task 7 still requires hosted OIDC delivery,
independent dashboard read-back, counts/attachments checks and privacy/project
approval. No hosted delivery was exercised during local implementation.

Rollout requires this consumer and the revised producer authorization metadata on
main before a new producer run. `pull_request_target` uses the base workflow;
arbitrary feature-branch pushes remain disabled. Do not grant OIDC or Flakiness
authentication to test jobs to work around staged rollout. Full deployment/E2E
acceptance remains a separate hosted check. Existing legacy stats reporting stays
for the bounded comparison period; its removal is a later cutover task.

Classic main protection requires GitHub Actions checks named `authorize` and
`test` (app 15368). Keep the authorization job key and check name fixed. After its
approval, the separate secret-free `producer-identity` job emits the immutable
name before unit tests and preview setup run in parallel. Its only step is a
fixed echo; it has no checkout, permissions, OIDC, secrets or approval environment.
The existing adapter continues matching the `authorize:` prefix on this metadata
job, without a live-head fallback.

The fixed `test` aggregate in `pr-tests.yml` uses only scheduler `needs` results.
It requires authorization, producer identity and unit success plus exactly one
complete path: remote setup, shards, locked tests and cleanup all successful with
local skipped; or local successful with the entire remote path skipped. Missing,
failed, cancelled and all-skipped paths fail. It runs fixed inline code with
`permissions: {}` and no checkout or PR-controlled outputs. No protection settings
or status synthesis are involved. Only the four new vendor artifact upload steps
are best effort; native coverage, E2E, type checks and legacy uploads retain their
existing failure behaviour. Missing vendor evidence still fails the consumer.

Because `pull_request_target` uses base YAML, that aggregate cannot run from this
head until main contains it. `flakiness-head-validation.yml` therefore triggers
only on pushes to `ci/flakiness-publishing`, with job/check name `test`. This
narrow rollout path executes actual exact-head locked install, type checks, E2E
skip/tag lint, core coverage, reporting contracts, core build, matching Chromium
and OS dependency install, local D1 migrations and the full CMS suite under the
existing Playwright-owned wrangler server. It uses the same local E2E commands,
150/140-minute job/step limits and existing workers/retries configuration. State
is owned by runner temp plus run ID and attempt; remote `BASE_URL` and server
reuse are disabled. SHA-pinned actions, read-only contents, no credential
persistence, caches, stored-secret references, OIDC, deployment or upload service
are used. Native/vendor evidence is always archived under `head-validation-*`,
which cannot match the consumer's `flakiness-*` pattern. Full suite exit codes
gate this check; it is not an alias for reporting-only contracts. Parent CI must
still verify genuine exact-head local and existing remote PR Tests results.

Local verification:

```sh
npm run test:reporting
npm run type-check
actionlint .github/workflows/pr-tests.yml .github/workflows/flakiness-upload.yml \
  .github/workflows/reporting-contracts.yml .github/workflows/flakiness-head-validation.yml
```

Reporting contracts use fake GitHub API fixtures and fake CLI execution without
live credentials, plus actual pinned native Vitest/Playwright reports and
attachments. They cover both suites, four-shard completeness, stale/fork identity,
partial evidence, independent upload failure, relative runtime execution and
persisted-ledger recovery. They do not prove the hosted service accepts reports.

Completeness is mandatory Task 5/6 security policy, not best-effort migration.
Missing, malformed, mismatched, duplicate or interrupted executed evidence
withholds the entire batch with a visible publishing failure. Native producer
artifacts remain intact; the consumer never silently rewrites native results or
claims partial evidence is success. Coverage-threshold/post-script failures and
Playwright globalTeardown failures can disagree with reporter outcomes and thus
withhold otherwise useful evidence. Multiple invocations for one job/suite are
unsupported. Fixed limits apply across the whole attempt of up to six invocations:
128 MiB and 2048 files total (also 16 MiB per report, 32 MiB per file). Failed runs
with large traces/screenshots may exceed these budgets. No budget increase or
partial-publish policy is approved here. Representative hosted sizes and failed-run
count/attachment parity must be checked while the activation switch remains off;
these are Task 7 gates, not claims that full migration is complete.

PR code can falsify evidence, including evidence attributed to another producing
job in the merged artifact tree. There is no per-job cryptographic honesty proof.
Strict content/provenance checks prevent privilege escalation and unauthorized
destinations; they cannot make untrusted report content honest.

Production `test:cov` delegates to the core workspace, whose Vitest include is
`src/**/*.{test,spec}.{js,ts}`. It does not discover root reporting contracts.
Reporting fixture scratch nevertheless uses an explicit evidence root, TMPDIR,
RUNNER_TEMP or test-owned `.cache/reporting-contracts`, outside `flakiness-reports/`.
The selected parent is created then resolved with `realpath` before allocating a
fixture, preserving this precedence while avoiding macOS `/var` symlink ancestry.
No discovery/skips or producer uploads were changed for this separation.
