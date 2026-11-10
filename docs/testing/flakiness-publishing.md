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
jobs are recorded as not run. After complete trusted provenance validation, an
attempt with no executed suites succeeds explicitly with "nothing to publish;
suites not run", without requiring artifacts, a CLI runtime or upload auth. This
never bypasses cancelled, stale-head or unauthorized producer rejection. A failure after upload starts does not prevent the
remaining validated invocations from being attempted. Publishing cannot change
the producer's test conclusions.

The authorization job's name records run ID, attempt, event, PR number, original
head repository and tested SHA. This is immutable GitHub job metadata from a job
that executes a fixed echo, with no checkout or dependencies. The consumer reads
exact-attempt run/jobs API metadata, including every page, checks the workflow
ID/path and repository, and compares a live PR against this historical identity.
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
`<64 lowercase hex>.json` records; it excludes directories, symlinks, hardlinks,
unknown files and temporary writes. The whole filtered export is published
atomically so an interrupted export cannot expose a checkpoint without all
records. Only that export is archived, including when the uploader is killed
before cleanup. Credential scratch is never archived. Upload-only reruns restore the previous consumer attempt's
ledger and require its completed checkpoint. Missing/expired history or an abrupt
termination without a checkpoint blocks reruns. Started, ambiguous, accepted and
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

Local verification:

```sh
npm run test:reporting
npm run type-check
actionlint .github/workflows/pr-tests.yml .github/workflows/flakiness-upload.yml
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
No discovery/skips or producer uploads were changed for this separation.
