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
jobs are recorded as not run. A failure after upload starts does not prevent the
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
consumer; rerun all producer jobs after rollout.

`Flakiness Upload` checks out only main with persisted credentials disabled. It
installs the independent locked runtime with lifecycle scripts disabled and
copies a fixed helper allowlist into that prefix. It does not install root/PR
dependencies or execute report hooks. Only this consumer job has `actions: read`
and `id-token: write`. `FLAKINESS_PROJECT` must be a configured repository
variable naming the approved project. The endpoint is fixed to
`https://flakiness.io`; artifacts cannot select either destination. CLI execution
uses absolute paths, a private working directory, a fresh HOME and an explicit
environment allowlist. Untrusted schema/path/attachment inputs are validated and
copied into immutable private snapshots before credentials reach the CLI.

Delivery state is written before each child starts and retained as a seven-day
consumer artifact. Upload-only reruns restore the previous consumer attempt's
ledger and require its completed checkpoint. Missing/expired history or an abrupt
termination without a checkpoint blocks reruns. Started, ambiguous, accepted and
nonzero-exit deliveries are never automatically resubmitted: a CLI failure can
occur after remote acceptance. Content changes under an existing identity also
block delivery. A rerun can safely retry an ordinary preflight failure that
produced a checkpoint without submitting anything. Do not delete ledger entries
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
