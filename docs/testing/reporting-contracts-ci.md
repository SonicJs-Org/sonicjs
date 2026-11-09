# Reporting Contracts CI (`reporting-contracts.yml`)

## Purpose

The `Reporting Contracts` workflow runs the `test:reporting` suite on
`ubuntu-latest` to verify that the Python FD bridge (`read-flakiness-artifacts.py`)
works on Linux. Prior to this workflow, the bridge was only exercised on macOS.

Actual Linux execution is confirmed once a run of this workflow completes
successfully on GitHub-hosted `ubuntu-latest` with `ubuntu-latest`'s system
Python 3. Until then, Linux support is **pending published CI**.

## Scope

This is a **read-only, credential-free** diagnostic workflow:

- No Flakiness service uploads (`FLAKINESS_DISABLE_UPLOAD=1`)
- No Cloudflare, Codecov, npm-publish, or GitHub id-token secrets
- No app servers, deployments, or write operations
- Global permissions: `contents: read` only
- Triggers: `pull_request` (main/v3) and `push` (main/v3/ci/flakiness-artifact-validation)

## What it verifies

1. `/usr/bin/python3 ≥ 3.9` with POSIX `dir_fd`, `scandir`, `stat` FD capabilities
2. Fresh `npm ci` install completes
3. All 300+ reporting contracts pass (including artifact validation and upload orchestration)
4. Native flakiness reports from the `reporting-contracts` suite are preserved as
   CI artifacts (7-day retention; run-attempt-unique name)

## Relationship to Task 6 (producer registration)

This workflow is **not** a registered Flakiness producer. It does not upload any
reports to the hosted service. The current trusted producer allowlist in
`validate-flakiness-artifacts.mjs` remains:
- Workflow: `PR Tests` (ID 207092903, `.github/workflows/pr-tests.yml`)
- Suites: `core-unit` and `cms-e2e`

Task 6 must explicitly register any additional producers (including this workflow's
parent runs, if desired) and exclude controlled fixture reports before hosted rollout.
Publishing from an unregistered producer without this gate would bypass the
provenance trust boundary.

## YAML contract tests

`tests/reporting/reporting-ci.test.ts` asserts the workflow's security properties
using the `yaml` package. Tests cover triggers (no `pull_request_target`,
`workflow_run`, `schedule`), permissions (no `id-token`, no write-all), job
structure (no secrets/services/cached), env vars, pinned action SHAs,
`persist-credentials: false`, and credential isolation. Mutation guards verify
that weakening permissions or adding secrets would be detected.
