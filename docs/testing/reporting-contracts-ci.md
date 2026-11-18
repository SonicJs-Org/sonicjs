# Reporting Contracts CI (`reporting-contracts.yml`)

## Purpose

Runs the `test:reporting` suite (reporter options, metadata, Vitest/Playwright wiring,
workflow security contracts) on `ubuntu-latest` for every PR and push to main/v3.

## Scope

Read-only, credential-free:

- No Flakiness uploads (`FLAKINESS_DISABLE_UPLOAD=1`, `SONICJS_TEST_UPLOAD=0`)
- No Cloudflare, Codecov, npm-publish or `id-token` secrets
- Global permissions: `contents: read` only
- Triggers: `pull_request` and `push` (main, v3); never `pull_request_target`

Fixture reports from the `reporting-contracts` suite are kept as a 7-day CI artifact only.
They are not part of any `PR Tests` artifact and are never uploaded to flakiness.io.

## Live delivery flow (lives in `pr-tests.yml`)

`PR Tests` jobs archive native reports → trusted `flakiness-upload` job → flakiness.io
(main only, forks included; the Flakiness.io PR check is a required merge check).
See "Hosted upload" in `docs/testing/flakiness-coverage.md`.

## YAML contract tests

`tests/reporting/reporting-ci.test.ts` asserts this workflow's security properties:
triggers, permissions (no `id-token`, no write-all), job structure (no secrets/services/cache),
env vars, pinned action SHAs, `persist-credentials: false`, and credential isolation.
Mutation guards verify that weakening permissions or adding secrets is detected.
