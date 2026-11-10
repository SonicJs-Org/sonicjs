# Flakiness Upload Runtime

Pinned independent CLI runtime for Flakiness upload orchestration (Tasks 5–6).

## Purpose

Install this runtime **outside the PR checkout** using `npm ci --ignore-scripts` before
providing credentials. This prevents untrusted PR dependencies from executing during the
credential-bearing upload step.

## Pinned packages

| Package | Version | Role |
|---------|---------|------|
| `flakiness` | 0.327.0 | Upload CLI |
| `@flakiness/sdk` | 3.6.0 | SDK used by CLI |
| `@flakiness/flakiness-report` | 0.36.0 | Report schema |
| `zod` | 4.6.7 | Schema runtime |
| `yauzl` | 3.4.0 | ZIP archive reading |

The `package-lock.json` pins all 44 transitive dependencies to exact registry-verified
versions. Parent verified all integrity hashes against official npm tarballs and all
engine constraints against Node 22.23.1.

## Install

```sh
npm ci --ignore-scripts --no-audit --no-fund
```

Run from this directory. Do **not** run with scripts enabled — the runtime must never
execute install lifecycle hooks from an untrusted dependency graph.

## Usage in upload-flakiness.mjs

The `executeUpload` function accepts a `config.runtimeDir` pointing to the installed
runtime. It resolves the CLI binary as:

```
{runtimeDir}/node_modules/.bin/flakiness
```

## Trusted helper copy

The main-only consumer copies this fixed allowlist into the runtime prefix so
Node resolves validator dependencies from the independent locked install:

- `validate-flakiness-artifacts.mjs`
- `read-flakiness-artifacts.py`
- `upload-flakiness.mjs`
- `fetch-producer-provenance.mjs`
- `run-flakiness-upload.mjs`
- `delivery-ledger.mjs`
- `export-flakiness-ledger.mjs`

No artifact code or PR hooks are copied or executed. See
[the publishing contract](../../../docs/testing/flakiness-publishing.md) for
identity, completeness and upload-only rerun policy.

## Prerequisites

- Node.js satisfying `^20.17.0 || >=22.9.0` (tested on 22.23.1)
- Python 3.9+ at `/usr/bin/python3` with POSIX `dir_fd`/`scandir`/`stat` capabilities
  (required by `read-flakiness-artifacts.py`; Linux `ubuntu-latest` satisfies this)
- Private writable `ledgerDir` outside any snapshot directory
- Explicit absolute caller-owned `privateScratchDir` (`CLI_SCRATCH_DIR` in CI),
  separate from the ledger even after resolving symlinks; no system temp fallback.
  Fresh mode-0700 CLI HOME/TMPDIR directories live here. Abrupt termination may
  leave credential caches here; never archive this root.
- Separate `LEDGER_EXPORT_DIR` for the always-run filtered exporter. It publishes
  only flat regular `checkpoint.json` and 64-lowercase-hex `.json` records, excluding
  symlinks, hardlinks, subdirectories and partial writes. Export staging stays in
  a private sibling directory until atomic publication; a failed export exposes
  no incomplete checkpoint. The workflow archives only this safe export.

## Linux vs macOS

The Python FD bridge has been exercised on macOS. Linux execution is pending published
CI (see `docs/testing/reporting-contracts-ci.md`). Do not claim Linux support until
the `Reporting Contracts` CI workflow passes on `ubuntu-latest`.

## Activation and auth contract

The workflow defaults off: `vars.FLAKINESS_UPLOAD_ENABLED == 'true'` is required.
Parent/user must separately approve privacy/project and hosted Task 7 gates before
setting that repository variable; merging code does not grant activation approval.
No repository variables are changed by local work.

Pinned CLI 0.327.0 / SDK 3.6.0 primary-source inspection and isolated SDK initialization
confirmed that only `ACTIONS_ID_TOKEN_REQUEST_URL` and
`ACTIONS_ID_TOKEN_REQUEST_TOKEN` are needed to initialize OIDC. Neither package
references `FLAKINESS_DISABLE_UPLOAD`; the upload child omits that producer opt-out.
No ambient `GITHUB_*` variables or additional permissions are passed to the CLI.
Offline fake-CLI contracts pin this allowlist, the real `upload` subcommand, fixed
endpoint and trusted configured project without installing this runtime in root tests.
This confirms initialization only: hosted exchange, real upload acceptance, receipt
format and dashboard read-back remain activation gates.
