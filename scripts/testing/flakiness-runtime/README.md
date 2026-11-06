# Flakiness Upload Runtime

Pinned independent CLI runtime for Flakiness upload orchestration (Task 5).

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
| `zod` | 4.4.3 | Schema runtime |
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

## Helper module copy

Before executing uploads, the operator must copy the reviewed helper modules into the
runtime prefix so they resolve as normal Node modules:

Allowed copy list:
- `scripts/testing/validate-flakiness-artifacts.mjs`
- `scripts/testing/validate-flakiness-artifacts.d.mts`
- `scripts/testing/read-flakiness-artifacts.py`

No other source files should be copied. These modules have been independently reviewed
and do not execute code from artifact input.

## Prerequisites

- Node.js satisfying `^20.17.0 || >=22.9.0` (tested on 22.23.1)
- Python 3.9+ at `/usr/bin/python3` with POSIX `dir_fd`/`scandir`/`stat` capabilities
  (required by `read-flakiness-artifacts.py`; Linux `ubuntu-latest` satisfies this)
- Private writable `ledgerDir` outside any snapshot directory

## Linux vs macOS

The Python FD bridge has been exercised on macOS. Linux execution is pending published
CI (see `docs/testing/reporting-contracts-ci.md`). Do not claim Linux support until
the `Reporting Contracts` CI workflow passes on `ubuntu-latest`.
