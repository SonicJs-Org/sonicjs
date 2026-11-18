# Flakiness Upload Runtime

Pinned CLI runtime used by the `flakiness-upload` job in `.github/workflows/pr-tests.yml`.

## How it is used

The job checks out **only this directory** from the trusted base ref (never PR code) and installs it:

```sh
cd scripts/testing/flakiness-runtime
npm ci --ignore-scripts --no-audit --no-fund
```

`--ignore-scripts` ensures no install lifecycle hook from the dependency graph ever runs.
The job then downloads the `flakiness-*-<run_id>-<run_attempt>` artifacts (native reports at
`flakiness-reports/<suite>/<invocation>/vendor/report.json`) and uploads each with:

```sh
node_modules/.bin/flakiness upload --project SonicJs/sonicjs <report dir>
```

The project is hardcoded; artifact content never selects it. Reports from fork PRs are
untrusted data and are only read, never executed.

## Pinned packages

| Package | Version | Role |
|---------|---------|------|
| `flakiness` | 0.327.0 | Upload CLI |
| `@flakiness/sdk` | 3.6.0 | SDK used by CLI |
| `@flakiness/flakiness-report` | 0.36.0 | Report schema |
| `zod` | 4.4.3 | Schema runtime |
| `yauzl` | 3.4.0 | ZIP archive reading |

`package-lock.json` pins all transitive dependencies. Requires Node `^20.17.0 || >=22.9.0`.
Bump versions via Dependabot/PR; do not edit the lock by hand.
