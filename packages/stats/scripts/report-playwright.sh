#!/usr/bin/env bash
#
# report-playwright.sh — Send Playwright JSON results to stats.sonicjs.com
#
# Required env vars:
#   PLAYWRIGHT_STATS_API_KEY  — Bearer token for authentication
#   PLAYWRIGHT_STATS_URL      — Base URL (default: https://stats.sonicjs.com)
#
# Optional env vars (auto-detected in GitHub Actions):
#   GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, GITHUB_REF_NAME, GITHUB_SHA,
#   GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_EVENT_NAME
#
# Usage:
#   PLAYWRIGHT_STATS_API_KEY=xxx bash scripts/report-playwright.sh [path/to/results.json]
#
set -euo pipefail

RESULTS_FILE="${1:-test-results/results.json}"
STATS_URL="${PLAYWRIGHT_STATS_URL:-https://stats.sonicjs.com}"
API_KEY="${PLAYWRIGHT_STATS_API_KEY:-}"

if [ -z "$API_KEY" ]; then
  echo "⚠️  PLAYWRIGHT_STATS_API_KEY not set — skipping stats upload"
  exit 0
fi

if [ ! -f "$RESULTS_FILE" ]; then
  echo "⚠️  Results file not found: $RESULTS_FILE — skipping stats upload"
  exit 0
fi

if ! command -v jq &>/dev/null; then
  echo "❌ jq is required but not installed"
  exit 1
fi

# Temp file for curl response; cleaned up on exit
RESP_FILE=$(mktemp)
trap 'rm -f "$RESP_FILE"' EXIT

# GitHub Actions metadata (auto-detected)
RUN_ID="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
BRANCH="${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')}"
COMMIT_SHA="${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo 'unknown')}"
COMMIT_MSG="$(git log -1 --format=%s 2>/dev/null | head -c 200 || echo '')"
CI_RUN_URL=""
if [ -n "${GITHUB_SERVER_URL:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ] && [ -n "${GITHUB_RUN_ID:-}" ]; then
  CI_RUN_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
fi
TRIGGERED_BY="${GITHUB_EVENT_NAME:-manual}"

# Parse the Playwright JSON output and build our payload.
#
# Playwright JSON structure:
#   suites[] (one per file) → suites[] (describe blocks, nested) → specs[] → tests[] → results[]
#
# We walk the nested suites tree, accumulate parent titles, and flatten every
# tests[].results[] entry into a row with a stable test_id (spec.id::projectName).
#
PAYLOAD=$(jq -c --arg run_id "$RUN_ID" \
  --arg project "sonicjs" \
  --arg branch "$BRANCH" \
  --arg commit_sha "$COMMIT_SHA" \
  --arg commit_message "$COMMIT_MSG" \
  --arg ci_run_url "$CI_RUN_URL" \
  --arg triggered_by "$TRIGGERED_BY" '
# Recursively walk nested suites, accumulating titles and inheriting file path.
# Emits one object per spec: {id, title, file, tests}
def flatten_specs(titles; file):
  ((.file // file) as $f |
    ((.specs // [])[] |
      {
        id: (.id // ""),
        title: (titles + [.title] | join(" > ")),
        file: $f,
        tests: (.tests // [])
      }
    ),
    ((.suites // [])[] | flatten_specs(titles + [.title]; $f))
  )
;

{
  run: {
    run_id: $run_id,
    project: $project,
    branch: $branch,
    commit_sha: $commit_sha,
    commit_message: $commit_message,
    ci_provider: "github_actions",
    ci_run_url: $ci_run_url,
    triggered_by: $triggered_by,
    started_at: (.stats.startTime // (now | todate)),
    finished_at: (now | todate),
    duration_ms: (.stats.duration // 0)
  },
  tests: [
    .suites[] | flatten_specs([]; .file) |
    . as $flat |
    $flat.tests[] |
    . as $test |
    .results | to_entries[] |
    {
      test_id: ($flat.id + "::" + ($test.projectName // "")),
      test_title: $flat.title,
      test_file: $flat.file,
      project_name: $test.projectName,
      status: .value.status,
      duration_ms: .value.duration,
      retry: .key,
      is_flaky: (
        if .key > 0 and .value.status == "passed" then true
        else false end
      ),
      error_message: (
        if .value.errors and (.value.errors | length) > 0
        then (.value.errors[0].message // "" | .[0:500])
        else null end
      ),
      error_snippet: (
        if .value.errors and (.value.errors | length) > 0
        then (.value.errors[0].snippet // "" | .[0:300])
        else null end
      )
    }
  ]
}' "$RESULTS_FILE" 2>/dev/null) || {
  echo "⚠️  Failed to parse Playwright results JSON — skipping stats upload"
  exit 0
}

echo "📊 Uploading Playwright results to $STATS_URL..."

# Pipe payload through stdin to avoid ARG_MAX limits on large suites.
# --max-time 30 prevents hanging. || HTTP_CODE=000 makes curl failures non-fatal.
HTTP_CODE=$(echo "$PAYLOAD" | curl -s -o "$RESP_FILE" -w "%{http_code}" \
  --max-time 30 \
  -X POST "$STATS_URL/v1/playwright-runs" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @- 2>/dev/null) || HTTP_CODE="000"

if [ "$HTTP_CODE" = "201" ]; then
  echo "✅ Results uploaded successfully"
  cat "$RESP_FILE"
else
  echo "⚠️  Upload failed with HTTP $HTTP_CODE (non-fatal)"
  cat "$RESP_FILE" 2>/dev/null || true
fi

# Never fail the CI pipeline because stats upload failed
exit 0
