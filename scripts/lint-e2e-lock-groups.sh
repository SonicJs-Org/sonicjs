#!/usr/bin/env bash
# Guard against the e2e-locked matrix groups drifting from the actual @lock-*
# tags used in tests/e2e/**/*.spec.ts.
#
# pr-tests.yml's e2e-locked job runs each matrix.include entry's `lock_grep`
# as its OWN parallel runner. If a future lock tag (or a test gaining a second
# lock tag) isn't reflected in one of these grep patterns, two things can
# happen silently: the test disappears from every locked job (never executed
# in CI), or — the actual bug caught in PR #1207's review — it gets selected
# by two DIFFERENT groups and runs concurrently on two runners against the
# same shared preview, racing on shared state that --workers 1 cannot protect
# across runners.
#
# This script is the single source of truth for the group grep patterns
# (pr-tests.yml's matrix.include must match GROUP_GREPS below exactly) and
# verifies, by actual test TITLE (not just count), that:
#   1. every group's selection is non-overlapping with every other group's, and
#   2. the union of all groups is exactly the full `@lock-` selection.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Keep in sync with the `matrix.include` list in .github/workflows/pr-tests.yml,
# job `e2e-locked`.
GROUP_GREPS=(
  '@lock-(auth-login|auth-registration|plugin-hello-world|rbac-example-grant)'
  '@lock-plugin-multi-tenant'
)

list_titles() {
  # The @testdino/playwright reporter throws when TESTDINO_TOKEN is unset (no
  # secret access on fork/Dependabot PRs). That happens AFTER --list already
  # printed every matching test, so capture combined output and never let a
  # reporter-stage failure abort this lint under set -e.
  npx playwright test --config tests/playwright.config.ts --grep "$1" --list 2>&1 \
    | grep -E '^\s*\[' | sed -E 's/^\s*\[[0-9]+\]\s*//' || true
}

ALL_TITLES=$(list_titles '@lock-' | sort)
UNION_TITLES=""
OVERLAP_FOUND=0

for i in "${!GROUP_GREPS[@]}"; do
  grp_titles=$(list_titles "${GROUP_GREPS[$i]}" | sort)
  if [ -n "$UNION_TITLES" ]; then
    overlap=$(comm -12 <(echo "$UNION_TITLES") <(echo "$grp_titles"))
    if [ -n "$overlap" ]; then
      echo -e "${RED}OVERLAP${NC}: group ${i} (${GROUP_GREPS[$i]}) selects tests already"
      echo "claimed by an earlier group — these would run twice, concurrently:"
      echo "$overlap"
      OVERLAP_FOUND=1
    fi
  fi
  UNION_TITLES=$(printf '%s\n%s\n' "$UNION_TITLES" "$grp_titles" | sort -u)
done

if [ "$OVERLAP_FOUND" -ne 0 ]; then
  echo
  echo "Merge the overlapping groups' grep patterns into one matrix entry in"
  echo "pr-tests.yml and in GROUP_GREPS above — see sonicjs-issue-fixing skill."
  exit 1
fi

MISSING=$(comm -23 <(echo "$ALL_TITLES") <(echo "$UNION_TITLES"))
if [ -n "$MISSING" ]; then
  echo -e "${RED}MISSING${NC}: these @lock-* tests are not selected by ANY e2e-locked"
  echo "matrix group — they would silently never run in CI:"
  echo "$MISSING"
  echo
  echo "Add the test's lock tag to one of the GROUP_GREPS patterns above and to"
  echo "the matching matrix.include entry in pr-tests.yml."
  exit 1
fi

EXTRA=$(comm -13 <(echo "$ALL_TITLES") <(echo "$UNION_TITLES"))
if [ -n "$EXTRA" ]; then
  echo -e "${RED}STALE${NC}: a group grep pattern selects tests that no longer carry"
  echo "any @lock-* tag (or were renamed) — likely a stale/overly broad pattern:"
  echo "$EXTRA"
  exit 1
fi

echo -e "${GREEN}OK${NC}: e2e-locked matrix groups exactly partition all @lock-* tests"
echo "(no overlap, no gap) — $(echo "$ALL_TITLES" | grep -c . ) tests across ${#GROUP_GREPS[@]} groups."
