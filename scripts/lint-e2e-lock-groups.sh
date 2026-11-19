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
# Reads the group grep patterns DIRECTLY from the e2e-locked job's
# `matrix.include` in pr-tests.yml (not a hand-maintained copy — a copy can
# silently drift from what CI actually runs, caught in PR #1207 review) and
# verifies, by actual test TITLE (not just count), that:
#   1. every group's selection is non-overlapping with every other group's, and
#   2. the union of all groups is exactly the full `@lock-` selection.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

WORKFLOW_FILE=".github/workflows/pr-tests.yml"

# Portable across bash 3.2 (macOS default, no mapfile/readarray) and the
# modern bash on ubuntu-latest CI runners.
GROUP_GREPS=()
while IFS= read -r line; do
  GROUP_GREPS+=("$line")
done < <(python3 - "$WORKFLOW_FILE" <<'PYEOF'
import re
import sys

text = open(sys.argv[1]).read()
m = re.search(r'\n  e2e-locked:\n(.*?)\n  [a-zA-Z_-]+:\n', text, re.S)
if not m:
    sys.exit("could not locate the e2e-locked job block in " + sys.argv[1])
block = m.group(1)
greps = re.findall(r"lock_grep:\s*'([^']*)'", block)
if not greps:
    sys.exit("found the e2e-locked job but no lock_grep entries in its matrix.include")
for g in greps:
    print(g)
PYEOF
)

if [ "${#GROUP_GREPS[@]}" -eq 0 ]; then
  echo -e "${RED}ERROR${NC}: could not extract any lock_grep patterns from $WORKFLOW_FILE's"
  echo "e2e-locked matrix.include — the job structure may have changed; update this"
  echo "script's extraction regex to match."
  exit 1
fi

# List test titles for a grep pattern using a reporter override so this never
# depends on TESTDINO_TOKEN/stats secrets being set (fork/Dependabot CI has
# neither) — avoids masking a genuine Playwright discovery failure behind a
# reporter-stage error unrelated to what this script checks.
list_titles() {
  local output
  if ! output=$(npx playwright test --config tests/playwright.config.ts --grep "$1" --list --reporter=list 2>&1); then
    echo -e "${RED}ERROR${NC}: Playwright test discovery failed for grep pattern '$1':" >&2
    echo "$output" >&2
    exit 1
  fi
  echo "$output" | grep -E '^\s*\[' | sed -E 's/^\s*\[[0-9]+\]\s*//'
}

ALL_TITLES=$(list_titles '@lock-' | sort)
if [ -z "$ALL_TITLES" ]; then
  echo -e "${RED}ERROR${NC}: the plain '@lock-' grep matched zero tests — either every"
  echo "@lock-* test was removed/retagged, or test discovery is broken. Either way this"
  echo "guard cannot verify a partition against an empty baseline; investigate before"
  echo "trusting this lint again."
  exit 1
fi

UNION_TITLES=""
OVERLAP_FOUND=0

for i in "${!GROUP_GREPS[@]}"; do
  grp_titles=$(list_titles "${GROUP_GREPS[$i]}" | sort)
  if [ -z "$grp_titles" ]; then
    echo -e "${RED}ERROR${NC}: group ${i} (${GROUP_GREPS[$i]}) matched zero tests — a typo'd"
    echo "or over-narrowed lock_grep pattern would silently never run any locked tests."
    exit 1
  fi
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
  echo "pr-tests.yml's e2e-locked job — see sonicjs-issue-fixing skill."
  exit 1
fi

MISSING=$(comm -23 <(echo "$ALL_TITLES") <(echo "$UNION_TITLES"))
if [ -n "$MISSING" ]; then
  echo -e "${RED}MISSING${NC}: these @lock-* tests are not selected by ANY e2e-locked"
  echo "matrix group — they would silently never run in CI:"
  echo "$MISSING"
  echo
  echo "Add the test's lock tag to one of the matrix.include lock_grep patterns in"
  echo "pr-tests.yml's e2e-locked job."
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
echo "(no overlap, no gap) — $(echo "$ALL_TITLES" | grep -c .) tests across ${#GROUP_GREPS[@]} groups."
