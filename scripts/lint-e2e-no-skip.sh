#!/usr/bin/env bash
# Reject skipped E2E tests — only runtime feature-detection guards are allowed.
# Usage: scripts/lint-e2e-no-skip.sh [files...]
# With no args, scans all tests/e2e/*.spec.ts and tests/www/*.spec.ts files.

set -euo pipefail

RED='\033[0;31m'
NC='\033[0m'

files=("$@")
if [ ${#files[@]} -eq 0 ]; then
  files=(tests/e2e/*.spec.ts tests/www/*.spec.ts)
fi

violations=0

# Match a pattern in real code: drop line-comment and block-comment lines so that a doc comment
# *describing* a banned pattern is not itself a violation. Keeps grep's line numbers.
scan() {
  grep -nE "$2" "$1" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*(//|\*|/\*)'
}

for f in "${files[@]}"; do
  [ -f "$f" ] || continue

  # describe.skip — always banned
  if scan "$f" 'describe\.skip\('; then
    echo -e "${RED}BANNED${NC}: describe.skip in $f"
    violations=$((violations + 1))
  fi

  # test.skip('name' — writing a test just to skip it
  if scan "$f" "test\.skip\('"; then
    echo -e "${RED}BANNED${NC}: test.skip('name') in $f"
    violations=$((violations + 1))
  fi

  # test.skip(true, 'reason') — an unconditional skip wearing a feature guard's clothes. This is
  # how a product failure gets reported as an absent feature: the test discovers it cannot do its
  # setup, calls test.skip(true, 'Could not create test content'), and the run stays green.
  if scan "$f" 'test\.skip\([[:space:]]*true'; then
    echo -e "${RED}BANNED${NC}: test.skip(true, …) in $f — assert instead, or delete the test"
    violations=$((violations + 1))
  fi

  # Bare test.skip(), wherever it sits on the line. The previous rule anchored to the start of the
  # line, so `if (!collectionHref) test.skip()` — the same unconditional bail with a condition in
  # front of it — was never checked. The one legal form is the documented runtime guard, which
  # names featureAvailable.
  if scan "$f" 'test\.skip\(\)' | grep -vE 'featureAvailable'; then
    echo -e "${RED}BANNED${NC}: bare test.skip() in $f — only a featureAvailable guard may skip"
    violations=$((violations + 1))
  fi

  # test.fixme — known broken = should be fixed or deleted
  if grep -nE 'test\.fixme\(' "$f" 2>/dev/null; then
    echo -e "${RED}BANNED${NC}: test.fixme in $f"
    violations=$((violations + 1))
  fi

  # test.todo — placeholder = should not exist
  if grep -nE 'test\.todo\(' "$f" 2>/dev/null; then
    echo -e "${RED}BANNED${NC}: test.todo in $f"
    violations=$((violations + 1))
  fi
done

if [ "$violations" -gt 0 ]; then
  echo ""
  echo -e "${RED}Found $violations file(s) with banned skip patterns.${NC}"
  echo "Rules: https://github.com/SonicJs-Org/sonicjs/blob/main/CLAUDE.md#no-skipped-tests-non-negotiable"
  exit 1
fi

echo "✓ No banned skip patterns found."
