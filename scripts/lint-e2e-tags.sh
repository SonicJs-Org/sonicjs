#!/usr/bin/env bash
# Reject E2E tests that carry no feature tag.
#
# This used to be a coverage gate: CI ran `--grep "@smoke|@<tag>"` for the tags
# the changed paths mapped to, so a test carrying none of them was invisible to
# every PR — written, reviewed, merged, never executed. Two separate passes on
# this repo found 14 whole spec files and then 62 more tests in that state.
#
# CI now runs the whole suite unfiltered, so an untagged test does get executed
# and this is no longer a correctness gate. It stays as a consistency one: tags
# are how you run a subset locally (`--grep @media`) and how the suite stays
# navigable, and an untagged test silently opts out of both.
#
# Playwright greps the joined title path, so a tag anywhere in the chain counts
# — on the test, on its describe, or on an enclosing describe.
#
# The vocabulary is declared here. It used to be parsed out of the TAGS="..."
# lines in pr-tests.yml, which no longer exist — changed-area selection was
# removed when CI went to full runs. Adding a tag means adding it below AND to
# the list in CLAUDE.md.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Feature tags, plus @smoke for the critical path.
TAG_LIST=(
  @api
  @api-keys
  @auth
  @collections
  @content
  @database
  @forms
  @media
  @plugins
  @smoke
  @stats
)

TAGS=$(printf '%s\n' "${TAG_LIST[@]}" | sort -u | tr '\n' '|' | sed 's/|$//')

echo "Tag vocabulary: $TAGS"

# Playwright exits non-zero when a filter matches nothing, which here is the
# success case, so the status is deliberately discarded and the output parsed.
OUT=$(npx playwright test --config tests/playwright.config.ts --grep-invert "$TAGS" --list 2>&1 || true)

if echo "$OUT" | grep -qE '^Total: 0 tests|No tests found'; then
  echo -e "${GREEN}OK${NC}: every E2E test is selected by at least one CI tag."
  exit 0
fi

echo -e "${RED}UNTAGGED${NC}: these tests carry no feature tag."
echo "$OUT" | grep -E '^\s*\[' || true
echo "$OUT" | grep -E '^Total:' || true
echo
echo "Add a feature tag (and @smoke if it covers login/nav/a core flow) to the test"
echo "title or its describe. See the tag list in CLAUDE.md."
exit 1
