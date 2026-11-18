#!/usr/bin/env node
/**
 * Seed local D1 with fake Playwright run data for development.
 * Run: node packages/stats/scripts/seed-playwright.mjs
 */

const API_KEY = process.env.PLAYWRIGHT_STATS_API_KEY || 'dev-test-key'
const BASE_URL = process.env.PLAYWRIGHT_STATS_URL || 'http://localhost:8787'

const BRANCHES = ['main', 'feat/auth', 'fix/api-cors', 'feat/media-upload', 'chore/deps']
const TEST_FILES = [
  'tests/api/posts.spec.ts',
  'tests/api/auth.spec.ts',
  'tests/api/media.spec.ts',
  'tests/admin/login.spec.ts',
  'tests/admin/collections.spec.ts',
  'tests/e2e/content-editing.spec.ts',
]
const TESTS = [
  'should create a new post',
  'should update an existing post',
  'should delete a post',
  'should return 401 for unauthenticated requests',
  'should login with valid credentials',
  'should upload a file',
  'should list all collections',
  'should handle pagination',
  'should filter by status',
  'should create a new user',
  'should handle concurrent edits',
  'should validate required fields',
]

function randomChoice(arr) { return arr[Math.floor(Math.random() * arr.length)] }
function randomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min }

async function seedRun(daysAgo) {
  const date = new Date(Date.now() - daysAgo * 86400000)
  const runId = `seed-${date.toISOString().slice(0,10)}-${randomInt(1, 999)}`
  const branch = randomChoice(BRANCHES)

  const tests = []
  const numTests = randomInt(8, TESTS.length)
  for (let i = 0; i < numTests; i++) {
    const status = Math.random() < 0.85 ? 'passed' : Math.random() < 0.7 ? 'failed' : 'skipped'
    const testEntry = {
      test_id: `test-${i}`,
      test_title: TESTS[i % TESTS.length],
      test_file: randomChoice(TEST_FILES),
      project_name: 'chromium',
      status,
      duration_ms: randomInt(500, 15000),
      retry: 0,
      is_flaky: false,
      error_message: status === 'failed' ? `Expected 200 but received ${randomChoice([401, 403, 500, 502])}` : undefined,
    }
    tests.push(testEntry)

    // Simulate retries + flaky
    if (status === 'failed' && Math.random() < 0.4) {
      tests.push({
        ...testEntry,
        status: 'passed',
        retry: 1,
        is_flaky: true,
        duration_ms: randomInt(500, 15000),
        error_message: undefined,
      })
    }
  }

  const payload = {
    run: {
      run_id: runId,
      project: 'sonicjs',
      branch,
      commit_sha: Math.random().toString(16).slice(2, 9),
      commit_message: `${randomChoice(['fix', 'feat', 'chore', 'test'])}: ${randomChoice(['update deps', 'fix auth bug', 'add media endpoint', 'refactor API', 'improve tests'])}`,
      ci_provider: 'github_actions',
      ci_run_url: `https://github.com/SonicJs-Org/sonicjs/actions/runs/${randomInt(10000, 99999)}`,
      triggered_by: randomChoice(['push', 'pull_request']),
      started_at: date.toISOString(),
      finished_at: new Date(date.getTime() + randomInt(120000, 600000)).toISOString(),
      duration_ms: randomInt(120000, 600000),
    },
    tests,
  }

  const resp = await fetch(`${BASE_URL}/v1/playwright-runs`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  })

  const result = await resp.json()
  console.log(`  ${resp.status === 201 ? '✅' : '❌'} ${runId} (${branch}) — ${result.summary?.passed ?? '?'}/${result.summary?.total ?? '?'} passed`)
}

async function main() {
  console.log(`🎭 Seeding Playwright runs to ${BASE_URL}...\n`)
  // Seed 30 days of runs (1-3 per day)
  for (let daysAgo = 30; daysAgo >= 0; daysAgo--) {
    const runsToday = randomInt(1, 3)
    for (let r = 0; r < runsToday; r++) {
      await seedRun(daysAgo)
    }
  }
  console.log('\n✅ Done! Visit /admin/playwright to see the dashboard.')
}

main().catch(console.error)
