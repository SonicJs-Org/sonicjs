#!/usr/bin/env npx tsx
/**
 * Seed Click Tracking Data
 *
 * Generates realistic search history + click tracking data spread over 30 days.
 * Performs real searches to get actual content IDs, then calls the admin
 * seeding endpoint to insert historical data.
 *
 * Usage:
 *   npx tsx tests/scripts/seed-click-tracking.ts [options]
 *
 * Options:
 *   --base-url <url>   Target URL (default: http://localhost:8787)
 *   --days <n>         Days of history to generate (default: 30)
 *   --count <n>        Number of searches to seed (default: 200)
 *   --clear            Clear existing data before seeding
 *   --email <email>    Admin email (default: admin@sonicjs.com)
 *   --password <pw>    Admin password (default: sonicjs!)
 */

// --------------- Config ---------------

const args = process.argv.slice(2)
function getArg(name: string, fallback: string): string {
  const idx = args.indexOf(`--${name}`)
  return idx >= 0 && args[idx + 1] ? args[idx + 1] : fallback
}
const hasFlag = (name: string) => args.includes(`--${name}`)

const BASE_URL = getArg('base-url', 'http://localhost:8787')
const DAYS = parseInt(getArg('days', '30'), 10)
const SEARCH_COUNT = parseInt(getArg('count', '200'), 10)
const CLEAR = hasFlag('clear')
const EMAIL = getArg('email', 'admin@sonicjs.com')
const PASSWORD = getArg('password', 'sonicjs!')

// Realistic search queries with varying popularity
const QUERY_POOL = [
  // High frequency
  { query: 'api', weight: 12 },
  { query: 'testing', weight: 10 },
  { query: 'design', weight: 9 },
  { query: 'documentation', weight: 8 },
  { query: 'security', weight: 8 },
  { query: 'performance', weight: 7 },
  // Medium frequency
  { query: 'authentication', weight: 5 },
  { query: 'database', weight: 5 },
  { query: 'deployment', weight: 4 },
  { query: 'microservices', weight: 4 },
  { query: 'gateway', weight: 3 },
  { query: 'caching', weight: 3 },
  { query: 'monitoring', weight: 3 },
  // Low frequency
  { query: 'graphql', weight: 2 },
  { query: 'websocket', weight: 2 },
  { query: 'serverless', weight: 2 },
  { query: 'docker', weight: 1 },
  { query: 'kubernetes', weight: 1 },
  // Zero-result queries (unlikely to match)
  { query: 'xyznonexistent', weight: 1 },
  { query: 'aaabbbccc', weight: 1 },
]

const MODES = ['fts5', 'fts5', 'fts5', 'keyword', 'ai'] // weighted toward fts5

// --------------- Helpers ---------------

function weightedRandom<T extends { weight: number }>(items: T[]): T {
  const total = items.reduce((sum, i) => sum + i.weight, 0)
  let r = Math.random() * total
  for (const item of items) {
    r -= item.weight
    if (r <= 0) return item
  }
  return items[items.length - 1]
}

function randomChoice<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]
}

// Click probability decreases with position (position bias)
function shouldClick(position: number): boolean {
  const probabilities = [0.35, 0.25, 0.18, 0.12, 0.08, 0.05, 0.03, 0.02, 0.01, 0.01]
  const p = probabilities[position - 1] || 0.005
  return Math.random() < p
}

// --------------- Auth ---------------

async function login(): Promise<string> {
  const res = await fetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  })

  const json = await res.json() as any

  if (!res.ok || !json.token) {
    throw new Error(`Login failed (${res.status}): ${json.error || 'No token'}`)
  }

  return `auth_token=${json.token}`
}

// --------------- Search ---------------

interface SearchResult {
  id: string
  title: string
  collection_name: string
}

async function performSearch(query: string, mode: string): Promise<{ results: SearchResult[]; total: number; search_id: string }> {
  const res = await fetch(`${BASE_URL}/api/search`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, mode, limit: 10 }),
  })

  if (!res.ok) return { results: [], total: 0, search_id: '' }

  const json = await res.json() as any
  return {
    results: (json.data?.results || []).map((r: any) => ({
      id: r.id,
      title: r.title || 'Untitled',
      collection_name: r.collection_name || '',
    })),
    total: json.data?.total || 0,
    search_id: json.data?.search_id || '',
  }
}

// --------------- Main ---------------

async function main() {
  console.log(`\n🔍 Seed Click Tracking`)
  console.log(`   Target:    ${BASE_URL}`)
  console.log(`   Searches:  ${SEARCH_COUNT}`)
  console.log(`   Days:      ${DAYS}`)
  console.log()

  // Step 1: Login
  console.log('🔐 Logging in...')
  const cookie = await login()
  console.log('   ✓ Authenticated')

  // Step 2: Optionally clear existing data
  if (CLEAR) {
    console.log('🗑️  Clearing existing data...')
    const res = await fetch(`${BASE_URL}/admin/plugins/ai-search/api/seed/clicks`, {
      method: 'DELETE',
      headers: { Cookie: cookie },
    })
    const json = await res.json() as any
    console.log(`   ✓ ${json.message || 'Cleared'}`)
  }

  // Step 3: Perform real searches to build content pool
  console.log('📡 Performing real searches to discover content...')
  const contentPool: SearchResult[] = []
  const searchQueries = new Set<string>()

  for (const q of QUERY_POOL) {
    if (q.query.startsWith('xyz') || q.query.startsWith('aaa')) continue
    const result = await performSearch(q.query, 'fts5')
    for (const r of result.results) {
      if (!contentPool.find(c => c.id === r.id)) {
        contentPool.push(r)
      }
    }
    searchQueries.add(q.query)
  }
  console.log(`   ✓ Found ${contentPool.length} unique content items from ${searchQueries.size} queries`)

  if (contentPool.length === 0) {
    console.error('❌ No content found — is the search index populated?')
    process.exit(1)
  }

  // Step 4: Generate synthetic search + click data
  console.log(`📊 Generating ${SEARCH_COUNT} searches with realistic click patterns...`)

  const searches: Array<{
    query: string
    mode: string
    results_count: number
    response_time_ms: number
    clicks: Array<{ content_id: string; content_title: string; position: number }>
  }> = []

  for (let i = 0; i < SEARCH_COUNT; i++) {
    const q = weightedRandom(QUERY_POOL)
    const mode = randomChoice(MODES)
    const isZeroResult = q.query.startsWith('xyz') || q.query.startsWith('aaa')
    const resultsCount = isZeroResult ? 0 : Math.floor(Math.random() * 50) + 1

    // Realistic response times by mode
    const baseTimes: Record<string, number> = { fts5: 60, keyword: 40, ai: 200, hybrid: 400 }
    const responseTime = Math.floor((baseTimes[mode] || 80) + Math.random() * 100)

    const clicks: Array<{ content_id: string; content_title: string; position: number }> = []

    if (!isZeroResult && contentPool.length > 0) {
      // Simulate user scanning results and clicking
      const numResults = Math.min(resultsCount, 10)
      for (let pos = 1; pos <= numResults; pos++) {
        if (shouldClick(pos)) {
          const content = randomChoice(contentPool)
          clicks.push({
            content_id: content.id,
            content_title: content.title,
            position: pos,
          })
        }
      }
    }

    searches.push({
      query: q.query,
      mode,
      results_count: resultsCount,
      response_time_ms: responseTime,
      clicks,
    })
  }

  const totalClicks = searches.reduce((sum, s) => sum + s.clicks.length, 0)
  const searchesWithClicks = searches.filter(s => s.clicks.length > 0).length
  const zeroResultSearches = searches.filter(s => s.results_count === 0).length

  console.log(`   ✓ Generated:`)
  console.log(`     - ${searches.length} searches (${zeroResultSearches} zero-result)`)
  console.log(`     - ${totalClicks} clicks (${searchesWithClicks} searches with clicks)`)
  console.log(`     - CTR: ${((searchesWithClicks / (searches.length - zeroResultSearches)) * 100).toFixed(1)}%`)

  // Step 5: Send to seeding endpoint (batch to avoid timeouts)
  console.log('💾 Inserting into database...')
  const BATCH_SIZE = 50

  let insertedSearches = 0
  let insertedClicks = 0

  for (let offset = 0; offset < searches.length; offset += BATCH_SIZE) {
    const batch = searches.slice(offset, offset + BATCH_SIZE)
    const res = await fetch(`${BASE_URL}/admin/plugins/ai-search/api/seed/clicks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({ searches: batch, days: DAYS }),
    })

    if (!res.ok) {
      const text = await res.text()
      console.error(`   ❌ Batch ${offset}-${offset + batch.length} failed: ${text.slice(0, 200)}`)
      continue
    }

    const json = await res.json() as any
    insertedSearches += json.data?.searches_inserted || 0
    insertedClicks += json.data?.clicks_inserted || 0
    process.stdout.write(`   ✓ Batch ${Math.floor(offset / BATCH_SIZE) + 1}/${Math.ceil(searches.length / BATCH_SIZE)} `)
    console.log(`(${insertedSearches} searches, ${insertedClicks} clicks)`)
  }

  console.log()
  console.log(`✅ Done! Seeded ${insertedSearches} searches and ${insertedClicks} clicks over ${DAYS} days`)
  console.log(`   View analytics at: ${BASE_URL}/admin/plugins/ai-search#analytics`)
}

main().catch(err => {
  console.error('❌ Fatal error:', err.message || err)
  process.exit(1)
})
