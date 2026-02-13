#!/usr/bin/env npx tsx
/**
 * Seed Facet Click Data
 *
 * Generates realistic facet interaction data spread over 30 days.
 * Reads the current facet config to use actual enabled facet fields,
 * then inserts click records with weighted distributions.
 *
 * Usage:
 *   npx tsx tests/scripts/seed-facet-clicks.ts [options]
 *
 * Options:
 *   --base-url <url>   Target URL (default: http://localhost:8787)
 *   --days <n>         Days of history to generate (default: 30)
 *   --count <n>        Number of facet clicks to seed (default: 300)
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
const CLICK_COUNT = parseInt(getArg('count', '300'), 10)
const CLEAR = hasFlag('clear')
const EMAIL = getArg('email', 'admin@sonicjs.com')
const PASSWORD = getArg('password', 'sonicjs!')

// Fallback facet values if we can't discover real ones
const FALLBACK_FACET_DATA: Record<string, { values: string[]; weight: number }> = {
  'collection_name': {
    values: ['Blog Posts', 'Documentation', 'Tutorials', 'Case Studies', 'News'],
    weight: 25,
  },
  'status': {
    values: ['published', 'draft', 'archived'],
    weight: 10,
  },
  'author': {
    values: ['admin@sonicjs.com', 'editor@sonicjs.com', 'Unknown'],
    weight: 15,
  },
  '$.category': {
    values: ['API Design', 'Security', 'Performance', 'Testing', 'DevOps', 'Architecture'],
    weight: 20,
  },
  '$.tags': {
    values: ['api', 'rest', 'graphql', 'testing', 'security', 'tutorial', 'beginner', 'advanced', 'best-practices', 'tools'],
    weight: 30,
  },
}

// --------------- Helpers ---------------

function randomChoice<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]
}

function weightedRandom(items: Array<{ field: string; weight: number }>): string {
  const total = items.reduce((sum, i) => sum + i.weight, 0)
  let r = Math.random() * total
  for (const item of items) {
    r -= item.weight
    if (r <= 0) return item.field
  }
  return items[items.length - 1].field
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

// --------------- Discovery ---------------

interface FacetConfig {
  field: string
  name: string
  enabled: boolean
}

async function loadFacetConfig(cookie: string): Promise<FacetConfig[]> {
  const res = await fetch(`${BASE_URL}/admin/plugins/ai-search/api/facets/config`, {
    headers: { Cookie: cookie },
  })

  if (!res.ok) return []

  const json = await res.json() as any
  return (json.data?.config || []).filter((f: any) => f.enabled)
}

async function discoverFacetValues(cookie: string): Promise<Record<string, string[]>> {
  // Do a search with facets=true to get real facet values
  const res = await fetch(`${BASE_URL}/api/search`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: 'the', mode: 'fts5', limit: 1, facets: true }),
  })

  if (!res.ok) return {}

  const json = await res.json() as any
  const facets = json.data?.facets || []
  const discovered: Record<string, string[]> = {}

  for (const f of facets) {
    if (f.values && f.values.length > 0) {
      discovered[f.field] = f.values.map((v: any) => v.value)
    }
  }

  return discovered
}

// --------------- Main ---------------

async function main() {
  console.log(`\n🏷️  Seed Facet Click Data`)
  console.log(`   Target:    ${BASE_URL}`)
  console.log(`   Clicks:    ${CLICK_COUNT}`)
  console.log(`   Days:      ${DAYS}`)
  console.log()

  // Step 1: Login
  console.log('🔐 Logging in...')
  const cookie = await login()
  console.log('   ✓ Authenticated')

  // Step 2: Optionally clear existing data
  if (CLEAR) {
    console.log('🗑️  Clearing existing facet click data...')
    const res = await fetch(`${BASE_URL}/admin/plugins/ai-search/api/seed/facet-clicks`, {
      method: 'DELETE',
      headers: { Cookie: cookie },
    })
    const json = await res.json() as any
    console.log(`   ✓ ${json.message || 'Cleared'}`)
  }

  // Step 3: Load facet config and discover real values
  console.log('📡 Loading facet configuration...')
  const enabledFacets = await loadFacetConfig(cookie)
  console.log(`   ✓ ${enabledFacets.length} enabled facets`)

  console.log('🔍 Discovering real facet values from search...')
  const realValues = await discoverFacetValues(cookie)
  const discoveredFields = Object.keys(realValues)
  console.log(`   ✓ Found values for ${discoveredFields.length} facets: ${discoveredFields.join(', ')}`)

  // Build facet data: prefer real values, fall back to defaults
  const facetData: Record<string, { values: string[]; weight: number }> = {}

  for (const facet of enabledFacets) {
    const field = facet.field
    if (realValues[field] && realValues[field].length > 0) {
      // Use real values with default weight based on type
      const weight = field === '$.tags' ? 30 :
                     field === 'collection_name' ? 25 :
                     field === '$.category' ? 20 :
                     field === 'author' ? 15 : 10
      facetData[field] = { values: realValues[field], weight }
    } else if (FALLBACK_FACET_DATA[field]) {
      facetData[field] = FALLBACK_FACET_DATA[field]
    } else {
      // Generic fallback for unknown fields
      facetData[field] = { values: ['value-1', 'value-2', 'value-3'], weight: 5 }
    }
  }

  // If no enabled facets, use fallback data
  if (Object.keys(facetData).length === 0) {
    console.log('   ⚠ No enabled facets found, using fallback data')
    Object.assign(facetData, FALLBACK_FACET_DATA)
  }

  console.log(`   Using ${Object.keys(facetData).length} facet fields:`)
  for (const [field, data] of Object.entries(facetData)) {
    console.log(`     - ${field}: ${data.values.length} values (weight: ${data.weight})`)
  }

  // Step 4: Generate synthetic facet clicks
  console.log(`\n📊 Generating ${CLICK_COUNT} facet clicks...`)

  const fieldWeights = Object.entries(facetData).map(([field, data]) => ({
    field,
    weight: data.weight,
  }))

  const clicks: Array<{ facet_field: string; facet_value: string }> = []

  for (let i = 0; i < CLICK_COUNT; i++) {
    const field = weightedRandom(fieldWeights)
    const values = facetData[field].values

    // Weight toward first few values (more popular values)
    let valueIdx: number
    if (Math.random() < 0.6) {
      // 60% of clicks on top 3 values
      valueIdx = Math.floor(Math.random() * Math.min(3, values.length))
    } else {
      valueIdx = Math.floor(Math.random() * values.length)
    }

    clicks.push({
      facet_field: field,
      facet_value: values[valueIdx],
    })
  }

  // Count distribution for reporting
  const fieldCounts: Record<string, number> = {}
  for (const c of clicks) {
    fieldCounts[c.facet_field] = (fieldCounts[c.facet_field] || 0) + 1
  }
  console.log(`   ✓ Distribution:`)
  for (const [field, count] of Object.entries(fieldCounts).sort((a, b) => b[1] - a[1])) {
    console.log(`     - ${field}: ${count} clicks (${((count / clicks.length) * 100).toFixed(1)}%)`)
  }

  // Step 5: Send to seeding endpoint (batch to avoid timeouts)
  console.log('\n💾 Inserting into database...')
  const BATCH_SIZE = 100

  let insertedTotal = 0

  for (let offset = 0; offset < clicks.length; offset += BATCH_SIZE) {
    const batch = clicks.slice(offset, offset + BATCH_SIZE)
    const res = await fetch(`${BASE_URL}/admin/plugins/ai-search/api/seed/facet-clicks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({ clicks: batch, days: DAYS }),
    })

    if (!res.ok) {
      const text = await res.text()
      console.error(`   ❌ Batch failed: ${text.slice(0, 200)}`)
      continue
    }

    const json = await res.json() as any
    insertedTotal += json.data?.facet_clicks_inserted || 0
    console.log(`   ✓ Batch ${Math.floor(offset / BATCH_SIZE) + 1}/${Math.ceil(clicks.length / BATCH_SIZE)} (${insertedTotal} total)`)
  }

  console.log()
  console.log(`✅ Done! Seeded ${insertedTotal} facet clicks over ${DAYS} days`)
  console.log(`   View analytics at: ${BASE_URL}/admin/plugins/ai-search#analytics`)
}

main().catch(err => {
  console.error('❌ Fatal error:', err.message || err)
  process.exit(1)
})
