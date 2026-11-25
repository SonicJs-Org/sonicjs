/**
 * Cache Warming Utilities
 *
 * Utilities for preloading and warming cache entries
 */

import { getCacheService } from './cache.js'
import { CACHE_CONFIGS } from './cache-config.js'
import { getCollectionRegistry, collectionRecordToRow } from '../../../services/collection-registry'

/**
 * Warm cache with common queries
 */
export async function warmCommonCaches(db: D1Database): Promise<{
  warmed: number
  errors: number
  details: Array<{ namespace: string; count: number }>
}> {
  let totalWarmed = 0
  let totalErrors = 0
  const details: Array<{ namespace: string; count: number }> = []

  try {
    // Warm collection cache
    const collectionCount = await warmCollections(db)
    totalWarmed += collectionCount
    details.push({ namespace: 'collection', count: collectionCount })

    // Warm content cache (most recent items)
    const contentCount = await warmRecentContent(db)
    totalWarmed += contentCount
    details.push({ namespace: 'content', count: contentCount })

    // Warm media cache (most recent items)
    const mediaCount = await warmRecentMedia(db)
    totalWarmed += mediaCount
    details.push({ namespace: 'media', count: mediaCount })

  } catch (error) {
    console.error('Error warming caches:', error)
    totalErrors++
  }

  return {
    warmed: totalWarmed,
    errors: totalErrors,
    details
  }
}

/**
 * Warm collections cache
 */
async function warmCollections(db: D1Database): Promise<number> {
  const config = CACHE_CONFIGS.collection
  if (!config) return 0
  const collectionCache = getCacheService(config)
  let count = 0

  try {
    const results = getCollectionRegistry()
      .listActive()
      .map(collectionRecordToRow)

    for (const collection of results) {
      const key = collectionCache.generateKey('item', collection.id)
      await collectionCache.set(key, collection)
      count++
    }

    // Also cache the full list
    const listKey = collectionCache.generateKey('list', 'all')
    await collectionCache.set(listKey, results)
    count++

  } catch (error) {
    console.error('Error warming collections cache:', error)
  }

  return count
}

/**
 * Warm recent content cache
 */
async function warmRecentContent(db: D1Database, limit: number = 50): Promise<number> {
  const config = CACHE_CONFIGS.content
  if (!config) return 0
  const contentCache = getCacheService(config)
  let count = 0

  try {
    // Content is document-backed now — warm recent current-draft documents (decommission of `content`).
    // Exclude media_asset (warmed separately by warmRecentMedia). Tenant-scoped per R3.
    const stmt = db
      .prepare(`SELECT * FROM documents WHERE tenant_id = ? AND type_id != 'media_asset' AND is_current_draft = 1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT ${limit}`)
      .bind('default')
    const { results } = await stmt.all()

    for (const content of results as any[]) {
      const key = contentCache.generateKey('item', content.root_id ?? content.id)
      await contentCache.set(key, content)
      count++
    }

    // Cache the list
    const listKey = contentCache.generateKey('list', 'recent')
    await contentCache.set(listKey, results)
    count++

  } catch (error) {
    console.error('Error warming content cache:', error)
  }

  return count
}

/**
 * Warm recent media cache
 */
async function warmRecentMedia(db: D1Database, limit: number = 50): Promise<number> {
  const config = CACHE_CONFIGS.media
  if (!config) return 0
  const mediaCache = getCacheService(config)
  let count = 0

  try {
    // Media is document-backed (type_id = 'media_asset'). Tenant-scoped per R3.
    const stmt = db
      .prepare(`SELECT * FROM documents WHERE tenant_id = ? AND type_id = 'media_asset' AND is_current_draft = 1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT ${limit}`)
      .bind('default')
    const { results } = await stmt.all()

    for (const media of results as any[]) {
      const key = mediaCache.generateKey('item', (media as any).root_id ?? media.id)
      await mediaCache.set(key, media)
      count++
    }

    // Cache the list
    const listKey = mediaCache.generateKey('list', 'recent')
    await mediaCache.set(listKey, results)
    count++

  } catch (error) {
    console.error('Error warming media cache:', error)
  }

  return count
}

/**
 * Warm specific namespace with custom data
 */
export async function warmNamespace(
  namespace: string,
  entries: Array<{ key: string; value: any }>
): Promise<number> {
  const config = CACHE_CONFIGS[namespace]
  if (!config) {
    throw new Error(`Unknown namespace: ${namespace}`)
  }

  const cache = getCacheService(config)
  await cache.setMany(entries)

  return entries.length
}

/**
 * Preload cache on application startup
 */
export async function preloadCache(db: D1Database): Promise<void> {
  console.log('🔥 Preloading cache...')

  const result = await warmCommonCaches(db)

  console.log(`✅ Cache preloaded: ${result.warmed} entries across ${result.details.length} namespaces`)
  result.details.forEach(detail => {
    console.log(`  - ${detail.namespace}: ${detail.count} entries`)
  })

  if (result.errors > 0) {
    console.warn(`⚠️  ${result.errors} errors during cache preloading`)
  }
}

/**
 * Schedule periodic cache warming
 */
export function schedulePeriodicWarming(
  db: D1Database,
  intervalMs: number = 300000 // 5 minutes default
): NodeJS.Timeout {
  console.log(`⏰ Scheduling periodic cache warming every ${intervalMs / 1000}s`)

  return setInterval(async () => {
    try {
      console.log('🔄 Running periodic cache warming...')
      await warmCommonCaches(db)
    } catch (error) {
      console.error('Error during periodic cache warming:', error)
    }
  }, intervalMs)
}

// ── Filter-combo prewarm ─────────────────────────────────────────────────────

export interface FilterDimension {
  /** Query field path, e.g. 'data.department' */
  field: string
  /** D1 type_id (== collection name) used to look up all published IDs */
  typeId: string
}

export interface PrewarmCombinationsOpts {
  db: D1Database
  /** Base origin of this Worker, e.g. 'https://speed-backend.sonicjs.com' */
  baseUrl: string
  /** Collection slug to query, default 'employees' */
  collection?: string
  /** Filter dimensions; defaults to department + region */
  filterDimensions?: FilterDimension[]
  /** Number of pages to warm per combo (1-indexed), default 3 */
  pages?: number
  /** Items per page, default 10 */
  pageSize?: number
  /** Parallel fetch concurrency, default 10 */
  concurrency?: number
  /**
   * Optional sort parameter to include in every prewarmed URL.
   * Must match what the front-end client sends so the cache keys align.
   * Example: JSON.stringify([{ field: 'data.phone', order: 'asc' }])
   */
  sort?: string
}

export interface PrewarmCombinationsResult {
  warmed: number
  errors: number
  errorDetails: string[]
  total: number
  combinations: number
  pages: number
  pageSize: number
  collection: string
  dimensions: Array<{ field: string; count: number }>
}

/**
 * Prewarm all filter-combo pages for a collection by self-fetching its public
 * content API endpoint.  Callers are responsible for ensuring `baseUrl` is
 * reachable (same Worker on Cloudflare, localhost in dev).
 *
 * Each fetch goes through the full cache middleware stack, so KV is populated
 * exactly as if a real user had made the request.
 *
 * Combo count: (D + 1) × (R + 1) for two dimensions (D depts, R regions),
 * including the "no-filter / all" baseline.  With 9 depts and 6 regions that
 * is 70 combos × 3 pages = 210 requests, well within CF CPU limits when
 * batched at concurrency=10.
 */
export async function prewarmFilterCombinations(
  opts: PrewarmCombinationsOpts
): Promise<PrewarmCombinationsResult> {
  const {
    db,
    baseUrl,
    collection = 'employees',
    filterDimensions = [
      { field: 'data.department', typeId: 'departments' },
      { field: 'data.region',     typeId: 'regions'     },
    ],
    pages      = 3,
    pageSize   = 10,
    concurrency = 10,
    sort,
  } = opts

  const cappedPages = Math.min(pages, 10)

  // 1. Resolve each dimension's published IDs from D1
  const dimensionValues: Array<{ field: string; ids: string[] }> = []
  for (const dim of filterDimensions) {
    const { results } = await db
      .prepare(
        `SELECT root_id FROM documents
         WHERE type_id = ? AND tenant_id = 'default'
           AND is_published = 1 AND deleted_at IS NULL`
      )
      .bind(dim.typeId)
      .all()
    dimensionValues.push({
      field: dim.field,
      ids: (results as any[]).map(r => r.root_id as string),
    })
  }

  // 2. Build cartesian product of filter combos, including "no filter" for each dim.
  //    Start with [{}] (the all-results baseline), then for each dimension expand
  //    the existing combos by adding a copy without the dim (already present) and
  //    one copy per ID value.
  let combos: Array<Record<string, string>> = [{}]
  for (const dim of dimensionValues) {
    const expanded: Array<Record<string, string>> = []
    for (const existing of combos) {
      // "all" for this dimension — keep existing combo as-is
      expanded.push({ ...existing })
      // one combo per specific value
      for (const id of dim.ids) {
        expanded.push({ ...existing, [dim.field]: id })
      }
    }
    combos = expanded
  }

  // 3. Build the full URL list (cappedPages per combo)
  const urls: string[] = []
  for (const combo of combos) {
    for (let page = 0; page < cappedPages; page++) {
      const params = new URLSearchParams()
      params.set('limit',  String(pageSize))
      params.set('offset', String(page * pageSize))
      params.set('status', 'published')
      if (sort) params.set('sort', sort)
      for (const [field, value] of Object.entries(combo)) {
        params.set(`where[${field}][equals]`, value)
      }
      urls.push(`${baseUrl}/api/${collection}?${params.toString()}`)
    }
  }

  // 4. Fetch in parallel batches of `concurrency`
  let warmed = 0
  let errors = 0
  const errorDetails: string[] = []

  for (let i = 0; i < urls.length; i += concurrency) {
    const batch = urls.slice(i, i + concurrency)
    const settled = await Promise.allSettled(
      batch.map(url => fetch(url, { headers: { 'X-Cache-Prewarm': '1' } }))
    )
    for (let j = 0; j < settled.length; j++) {
      const r = settled[j]!
      if (r.status === 'fulfilled') {
        if (r.value.ok) {
          warmed++
        } else {
          errors++
          if (errorDetails.length < 5) errorDetails.push(`HTTP ${r.value.status} ${batch[j]}`)
        }
      } else {
        errors++
        if (errorDetails.length < 5) errorDetails.push(String(r.reason))
      }
    }
  }

  return {
    warmed,
    errors,
    errorDetails,
    total:        urls.length,
    combinations: combos.length,
    pages:        cappedPages,
    pageSize,
    collection,
    dimensions:   dimensionValues.map(d => ({ field: d.field, count: d.ids.length })),
  }
}
