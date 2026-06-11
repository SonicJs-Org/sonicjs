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
    const stmt = db.prepare(`SELECT * FROM documents WHERE is_current_draft = 1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT ${limit}`)
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
    const stmt = db.prepare(`SELECT * FROM media WHERE deleted_at IS NULL ORDER BY uploaded_at DESC LIMIT ${limit}`)
    const { results } = await stmt.all()

    for (const media of results as any[]) {
      const key = mediaCache.generateKey('item', media.id)
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
