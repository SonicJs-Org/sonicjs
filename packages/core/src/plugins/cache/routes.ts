/**
 * Cache Plugin Routes
 *
 * Admin routes for cache management
 */

import { Hono } from 'hono'
import type { Context } from 'hono'
import { getAllCacheStats, clearAllCaches, getCacheService } from './services/cache.js'
import { CACHE_CONFIGS, parseCacheKey } from './services/cache-config.js'
import { getRecentInvalidations, getCacheInvalidationStats } from './services/cache-invalidation.js'
import { warmCommonCaches, warmNamespace } from './services/cache-warming.js'
import { renderCacheDashboard, CacheDashboardData } from '../../templates/pages/admin-cache.template'

const app = new Hono()

/**
 * GET /admin/cache
 * Cache statistics dashboard
 */
app.get('/', async (c: Context) => {
  const stats = getAllCacheStats()
  const user = c.get('user')

  // Calculate totals
  let totalHits = 0
  let totalMisses = 0
  let totalSize = 0
  let totalEntries = 0

  Object.values(stats).forEach(stat => {
    totalHits += stat.memoryHits + stat.kvHits
    totalMisses += stat.memoryMisses + stat.kvMisses
    totalSize += stat.memorySize
    totalEntries += stat.entryCount
  })

  const totalRequests = totalHits + totalMisses
  const overallHitRate = totalRequests > 0 ? (totalHits / totalRequests) * 100 : 0

  const dashboardData: CacheDashboardData = {
    stats,
    totals: {
      hits: totalHits,
      misses: totalMisses,
      requests: totalRequests,
      hitRate: overallHitRate.toFixed(2),
      memorySize: totalSize,
      entryCount: totalEntries
    },
    namespaces: Object.keys(stats),
    user: user ? {
      name: user.email,
      email: user.email,
      role: user.role
    } : undefined,
    version: c.get('appVersion')
  }

  return c.html(renderCacheDashboard(dashboardData))
})

/**
 * GET /admin/cache/stats
 * Detailed statistics for all namespaces
 */
app.get('/stats', async (c: Context) => {
  const stats = getAllCacheStats()

  return c.json({
    success: true,
    data: stats,
    timestamp: new Date().toISOString()
  })
})

/**
 * GET /admin/cache/stats/:namespace
 * Statistics for a specific namespace
 */
app.get('/stats/:namespace', async (c: Context) => {
  const namespace = c.req.param('namespace')!
  const config = CACHE_CONFIGS[namespace]

  if (!config) {
    return c.json({
      success: false,
      error: `Unknown namespace: ${namespace}`
    }, 404)
  }

  const cache = getCacheService(config)
  const stats = cache.getStats()

  return c.json({
    success: true,
    data: {
      namespace,
      config,
      stats
    },
    timestamp: new Date().toISOString()
  })
})

/**
 * POST /admin/cache/clear
 * Clear all cache entries
 */
app.post('/clear', async (c: Context) => {
  await clearAllCaches()

  return c.json({
    success: true,
    message: 'All cache entries cleared',
    timestamp: new Date().toISOString()
  })
})

/**
 * POST /admin/cache/clear/:namespace
 * Clear cache for a specific namespace
 */
app.post('/clear/:namespace', async (c: Context) => {
  const namespace = c.req.param('namespace')!
  const config = CACHE_CONFIGS[namespace]

  if (!config) {
    return c.json({
      success: false,
      error: `Unknown namespace: ${namespace}`
    }, 404)
  }

  const cache = getCacheService(config)
  await cache.clear()

  return c.json({
    success: true,
    message: `Cache cleared for namespace: ${namespace}`,
    namespace,
    timestamp: new Date().toISOString()
  })
})

/**
 * POST /admin/cache/invalidate
 * Invalidate cache entries matching a pattern
 */
app.post('/invalidate', async (c: Context) => {
  const body = await c.req.json()
  const { pattern, namespace } = body

  if (!pattern) {
    return c.json({
      success: false,
      error: 'Pattern is required'
    }, 400)
  }

  let totalInvalidated = 0

  if (namespace) {
    // Invalidate from specific namespace
    const config = CACHE_CONFIGS[namespace]
    if (!config) {
      return c.json({
        success: false,
        error: `Unknown namespace: ${namespace}`
      }, 404)
    }

    const cache = getCacheService(config)
    totalInvalidated = await cache.invalidate(pattern)
  } else {
    // Invalidate from all namespaces
    for (const config of Object.values(CACHE_CONFIGS)) {
      const cache = getCacheService(config)
      totalInvalidated += await cache.invalidate(pattern)
    }
  }

  return c.json({
    success: true,
    invalidated: totalInvalidated,
    pattern,
    namespace: namespace || 'all',
    timestamp: new Date().toISOString()
  })
})

/**
 * GET /admin/cache/health
 * Cache system health check
 */
app.get('/health', async (c: Context) => {
  const stats = getAllCacheStats()

  // Calculate health metrics
  const namespaces = Object.entries(stats)
  const healthChecks = namespaces.map(([name, stat]) => {
    const hitRate = stat.hitRate
    const memoryUsage = stat.memorySize / (50 * 1024 * 1024) // Assume 50MB max

    return {
      namespace: name,
      status: hitRate > 70 ? 'healthy' : hitRate > 40 ? 'warning' : 'unhealthy',
      hitRate,
      memoryUsage: (memoryUsage * 100).toFixed(2) + '%',
      entryCount: stat.entryCount
    }
  })

  const overallStatus = healthChecks.every(h => h.status === 'healthy')
    ? 'healthy'
    : healthChecks.some(h => h.status === 'unhealthy')
    ? 'unhealthy'
    : 'warning'

  return c.json({
    success: true,
    data: {
      status: overallStatus,
      namespaces: healthChecks,
      timestamp: new Date().toISOString()
    }
  })
})

/**
 * GET /admin/cache/browser
 * Browse all cache entries across namespaces
 */
app.get('/browser', async (c: Context) => {
  const namespace = c.req.query('namespace') || 'all'
  const search = c.req.query('search') || ''
  const sortBy = c.req.query('sort') || 'age' // age, size, key
  const limit = parseInt(c.req.query('limit') || '100')

  const entries: Array<{
    namespace: string
    key: string
    size: number
    age: number
    ttl: number
    expiresAt: number
    parsed: any
  }> = []

  const namespaces = namespace === 'all'
    ? Object.keys(CACHE_CONFIGS)
    : [namespace]

  for (const ns of namespaces) {
    const config = CACHE_CONFIGS[ns]
    if (!config) continue

    const cache = getCacheService(config)
    const keys = await cache.listKeys()

    for (const keyInfo of keys) {
      // Apply search filter
      if (search && !keyInfo.key.toLowerCase().includes(search.toLowerCase())) {
        continue
      }

      const parsed = parseCacheKey(keyInfo.key)
      const ttl = Math.max(0, keyInfo.expiresAt - Date.now()) / 1000

      entries.push({
        namespace: ns,
        key: keyInfo.key,
        size: keyInfo.size,
        age: keyInfo.age,
        ttl,
        expiresAt: keyInfo.expiresAt,
        parsed
      })
    }
  }

  // Sort entries
  if (sortBy === 'size') {
    entries.sort((a, b) => b.size - a.size)
  } else if (sortBy === 'age') {
    entries.sort((a, b) => a.age - b.age)
  } else if (sortBy === 'key') {
    entries.sort((a, b) => a.key.localeCompare(b.key))
  }

  // Limit results
  const limitedEntries = entries.slice(0, limit)

  return c.json({
    success: true,
    data: {
      entries: limitedEntries,
      total: entries.length,
      showing: limitedEntries.length,
      namespace,
      search,
      sortBy
    },
    timestamp: new Date().toISOString()
  })
})

/**
 * GET /admin/cache/browser/:namespace/:key
 * Get detailed information about a specific cache entry
 */
app.get('/browser/:namespace/:key', async (c: Context) => {
  const namespace = c.req.param('namespace')!
  const key = decodeURIComponent(c.req.param('key')!)

  const config = CACHE_CONFIGS[namespace]
  if (!config) {
    return c.json({
      success: false,
      error: `Unknown namespace: ${namespace}`
    }, 404)
  }

  const cache = getCacheService(config)
  const entry = await cache.getEntry(key)

  if (!entry) {
    return c.json({
      success: false,
      error: 'Cache entry not found or expired'
    }, 404)
  }

  const parsed = parseCacheKey(key)

  return c.json({
    success: true,
    data: {
      key,
      namespace,
      parsed,
      ...entry,
      createdAt: new Date(entry.timestamp).toISOString(),
      expiresAt: new Date(entry.expiresAt).toISOString()
    },
    timestamp: new Date().toISOString()
  })
})

/**
 * GET /admin/cache/analytics
 * Advanced cache analytics
 */
app.get('/analytics', async (c: Context) => {
  const stats = getAllCacheStats()
  const invalidationStats = getCacheInvalidationStats()
  const recentInvalidations = getRecentInvalidations(20)

  // Calculate analytics
  let totalHits = 0
  let totalMisses = 0
  let totalSize = 0
  let totalEntries = 0

  const namespacesAnalytics = []

  for (const [namespace, stat] of Object.entries(stats)) {
    totalHits += stat.memoryHits + stat.kvHits
    totalMisses += stat.memoryMisses + stat.kvMisses
    totalSize += stat.memorySize
    totalEntries += stat.entryCount

    const totalRequests = stat.memoryHits + stat.kvHits + stat.memoryMisses + stat.kvMisses
    const hitRate = totalRequests > 0 ? ((stat.memoryHits + stat.kvHits) / totalRequests) * 100 : 0
    const avgEntrySize = stat.entryCount > 0 ? stat.memorySize / stat.entryCount : 0

    namespacesAnalytics.push({
      namespace,
      hitRate: hitRate.toFixed(2),
      totalRequests,
      memoryHitRate: totalRequests > 0 ? ((stat.memoryHits / totalRequests) * 100).toFixed(2) : '0',
      kvHitRate: totalRequests > 0 ? ((stat.kvHits / totalRequests) * 100).toFixed(2) : '0',
      avgEntrySize: Math.round(avgEntrySize),
      totalSize: stat.memorySize,
      entryCount: stat.entryCount,
      efficiency: totalRequests > 0 ? ((stat.memoryHits + stat.kvHits) / (stat.memoryHits + stat.kvHits + stat.dbHits + 1)).toFixed(2) : '0'
    })
  }

  // Sort by hit rate
  namespacesAnalytics.sort((a, b) => parseFloat(b.hitRate) - parseFloat(a.hitRate))

  const totalRequests = totalHits + totalMisses
  const overallHitRate = totalRequests > 0 ? (totalHits / totalRequests) * 100 : 0

  // Calculate cost savings (assume 50ms per DB query vs 2ms for cache)
  const dbQueriesAvoided = totalHits
  const timeSaved = dbQueriesAvoided * 48 // 48ms saved per cache hit
  const estimatedCostSavings = (dbQueriesAvoided / 1000000) * 0.50 // $0.50 per million queries

  return c.json({
    success: true,
    data: {
      overview: {
        totalHits,
        totalMisses,
        totalRequests,
        overallHitRate: overallHitRate.toFixed(2),
        totalSize,
        totalEntries,
        avgEntrySize: totalEntries > 0 ? Math.round(totalSize / totalEntries) : 0
      },
      performance: {
        dbQueriesAvoided,
        timeSavedMs: timeSaved,
        timeSavedMinutes: (timeSaved / 1000 / 60).toFixed(2),
        estimatedCostSavings: estimatedCostSavings.toFixed(4)
      },
      namespaces: namespacesAnalytics,
      invalidation: {
        ...invalidationStats,
        recent: recentInvalidations
      }
    },
    timestamp: new Date().toISOString()
  })
})

/**
 * GET /admin/cache/analytics/trends
 * Cache trends over time (simplified - would need historical data storage)
 */
app.get('/analytics/trends', async (c: Context) => {
  const stats = getAllCacheStats()

  // For now, return current snapshot as a data point
  // In production, this would query historical data
  const dataPoint = {
    timestamp: Date.now(),
    stats: Object.entries(stats).map(([namespace, stat]) => ({
      namespace,
      hitRate: stat.hitRate,
      entryCount: stat.entryCount,
      memorySize: stat.memorySize,
      totalRequests: stat.totalRequests
    }))
  }

  return c.json({
    success: true,
    data: {
      trends: [dataPoint],
      note: 'Historical trends require persistent storage. This returns current snapshot only.'
    },
    timestamp: new Date().toISOString()
  })
})

/**
 * GET /admin/cache/analytics/top-keys
 * Most accessed cache keys (would need hit tracking)
 */
app.get('/analytics/top-keys', async (c: Context) => {
  const _namespace = c.req.query('namespace') || 'all'
  const _limit = parseInt(c.req.query('limit') || '10')

  // This is a placeholder - would need per-key hit tracking
  return c.json({
    success: true,
    data: {
      topKeys: [],
      note: 'Top keys tracking requires per-key hit counting. Feature not yet implemented.'
    },
    timestamp: new Date().toISOString()
  })
})

/**
 * POST /admin/cache/warm
 * Warm cache with common queries
 */
app.post('/warm', async (c: Context) => {
  try {
    const db = c.env.DB as D1Database
    const result = await warmCommonCaches(db)

    return c.json({
      success: true,
      message: 'Cache warming completed',
      ...result,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Cache warming error:', error)
    return c.json({
      success: false,
      error: 'Cache warming failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, 500)
  }
})

/**
 * POST /admin/cache/warm/:namespace
 * Warm specific namespace cache
 */
app.post('/warm/:namespace', async (c: Context) => {
  try {
    const namespace = c.req.param('namespace')!
    const body = await c.req.json()
    const { entries } = body

    if (!entries || !Array.isArray(entries)) {
      return c.json({
        success: false,
        error: 'Entries array is required'
      }, 400)
    }

    const count = await warmNamespace(namespace, entries)

    return c.json({
      success: true,
      message: `Warmed ${count} entries in namespace: ${namespace}`,
      namespace,
      count,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Namespace warming error:', error)
    return c.json({
      success: false,
      error: 'Namespace warming failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, 500)
  }
})

export default app
