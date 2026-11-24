/**
 * Cache Plugin
 *
 * Three-tiered caching system for SonicJS
 * - Tier 1: In-Memory (fastest, region-specific)
 * - Tier 2: Cloudflare KV (fast, global)
 * - Tier 3: Database (source of truth)
 */

import type { Context } from 'hono'
import type { PluginContext } from '@sonicjs-cms/core'
import { getCacheService, clearAllCaches, getAllCacheStats } from './services/cache.js'
import { CACHE_CONFIGS } from './services/cache-config.js'
import { setupCacheInvalidation } from './services/cache-invalidation.js'
import cacheRoutes from './routes.js'

export class CachePlugin {
  private _context: PluginContext | null = null

  /**
   * Get plugin routes
   */
  getRoutes() {
    return cacheRoutes
  }

  /**
   * Activate the cache plugin
   */
  async activate(context: PluginContext): Promise<void> {
    this._context = context

    const settings = context.config || {}

    console.log('✅ Cache plugin activated', {
      memoryEnabled: settings.memoryEnabled ?? true,
      kvEnabled: settings.kvEnabled ?? true,
      defaultTTL: settings.defaultTTL ?? 3600
    })

    // Initialize default cache services
    // Note: kvEnabled is intentionally NOT overridden by plugin settings — it is a
    // per-namespace system concern governed by CACHE_CONFIGS, not a plugin toggle.
    // memoryEnabled and defaultTTL remain user-configurable.
    for (const [_namespace, config] of Object.entries(CACHE_CONFIGS)) {
      getCacheService({
        ...config,
        memoryEnabled: settings.memoryEnabled ?? config.memoryEnabled,
        ttl: settings.defaultTTL ?? config.ttl
      })
    }

    // Setup event-based cache invalidation
    setupCacheInvalidation()
  }

  /**
   * Deactivate the cache plugin
   */
  async deactivate(): Promise<void> {
    console.log('❌ Cache plugin deactivated - clearing all caches')
    await clearAllCaches()
    this._context = null
  }

  /**
   * Configure the cache plugin
   */
  async configure(settings: Record<string, any>): Promise<void> {
    console.log('⚙️ Cache plugin configured', settings)

    // Reconfigure all cache instances with new settings
    for (const [_namespace, config] of Object.entries(CACHE_CONFIGS)) {
      getCacheService({
        ...config,
        memoryEnabled: settings.memoryEnabled ?? config.memoryEnabled,
        kvEnabled: settings.kvEnabled ?? config.kvEnabled,
        ttl: settings.defaultTTL ?? config.ttl
      })
    }
  }

  /**
   * Get cache statistics
   */
  async getStats(c: Context): Promise<Response> {
    const stats = getAllCacheStats()

    return c.json({
      success: true,
      data: stats,
      timestamp: new Date().toISOString()
    })
  }

  /**
   * Clear all cache entries
   */
  async clearCache(c: Context): Promise<Response> {
    await clearAllCaches()

    return c.json({
      success: true,
      message: 'All cache entries cleared',
      timestamp: new Date().toISOString()
    })
  }

  /**
   * Invalidate cache entries matching pattern
   */
  async invalidatePattern(c: Context): Promise<Response> {
    const body = await c.req.json()
    const { pattern, namespace: _namespace } = body

    if (!pattern) {
      return c.json({
        success: false,
        error: 'Pattern is required'
      }, 400)
    }

    let totalInvalidated = 0

    if (_namespace) {
      // Invalidate from specific namespace
      const cache = getCacheService(CACHE_CONFIGS[_namespace] || {
        ttl: 3600,
        kvEnabled: false,
        memoryEnabled: true,
        namespace: _namespace,
        invalidateOn: [],
        version: 'v1'
      })
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
      namespace: _namespace || 'all',
      timestamp: new Date().toISOString()
    })
  }
}

// Export cache services for use by other plugins/routes when cache plugin is active
export {
  getCacheService,
  clearAllCaches,
  getAllCacheStats,
  setGlobalKVNamespace
} from './services/cache'
export { CACHE_CONFIGS, getCacheConfig, generateCacheKey } from './services/cache-config'
export type { CacheConfig, CacheStats } from './services/cache-config'
export { emitEvent, onEvent, getEventBus } from './services/event-bus'
export { getCacheInvalidationStats, getRecentInvalidations } from './services/cache-invalidation'
export { warmCommonCaches, warmNamespace, preloadCache } from './services/cache-warming'

// Create and export plugin instance
const plugin = new CachePlugin()
export default plugin
