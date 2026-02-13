/**
 * Admin Search Route
 *
 * GET /admin/search — renders the Search admin dashboard
 * Data gathered from AI Search plugin services, rendered via admin-search.template.ts
 */

import { Hono } from 'hono'
import type { Bindings, Variables } from '../app'
import { requireAuth } from '../middleware'
import { AISearchService } from '../plugins/core-plugins/ai-search-plugin/services/ai-search'
import { IndexManager } from '../plugins/core-plugins/ai-search-plugin/services/indexer'
import { FTS5Service } from '../plugins/core-plugins/ai-search-plugin/services/fts5.service'
import { BenchmarkService } from '../plugins/core-plugins/ai-search-plugin/services/benchmark.service'
import { renderSearchDashboard } from '../templates/pages/admin-search.template'
import { getCoreVersion } from '../utils/version'

const adminSearchRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

adminSearchRoutes.use('*', requireAuth())

adminSearchRoutes.get('/', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_INDEX

    const service = new AISearchService(db, ai, vectorize)
    const indexer = new IndexManager(db, ai, vectorize)
    const fts5Service = new FTS5Service(db)
    const kv = c.env.CACHE_KV
    const benchmarkService = new BenchmarkService(db, kv)

    // Gather all data in parallel
    const [settings, collections, newCollections, indexStatus, analytics] = await Promise.all([
      service.getSettings(),
      service.getAllCollections(),
      service.detectNewCollections(),
      indexer.getAllIndexStatus(),
      service.getSearchAnalytics(),
    ])

    // FTS5 status
    let fts5Status: { available: boolean; total_indexed: number; by_collection: Record<string, number> } | null = null
    try {
      const isAvailable = await fts5Service.isAvailable()
      if (isAvailable) {
        const stats = await fts5Service.getStats()
        fts5Status = { available: true, total_indexed: stats.total_indexed, by_collection: stats.by_collection }
      } else {
        fts5Status = { available: false, total_indexed: 0, by_collection: {} }
      }
    } catch {
      fts5Status = { available: false, total_indexed: 0, by_collection: {} }
    }

    // Benchmark status (default dataset: scifact)
    let benchmarkStatus: { seeded: boolean; seeded_count: number; corpus_size: number; query_count: number } | null = null
    try {
      const { seeded, count } = await benchmarkService.isSeeded()
      const meta = benchmarkService.getMeta()
      benchmarkStatus = {
        seeded,
        seeded_count: count,
        corpus_size: meta.corpus_size,
        query_count: meta.query_count,
      }
    } catch {
      benchmarkStatus = null
    }

    return c.html(
      renderSearchDashboard({
        settings,
        collections: collections || [],
        newCollections: (newCollections || []).map(n => ({ id: String(n.collection.id), name: n.collection.name })),
        indexStatus: indexStatus || {},
        analytics,
        fts5Status,
        benchmarkStatus,
        user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
        version: getCoreVersion(),
      })
    )
  } catch (error) {
    console.error('Error rendering Search admin page:', error)
    return c.html(`<p>Error loading search dashboard: ${error instanceof Error ? error.message : String(error)}</p>`, 500)
  }
})

export { adminSearchRoutes }
