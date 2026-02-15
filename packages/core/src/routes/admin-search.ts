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
    const now = Date.now()
    const midnightToday = new Date()
    midnightToday.setHours(0, 0, 0, 0)
    const thirtyDaysAgo = now - 30 * 24 * 60 * 60 * 1000

    const [settings, collections, newCollections, indexStatus, analytics, queriesTodayRow, totalClicks30dRow, zeroResults30dRow] = await Promise.all([
      service.getSettings(),
      service.getAllCollections(),
      service.detectNewCollections(),
      indexer.getAllIndexStatus(),
      service.getSearchAnalytics(),
      db.prepare('SELECT COUNT(*) as count FROM ai_search_history WHERE created_at >= ?').bind(midnightToday.getTime()).first<{ count: number }>().catch(() => null),
      db.prepare("SELECT COUNT(*) as count FROM ai_search_clicks WHERE created_at > datetime('now', '-30 days')").first<{ count: number }>().catch(() => null),
      db.prepare('SELECT COUNT(*) as count FROM ai_search_history WHERE results_count = 0 AND created_at >= ?').bind(thirtyDaysAgo).first<{ count: number }>().catch(() => null),
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
        queriesToday: queriesTodayRow?.count ?? 0,
        totalClicks30d: totalClicks30dRow?.count ?? 0,
        zeroResults30d: zeroResults30dRow?.count ?? 0,
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
