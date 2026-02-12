/**
 * Hybrid Search Service
 *
 * Combines FTS5 (BM25) and AI (Vectorize) search results using
 * Reciprocal Rank Fusion (RRF):
 *   1. Retrieve candidates from both FTS5 and AI in parallel
 *   2. Score each doc: RRF(d) = Σ 1/(k + rank_in_system)
 *   3. Docs found by BOTH systems get boosted (two rank contributions)
 *   4. Sort by combined RRF score, slice to limit
 *
 * RRF is the industry standard for multi-source fusion — it properly
 * balances contributions without requiring score normalization.
 *
 * When Vectorize is unavailable (local dev), falls back to FTS5-only
 * while still returning mode: 'hybrid'.
 */

import type { SearchQuery, SearchResponse, SearchResult, AISearchSettings } from '../types'
import type { FTS5Service } from './fts5.service'
import type { CustomRAGService } from './custom-rag.service'

/** RRF constant — standard value from the original paper (Cormack et al. 2009) */
const RRF_K = 60

export class HybridSearchService {
  constructor(
    private fts5Service: FTS5Service,
    private customRAG?: CustomRAGService
  ) {}

  /**
   * Run FTS5 + AI searches in parallel, merge with RRF
   * Uses Promise.allSettled for partial failure tolerance
   */
  async search(query: SearchQuery, settings: AISearchSettings): Promise<SearchResponse> {
    const startTime = Date.now()

    // Build search promises: FTS5 always, AI only if available
    const fts5Weights = {
      titleBoost: settings.fts5_title_boost,
      slugBoost: settings.fts5_slug_boost,
      bodyBoost: settings.fts5_body_boost,
    }
    const searches: Promise<SearchResponse>[] = [
      this.fts5Service.search(query, settings, fts5Weights)
    ]
    if (this.customRAG?.isAvailable()) {
      searches.push(this.customRAG.search(query, settings))
    }

    const settled = await Promise.allSettled(searches)

    // Extract fulfilled results, log any rejections
    const fulfilled: SearchResponse[] = []
    for (const result of settled) {
      if (result.status === 'fulfilled') {
        fulfilled.push(result.value)
      } else {
        console.error('[HybridSearch] One search leg failed:', result.reason)
      }
    }

    // If ALL legs failed, return empty results
    if (fulfilled.length === 0) {
      return {
        results: [],
        total: 0,
        query_time_ms: Date.now() - startTime,
        mode: 'hybrid'
      }
    }

    // Single leg (FTS5 only) — no fusion needed
    if (fulfilled.length === 1) {
      const single = fulfilled[0]!
      return {
        results: single.results,
        total: single.total,
        suggestions: single.suggestions,
        mode: 'hybrid' as const,
        query_time_ms: Date.now() - startTime
      }
    }

    // Two legs: Reciprocal Rank Fusion
    return this.mergeWithRRF(fulfilled[0]!, fulfilled[1]!, query, settings, startTime)
  }

  /**
   * Reciprocal Rank Fusion (RRF)
   *
   * For each document d, compute:
   *   RRF_score(d) = Σ 1/(k + rank_i(d))
   * where rank_i(d) is the 1-based rank of d in system i.
   *
   * Docs found by both systems get two contributions (higher score).
   * k=60 smooths out rank differences (standard value).
   */
  private mergeWithRRF(
    fts5Response: SearchResponse,
    aiResponse: SearchResponse,
    query: SearchQuery,
    settings: AISearchSettings,
    startTime: number
  ): SearchResponse {
    // RRF score accumulator and doc data store
    const rrfScores = new Map<string, number>()
    const docData = new Map<string, SearchResult>()

    // Score AI results (1-based rank)
    aiResponse.results.forEach((doc, i) => {
      const rank = i + 1
      const score = 1.0 / (RRF_K + rank)
      rrfScores.set(doc.id, (rrfScores.get(doc.id) || 0) + score)
      docData.set(doc.id, { ...doc })
    })

    // Score FTS5 results (1-based rank)
    fts5Response.results.forEach((doc, i) => {
      const rank = i + 1
      const score = 1.0 / (RRF_K + rank)
      rrfScores.set(doc.id, (rrfScores.get(doc.id) || 0) + score)

      // Merge: keep AI data if exists, add FTS5 highlights/bm25
      const existing = docData.get(doc.id)
      if (existing) {
        if (doc.highlights) existing.highlights = doc.highlights
        if (doc.bm25_score) existing.bm25_score = doc.bm25_score
      } else {
        docData.set(doc.id, { ...doc })
      }
    })

    // Sort by RRF score descending
    const sorted = [...rrfScores.entries()].sort((a, b) => b[1] - a[1])

    const limit = query.limit || settings.results_limit || 20
    const results: SearchResult[] = sorted.slice(0, limit).map(([id, score]) => ({
      ...docData.get(id)!,
      relevance_score: score,
    }))

    return {
      mode: 'hybrid',
      results,
      total: rrfScores.size,
      query_time_ms: Date.now() - startTime,
    }
  }
}
