/**
 * Hybrid Search Service
 *
 * Combines FTS5 (BM25) and AI (Vectorize) search results using
 * Reciprocal Rank Fusion (RRF) for unified ranking.
 *
 * When Vectorize is unavailable (local dev), falls back to FTS5-only
 * while still returning mode: 'hybrid'.
 */

import type { SearchQuery, SearchResponse, SearchResult, AISearchSettings } from '../types'
import type { FTS5Service } from './fts5.service'
import type { CustomRAGService } from './custom-rag.service'

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
    const searches: Promise<SearchResponse>[] = [
      this.fts5Service.search(query, settings)
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

    // Merge with Reciprocal Rank Fusion
    return this.mergeWithRRF(fulfilled, query, settings, startTime)
  }

  /**
   * Reciprocal Rank Fusion (Cormack et al. 2009)
   * score(d) = Σ 1/(k + rank(d))  where k=60
   */
  private mergeWithRRF(
    responses: SearchResponse[],
    query: SearchQuery,
    settings: AISearchSettings,
    startTime: number
  ): SearchResponse {
    const K = 60 // Standard RRF constant
    const scoreMap = new Map<string, { result: SearchResult; rrfScore: number }>()

    for (const response of responses) {
      response.results.forEach((result, rank) => {
        const id = result.id
        const rrfContribution = 1 / (K + rank + 1) // rank is 0-indexed, so +1

        if (scoreMap.has(id)) {
          const existing = scoreMap.get(id)!
          existing.rrfScore += rrfContribution
          // Merge metadata: keep FTS5 highlights and bm25_score, keep AI relevance_score
          if (result.highlights) existing.result.highlights = result.highlights
          if (result.bm25_score) existing.result.bm25_score = result.bm25_score
          if (result.relevance_score) existing.result.relevance_score = result.relevance_score
        } else {
          scoreMap.set(id, {
            result: { ...result },
            rrfScore: rrfContribution
          })
        }
      })
    }

    const limit = query.limit || settings.results_limit || 20

    // Sort descending by RRF score, apply limit
    const merged = Array.from(scoreMap.values())
      .sort((a, b) => b.rrfScore - a.rrfScore)
      .slice(0, limit)
      .map(({ result, rrfScore }) => ({
        ...result,
        rrf_score: rrfScore
      }))

    return {
      mode: 'hybrid',
      results: merged,
      total: scoreMap.size,
      query_time_ms: Date.now() - startTime
    }
  }
}
