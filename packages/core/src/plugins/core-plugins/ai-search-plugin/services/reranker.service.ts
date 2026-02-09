/**
 * Reranker Service
 *
 * Uses @cf/baai/bge-reranker-base cross-encoder to rerank search results
 * by scoring each (query, passage) pair for semantic relevance.
 *
 * API shape (verified from Cloudflare Workers AI docs):
 *   Request:  { query: string, contexts: [{text: string}, ...], top_k?: number }
 *   Response: [{id: number, score: number}, ...] where id = original index, score in [0,1]
 *
 * On by default (reranking_enabled setting). Gracefully falls back to
 * original order on any error.
 */

import type { SearchResult } from '../types'

export class RerankerService {
  constructor(private ai: any) {}

  /**
   * Rerank results using cross-encoder scoring
   * Returns results sorted by reranker score with rerank_score field added
   */
  async rerank(
    query: string,
    results: SearchResult[],
    topK?: number
  ): Promise<SearchResult[]> {
    if (results.length <= 1) return results

    const limit = topK || results.length

    try {
      // Build contexts from result titles + snippets
      const contexts = results.map(r => ({
        text: `${r.title}. ${r.snippet || ''}`
      }))

      const response = await this.ai.run('@cf/baai/bge-reranker-base', {
        query,
        contexts,
        top_k: limit
      })

      // Response is an array of {id: number, score: number}
      // where id references the original index in contexts
      const scores = Array.isArray(response) ? response : response.response
      if (!Array.isArray(scores) || scores.length === 0) {
        console.warn('[Reranker] Unexpected response format, returning original order')
        return results.slice(0, limit)
      }

      // Map scores back to results by original index
      const reranked: SearchResult[] = scores
        .filter((s: any) => s.id >= 0 && s.id < results.length)
        .map((s: any) => {
          const result = results[s.id]!
          return { ...result, rerank_score: s.score }
        })

      return reranked.slice(0, limit)
    } catch (error) {
      console.error('[Reranker] Cross-encoder failed, returning original order:', error)
      return results.slice(0, limit)
    }
  }
}
