import type { D1Database } from '@cloudflare/workers-types'
import type { RankingStage, SearchResult, SearchResponse } from '../types'
import { DEFAULT_RANKING_PIPELINE } from '../types'

/** Clamp a weight value to [0, 10] with 1 decimal place */
function clampWeight(val: any, fallback: number): number {
  const n = Number(val)
  return (isNaN(n) || !isFinite(n)) ? fallback : Math.round(Math.min(10, Math.max(0, n)) * 10) / 10
}

const VALID_STAGE_TYPES = new Set(['exactMatch', 'bm25', 'semantic', 'recency', 'popularity', 'custom'])

/**
 * Ranking Pipeline Service
 *
 * Manages a composable scoring pipeline that post-processes search results.
 * Each stage produces a [0, 1] score, combined via weighted sum into pipeline_score.
 */
export class RankingPipelineService {
  constructor(private db: D1Database) {}

  // === Config CRUD ===

  async getConfig(): Promise<RankingStage[]> {
    try {
      const row = await this.db
        .prepare("SELECT pipeline_json FROM ai_search_ranking_config WHERE id = 'default' LIMIT 1")
        .first<{ pipeline_json: string }>()

      if (!row?.pipeline_json) {
        return structuredClone(DEFAULT_RANKING_PIPELINE)
      }

      return this.validateStages(JSON.parse(row.pipeline_json))
    } catch {
      // Table may not exist yet (migration not run)
      return structuredClone(DEFAULT_RANKING_PIPELINE)
    }
  }

  async saveConfig(stages: RankingStage[]): Promise<void> {
    const validated = this.validateStages(stages)
    await this.db
      .prepare(`
        INSERT INTO ai_search_ranking_config (id, pipeline_json, updated_at)
        VALUES ('default', ?, unixepoch())
        ON CONFLICT(id) DO UPDATE SET pipeline_json = excluded.pipeline_json, updated_at = excluded.updated_at
      `)
      .bind(JSON.stringify(validated))
      .run()
  }

  private validateStages(stages: RankingStage[]): RankingStage[] {
    if (!Array.isArray(stages)) return structuredClone(DEFAULT_RANKING_PIPELINE)
    return stages
      .filter(s => VALID_STAGE_TYPES.has(s.type))
      .map(s => ({
        type: s.type,
        weight: clampWeight(s.weight, 0),
        enabled: Boolean(s.enabled),
        config: s.config || undefined,
      }))
  }

  // === Pipeline Execution ===

  async apply(response: SearchResponse, query: string): Promise<SearchResponse> {
    const results = response.results
    if (results.length === 0) return response

    const stages = await this.getConfig()
    const activeStages = stages.filter(s => s.enabled && s.weight > 0)
    if (activeStages.length === 0) return response

    const totalWeight = activeStages.reduce((sum, s) => sum + s.weight, 0)
    if (totalWeight === 0) return response

    // Pre-compute BM25 min/max for normalization
    let minBM25 = Infinity
    let maxBM25 = -Infinity
    const hasBM25 = activeStages.some(s => s.type === 'bm25')
    if (hasBM25) {
      for (const r of results) {
        if (r.bm25_score != null) {
          if (r.bm25_score < minBM25) minBM25 = r.bm25_score
          if (r.bm25_score > maxBM25) maxBM25 = r.bm25_score
        }
      }
      if (minBM25 === Infinity) { minBM25 = 0; maxBM25 = 0 }
    }

    // Batch-load content scores if needed
    const contentIds = results.map(r => r.id)
    let popularityScores = new Map<string, number>()
    let customScores = new Map<string, number>()

    const needsPopularity = activeStages.some(s => s.type === 'popularity')
    const needsCustom = activeStages.some(s => s.type === 'custom')

    if (needsPopularity) {
      popularityScores = await this.getContentScores(contentIds, 'popularity')
      this.normalizeScoresMinMax(popularityScores)
    }
    if (needsCustom) {
      customScores = await this.getContentScores(contentIds, 'custom')
    }

    // Compute pipeline_score for each result
    for (const result of results) {
      let weightedSum = 0

      for (const stage of activeStages) {
        let score = 0

        switch (stage.type) {
          case 'exactMatch':
            score = this.scoreExactMatch(result, query)
            break
          case 'bm25':
            score = this.scoreBM25(result, minBM25, maxBM25)
            break
          case 'semantic':
            score = this.scoreSemantic(result)
            break
          case 'recency':
            score = this.scoreRecency(result, stage.config?.half_life_days ?? 30)
            break
          case 'popularity':
            score = popularityScores.get(result.id) ?? 0
            break
          case 'custom':
            score = Math.max(0, Math.min(1, customScores.get(result.id) ?? 0))
            break
        }

        weightedSum += stage.weight * score
      }

      result.pipeline_score = weightedSum / totalWeight
    }

    // Re-sort by pipeline_score descending
    results.sort((a, b) => (b.pipeline_score ?? 0) - (a.pipeline_score ?? 0))

    return { ...response, results }
  }

  // === Content Scores CRUD ===

  async getContentScores(contentIds: string[], scoreType: string): Promise<Map<string, number>> {
    if (contentIds.length === 0) return new Map()

    try {
      const placeholders = contentIds.map(() => '?').join(',')
      const { results } = await this.db
        .prepare(`SELECT content_id, score FROM ai_search_content_scores WHERE content_id IN (${placeholders}) AND score_type = ?`)
        .bind(...contentIds, scoreType)
        .all<{ content_id: string; score: number }>()

      const map = new Map<string, number>()
      for (const row of results || []) {
        map.set(row.content_id, row.score)
      }
      return map
    } catch {
      return new Map()
    }
  }

  async setContentScore(contentId: string, scoreType: string, score: number): Promise<void> {
    const clamped = Math.max(0, Math.min(1, score))
    await this.db
      .prepare(`
        INSERT INTO ai_search_content_scores (content_id, score_type, score, updated_at)
        VALUES (?, ?, ?, unixepoch())
        ON CONFLICT(content_id, score_type) DO UPDATE SET score = excluded.score, updated_at = excluded.updated_at
      `)
      .bind(contentId, scoreType, clamped)
      .run()
  }

  async deleteContentScore(contentId: string, scoreType: string): Promise<void> {
    await this.db
      .prepare('DELETE FROM ai_search_content_scores WHERE content_id = ? AND score_type = ?')
      .bind(contentId, scoreType)
      .run()
  }

  // === Scoring Functions ===

  private scoreExactMatch(result: SearchResult, query: string): number {
    if (!query || !result.title) return 0
    return result.title.toLowerCase().includes(query.toLowerCase()) ? 1.0 : 0.0
  }

  private scoreBM25(result: SearchResult, minBM25: number, maxBM25: number): number {
    if (result.bm25_score == null) return 0
    if (maxBM25 === minBM25) return 1.0
    return (result.bm25_score - minBM25) / (maxBM25 - minBM25)
  }

  private scoreSemantic(result: SearchResult): number {
    return result.relevance_score ?? 0
  }

  private scoreRecency(result: SearchResult, halfLifeDays: number): number {
    if (!result.created_at) return 0
    const nowMs = Date.now()
    // Handle both Unix seconds and milliseconds
    const createdMs = result.created_at > 1e12 ? result.created_at : result.created_at * 1000
    const ageDays = (nowMs - createdMs) / (1000 * 60 * 60 * 24)
    if (ageDays <= 0) return 1.0
    if (halfLifeDays <= 0) return 0
    return Math.exp(-Math.LN2 * ageDays / halfLifeDays)
  }

  /** Min-max normalize a map of scores in-place */
  private normalizeScoresMinMax(scores: Map<string, number>): void {
    if (scores.size === 0) return
    let min = Infinity
    let max = -Infinity
    for (const v of scores.values()) {
      if (v < min) min = v
      if (v > max) max = v
    }
    if (max === min) {
      for (const k of scores.keys()) scores.set(k, scores.size > 0 ? 1.0 : 0)
      return
    }
    for (const [k, v] of scores) {
      scores.set(k, (v - min) / (max - min))
    }
  }
}
