import type { D1Database } from '@cloudflare/workers-types'
import type { Recommendation, RecommendationCategory, RecommendationStatus, AgentRun } from '../types'
import { SynonymService } from './synonym.service'
import { QueryRulesService } from './query-rules.service'

/**
 * Recommendation Service
 *
 * Mines search analytics data (search history, click tracking, facet interactions)
 * and produces actionable recommendations across 5 categories.
 * Supports an approval queue where admins can review and auto-apply suggestions.
 */
export class RecommendationService {
  constructor(private db: D1Database) {}

  // =============================================
  // CRUD
  // =============================================

  async getAll(options?: {
    status?: RecommendationStatus
    category?: RecommendationCategory
    limit?: number
    offset?: number
  }): Promise<Recommendation[]> {
    const conditions: string[] = []
    const params: any[] = []

    if (options?.status) {
      conditions.push('status = ?')
      params.push(options.status)
    }
    if (options?.category) {
      conditions.push('category = ?')
      params.push(options.category)
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''
    const limit = options?.limit || 100
    const offset = options?.offset || 0

    const { results } = await this.db
      .prepare(`SELECT * FROM ai_search_recommendations ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
      .bind(...params, limit, offset)
      .all()

    return (results || []).map(row => this.mapRow(row))
  }

  async getById(id: string): Promise<Recommendation | null> {
    const row = await this.db
      .prepare('SELECT * FROM ai_search_recommendations WHERE id = ?')
      .bind(id)
      .first()

    return row ? this.mapRow(row) : null
  }

  async updateStatus(id: string, status: RecommendationStatus): Promise<Recommendation | null> {
    const appliedAt = status === 'applied' ? Math.floor(Date.now() / 1000) : null
    await this.db
      .prepare('UPDATE ai_search_recommendations SET status = ?, applied_at = COALESCE(?, applied_at), updated_at = unixepoch() WHERE id = ?')
      .bind(status, appliedAt, id)
      .run()

    return this.getById(id)
  }

  async dismissAll(): Promise<number> {
    const result = await this.db
      .prepare("UPDATE ai_search_recommendations SET status = 'dismissed', updated_at = unixepoch() WHERE status = 'pending'")
      .run()

    return result.meta?.changes ?? 0
  }

  async getStats(): Promise<{
    total: number
    pending: number
    applied: number
    dismissed: number
    byCategory: Record<string, number>
  }> {
    const [totalRow, pendingRow, appliedRow, dismissedRow] = await Promise.all([
      this.db.prepare('SELECT COUNT(*) as cnt FROM ai_search_recommendations').first<{ cnt: number }>(),
      this.db.prepare("SELECT COUNT(*) as cnt FROM ai_search_recommendations WHERE status = 'pending'").first<{ cnt: number }>(),
      this.db.prepare("SELECT COUNT(*) as cnt FROM ai_search_recommendations WHERE status = 'applied'").first<{ cnt: number }>(),
      this.db.prepare("SELECT COUNT(*) as cnt FROM ai_search_recommendations WHERE status = 'dismissed'").first<{ cnt: number }>(),
    ])

    const { results: catRows } = await this.db
      .prepare("SELECT category, COUNT(*) as cnt FROM ai_search_recommendations WHERE status = 'pending' GROUP BY category")
      .all<{ category: string; cnt: number }>()

    const byCategory: Record<string, number> = {}
    for (const row of catRows || []) {
      byCategory[row.category] = row.cnt
    }

    return {
      total: totalRow?.cnt ?? 0,
      pending: pendingRow?.cnt ?? 0,
      applied: appliedRow?.cnt ?? 0,
      dismissed: dismissedRow?.cnt ?? 0,
      byCategory,
    }
  }

  // =============================================
  // Run Tracking
  // =============================================

  async createRun(): Promise<string> {
    const id = crypto.randomUUID().replace(/-/g, '')
    await this.db
      .prepare('INSERT INTO ai_search_agent_runs (id, status) VALUES (?, ?)')
      .bind(id, 'running')
      .run()

    return id
  }

  async completeRun(runId: string, count: number, durationMs: number): Promise<void> {
    await this.db
      .prepare("UPDATE ai_search_agent_runs SET status = 'completed', recommendations_count = ?, duration_ms = ?, completed_at = unixepoch() WHERE id = ?")
      .bind(count, durationMs, runId)
      .run()
  }

  async failRun(runId: string, error: string): Promise<void> {
    await this.db
      .prepare("UPDATE ai_search_agent_runs SET status = 'failed', error_message = ?, completed_at = unixepoch() WHERE id = ?")
      .bind(error, runId)
      .run()
  }

  async getLatestRun(): Promise<AgentRun | null> {
    const row = await this.db
      .prepare('SELECT * FROM ai_search_agent_runs ORDER BY created_at DESC LIMIT 1')
      .first()

    return row ? this.mapRunRow(row) : null
  }

  async getRunHistory(limit: number = 10): Promise<AgentRun[]> {
    const { results } = await this.db
      .prepare('SELECT * FROM ai_search_agent_runs ORDER BY created_at DESC LIMIT ?')
      .bind(limit)
      .all()

    return (results || []).map(row => this.mapRunRow(row))
  }

  // =============================================
  // Analysis Engine
  // =============================================

  async runAnalysis(): Promise<string> {
    const runId = await this.createRun()
    const startTime = Date.now()

    try {
      const counts = await Promise.all([
        this.analyzeSynonymOpportunities(runId),
        this.analyzeQueryRuleOpportunities(runId),
        this.analyzeLowCtrQueries(runId),
        this.analyzeUnusedFacets(runId),
        this.analyzeContentGaps(runId),
      ])

      const totalCount = counts.reduce((a, b) => a + b, 0)
      const durationMs = Date.now() - startTime
      await this.completeRun(runId, totalCount, durationMs)
    } catch (error) {
      await this.failRun(runId, error instanceof Error ? error.message : String(error))
    }

    return runId
  }

  /**
   * Find zero-result queries similar to successful queries.
   * Both Levenshtein distance (<=2) AND token overlap (>=50%) must be satisfied
   * to reduce false positives. Stopwords and very short queries are excluded.
   */
  private async analyzeSynonymOpportunities(runId: string): Promise<number> {
    let count = 0
    try {
      // Get zero-result queries with >= 3 occurrences in last 30 days
      const thirtyDaysAgo = Math.floor(Date.now() / 1000) - (30 * 24 * 60 * 60)
      const { results: zeroResults } = await this.db
        .prepare(`
          SELECT LOWER(query) as query, COUNT(*) as cnt
          FROM ai_search_history
          WHERE results_count = 0 AND created_at >= ?
          GROUP BY LOWER(query) HAVING COUNT(*) >= 3
          ORDER BY cnt DESC LIMIT 50
        `)
        .bind(thirtyDaysAgo)
        .all<{ query: string; cnt: number }>()

      if (!zeroResults || zeroResults.length === 0) return 0

      // Get successful queries (results > 0) for comparison
      const { results: successResults } = await this.db
        .prepare(`
          SELECT LOWER(query) as query, COUNT(*) as cnt, AVG(results_count) as avg_results
          FROM ai_search_history
          WHERE results_count > 0 AND created_at >= ?
          GROUP BY LOWER(query)
          ORDER BY cnt DESC LIMIT 200
        `)
        .bind(thirtyDaysAgo)
        .all<{ query: string; cnt: number; avg_results: number }>()

      if (!successResults || successResults.length === 0) return 0

      for (const zr of zeroResults) {
        // Skip stopwords and very short queries (< 3 chars)
        if (zr.query.length < 3 || STOPWORDS.has(zr.query)) continue

        for (const sr of successResults) {
          if (sr.query.length < 3 || STOPWORDS.has(sr.query)) continue
          if (zr.query === sr.query) continue

          const distance = levenshteinDistance(zr.query, sr.query)
          const tokenOverlap = getTokenOverlap(zr.query, sr.query)

          // Both criteria must be satisfied (AND) to reduce false positives
          if (distance <= 2 && tokenOverlap >= 0.5) {
            const fingerprint = fnv1aHash(`synonym:${[zr.query, sr.query].sort().join('|')}`)
            const exists = await this.checkFingerprint(fingerprint)
            if (exists) continue

            await this.insertRecommendation({
              id: crypto.randomUUID().replace(/-/g, ''),
              category: 'synonym',
              title: `Synonym: "${zr.query}" \u2192 "${sr.query}"`,
              description: `"${zr.query}" returned 0 results ${zr.cnt} times, but "${sr.query}" returns ~${Math.round(sr.avg_results)} results. Adding a synonym group could help users find content.`,
              supporting_data: {
                failed_query: zr.query,
                failed_count: zr.cnt,
                success_query: sr.query,
                success_count: sr.cnt,
                avg_results: Math.round(sr.avg_results),
                levenshtein: distance,
                token_overlap: Math.round(tokenOverlap * 100),
              },
              action_payload: { terms: [zr.query, sr.query] },
              fingerprint,
              run_id: runId,
            })
            count++
            break // One match per zero-result query
          }
        }
      }
    } catch (error) {
      console.error('[Agent] Synonym analysis error:', error)
    }
    return count
  }

  /**
   * Find zero-result queries where removing common prefixes produces a successful query.
   */
  private async analyzeQueryRuleOpportunities(runId: string): Promise<number> {
    let count = 0
    const prefixes = ['how to ', 'what is ', 'where is ', 'how do i ', 'can i ', 'why does ', 'what are ']

    try {
      const thirtyDaysAgo = Math.floor(Date.now() / 1000) - (30 * 24 * 60 * 60)
      const { results: zeroResults } = await this.db
        .prepare(`
          SELECT LOWER(query) as query, COUNT(*) as cnt
          FROM ai_search_history
          WHERE results_count = 0 AND created_at >= ?
          GROUP BY LOWER(query) HAVING COUNT(*) >= 2
          ORDER BY cnt DESC LIMIT 50
        `)
        .bind(thirtyDaysAgo)
        .all<{ query: string; cnt: number }>()

      if (!zeroResults || zeroResults.length === 0) return 0

      for (const zr of zeroResults) {
        for (const prefix of prefixes) {
          if (!zr.query.startsWith(prefix)) continue
          const stripped = zr.query.slice(prefix.length).trim()
          if (stripped.length < 2) continue

          // Check if the stripped query returns results
          const successRow = await this.db
            .prepare(`
              SELECT COUNT(*) as cnt, AVG(results_count) as avg_results
              FROM ai_search_history
              WHERE LOWER(query) = ? AND results_count > 0 AND created_at >= ?
            `)
            .bind(stripped, thirtyDaysAgo)
            .first<{ cnt: number; avg_results: number }>()

          if (!successRow || successRow.cnt === 0) continue

          const fingerprint = fnv1aHash(`query_rule:${zr.query}|${stripped}`)
          const exists = await this.checkFingerprint(fingerprint)
          if (exists) continue

          await this.insertRecommendation({
            id: crypto.randomUUID().replace(/-/g, ''),
            category: 'query_rule',
            title: `Rule: "${zr.query}" \u2192 "${stripped}"`,
            description: `"${zr.query}" returns 0 results, but removing "${prefix.trim()}" yields "${stripped}" which returns ~${Math.round(successRow.avg_results)} results.`,
            supporting_data: {
              original_query: zr.query,
              stripped_query: stripped,
              prefix_removed: prefix.trim(),
              zero_result_count: zr.cnt,
              success_count: successRow.cnt,
              avg_results: Math.round(successRow.avg_results),
            },
            action_payload: {
              match_pattern: zr.query,
              match_type: 'exact',
              substitute_query: stripped,
            },
            fingerprint,
            run_id: runId,
          })
          count++
          break // One rule per zero-result query
        }
      }
    } catch (error) {
      console.error('[Agent] Query rule analysis error:', error)
    }
    return count
  }

  /**
   * Find queries with >= 5 searches but < 10% CTR in 30 days.
   */
  private async analyzeLowCtrQueries(runId: string): Promise<number> {
    let count = 0
    try {
      const thirtyDaysAgo = Math.floor(Date.now() / 1000) - (30 * 24 * 60 * 60)
      const { results: rows } = await this.db
        .prepare(`
          SELECT
            LOWER(h.query) as query,
            COUNT(DISTINCT h.id) as search_count,
            COUNT(DISTINCT c.id) as click_count,
            AVG(h.results_count) as avg_results
          FROM ai_search_history h
          LEFT JOIN ai_search_clicks c ON c.search_id = CAST(h.id AS TEXT) AND c.created_at >= datetime(?, 'unixepoch')
          WHERE h.created_at >= ? AND h.results_count > 0
          GROUP BY LOWER(h.query)
          HAVING COUNT(DISTINCT h.id) >= 5
            AND (CAST(COUNT(DISTINCT c.id) AS REAL) / COUNT(DISTINCT h.id)) < 0.1
          ORDER BY COUNT(DISTINCT h.id) DESC
          LIMIT 20
        `)
        .bind(thirtyDaysAgo, thirtyDaysAgo)
        .all<{ query: string; search_count: number; click_count: number; avg_results: number }>()

      if (!rows || rows.length === 0) return 0

      for (const row of rows) {
        const ctr = row.search_count > 0 ? (row.click_count / row.search_count) * 100 : 0
        const fingerprint = fnv1aHash(`low_ctr:${row.query}`)
        const exists = await this.checkFingerprint(fingerprint)
        if (exists) continue

        await this.insertRecommendation({
          id: crypto.randomUUID().replace(/-/g, ''),
          category: 'low_ctr',
          title: `Low CTR: "${row.query}"`,
          description: `"${row.query}" has been searched ${row.search_count} times with ${row.click_count} clicks (${ctr.toFixed(1)}% CTR). Results may not match user intent.`,
          supporting_data: {
            query: row.query,
            search_count: row.search_count,
            click_count: row.click_count,
            ctr: Math.round(ctr * 10) / 10,
            avg_results: Math.round(row.avg_results),
          },
          action_payload: null,
          fingerprint,
          run_id: runId,
        })
        count++
      }
    } catch (error) {
      console.error('[Agent] Low CTR analysis error:', error)
    }
    return count
  }

  /**
   * Find enabled facets with 0 clicks in 30 days.
   */
  private async analyzeUnusedFacets(runId: string): Promise<number> {
    let count = 0
    try {
      // Get facet config from settings
      const settingsRow = await this.db
        .prepare("SELECT value FROM ai_search_settings WHERE key = 'settings' LIMIT 1")
        .first<{ value: string }>()

      if (!settingsRow) return 0
      const settings = JSON.parse(settingsRow.value)
      const facetConfig: Array<{ field: string; name: string; enabled: boolean }> = settings.facet_config || []
      const enabledFacets = facetConfig.filter(f => f.enabled)
      if (enabledFacets.length === 0) return 0

      // Get facets with clicks in last 30 days
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
        .toISOString().replace('T', ' ').replace('Z', '').slice(0, 19)
      const { results: clickedFacets } = await this.db
        .prepare(`
          SELECT DISTINCT facet_field
          FROM ai_search_facet_clicks
          WHERE created_at >= ?
        `)
        .bind(thirtyDaysAgo)
        .all<{ facet_field: string }>()

      const clickedSet = new Set((clickedFacets || []).map(r => r.facet_field))

      for (const facet of enabledFacets) {
        if (clickedSet.has(facet.field)) continue

        const fingerprint = fnv1aHash(`unused_facet:${facet.field}`)
        const exists = await this.checkFingerprint(fingerprint)
        if (exists) continue

        await this.insertRecommendation({
          id: crypto.randomUUID().replace(/-/g, ''),
          category: 'unused_facet',
          title: `Unused facet: "${facet.name}"`,
          description: `The "${facet.name}" facet (${facet.field}) is enabled but has received 0 clicks in the last 30 days. Consider disabling it to simplify the UI.`,
          supporting_data: {
            facet_field: facet.field,
            facet_name: facet.name,
            days_checked: 30,
          },
          action_payload: null,
          fingerprint,
          run_id: runId,
        })
        count++
      }
    } catch (error) {
      console.error('[Agent] Unused facets analysis error:', error)
    }
    return count
  }

  /**
   * Find content clicked from position >= 4 with >= 3 clicks — suggests a ranking boost.
   */
  private async analyzeContentGaps(runId: string): Promise<number> {
    let count = 0
    try {
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
        .toISOString().replace('T', ' ').replace('Z', '').slice(0, 19)
      const { results: rows } = await this.db
        .prepare(`
          SELECT
            clicked_content_id,
            clicked_content_title,
            COUNT(*) as click_count,
            AVG(click_position) as avg_position
          FROM ai_search_clicks
          WHERE click_position >= 4 AND created_at >= ?
          GROUP BY clicked_content_id
          HAVING COUNT(*) >= 3
          ORDER BY click_count DESC
          LIMIT 20
        `)
        .bind(thirtyDaysAgo)
        .all<{ clicked_content_id: string; clicked_content_title: string; click_count: number; avg_position: number }>()

      if (!rows || rows.length === 0) return 0

      for (const row of rows) {
        const fingerprint = fnv1aHash(`content_gap:${row.clicked_content_id}`)
        const exists = await this.checkFingerprint(fingerprint)
        if (exists) continue

        const title = row.clicked_content_title || row.clicked_content_id
        await this.insertRecommendation({
          id: crypto.randomUUID().replace(/-/g, ''),
          category: 'content_gap',
          title: `Ranking gap: "${title}"`,
          description: `"${title}" was clicked ${row.click_count} times from avg position ${row.avg_position.toFixed(1)}. Users are scrolling past other results to find this content — it may deserve a ranking boost.`,
          supporting_data: {
            content_id: row.clicked_content_id,
            content_title: title,
            click_count: row.click_count,
            avg_position: Math.round(row.avg_position * 10) / 10,
          },
          action_payload: null,
          fingerprint,
          run_id: runId,
        })
        count++
      }
    } catch (error) {
      console.error('[Agent] Content gaps analysis error:', error)
    }
    return count
  }

  // =============================================
  // Apply Logic
  // =============================================

  async applyRecommendation(id: string): Promise<{ success: boolean; message: string }> {
    const rec = await this.getById(id)
    if (!rec) return { success: false, message: 'Recommendation not found' }
    if (rec.status !== 'pending') return { success: false, message: `Cannot apply recommendation with status "${rec.status}"` }

    try {
      switch (rec.category) {
        case 'synonym': {
          if (!rec.action_payload?.terms || rec.action_payload.terms.length < 2) {
            return { success: false, message: 'Invalid synonym payload' }
          }
          const synonymService = new SynonymService(this.db)
          await synonymService.create(rec.action_payload.terms, true, {
            synonym_type: rec.action_payload.synonym_type || 'bidirectional',
            source_term: rec.action_payload.source_term || undefined,
          })
          await this.updateStatus(id, 'applied')
          return { success: true, message: `Created synonym group: ${rec.action_payload.terms.join(', ')}` }
        }

        case 'query_rule': {
          if (!rec.action_payload?.match_pattern || !rec.action_payload?.substitute_query) {
            return { success: false, message: 'Invalid query rule payload' }
          }
          const rulesService = new QueryRulesService(this.db)
          await rulesService.create({
            match_pattern: rec.action_payload.match_pattern,
            match_type: rec.action_payload.match_type || 'exact',
            substitute_query: rec.action_payload.substitute_query,
          })
          await this.updateStatus(id, 'applied')
          return { success: true, message: `Created query rule: "${rec.action_payload.match_pattern}" \u2192 "${rec.action_payload.substitute_query}"` }
        }

        case 'low_ctr':
        case 'unused_facet':
        case 'content_gap': {
          // Informational only — mark as applied (admin acknowledged)
          await this.updateStatus(id, 'applied')
          return { success: true, message: 'Recommendation acknowledged' }
        }

        default:
          return { success: false, message: `Unknown category: ${rec.category}` }
      }
    } catch (error) {
      return { success: false, message: `Apply failed: ${error instanceof Error ? error.message : String(error)}` }
    }
  }

  // =============================================
  // Helpers
  // =============================================

  private async checkFingerprint(fingerprint: string): Promise<boolean> {
    const row = await this.db
      .prepare("SELECT id FROM ai_search_recommendations WHERE fingerprint = ? AND status IN ('pending', 'applied') LIMIT 1")
      .bind(fingerprint)
      .first()

    return row !== null
  }

  async insertRecommendation(rec: {
    id: string
    category: RecommendationCategory
    title: string
    description: string
    supporting_data: Record<string, any>
    action_payload: Record<string, any> | null
    fingerprint: string
    run_id: string
    import_source?: string | null
  }): Promise<void> {
    await this.db
      .prepare(`
        INSERT INTO ai_search_recommendations (id, category, title, description, supporting_data, action_payload, fingerprint, run_id, import_source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        rec.id,
        rec.category,
        rec.title,
        rec.description,
        JSON.stringify(rec.supporting_data),
        rec.action_payload ? JSON.stringify(rec.action_payload) : null,
        rec.fingerprint,
        rec.run_id,
        rec.import_source || null,
      )
      .run()
  }

  private mapRow(row: Record<string, unknown>): Recommendation {
    return {
      id: row.id as string,
      category: row.category as RecommendationCategory,
      title: row.title as string,
      description: row.description as string,
      supporting_data: typeof row.supporting_data === 'string' ? JSON.parse(row.supporting_data) : (row.supporting_data as Record<string, any>),
      action_payload: row.action_payload ? (typeof row.action_payload === 'string' ? JSON.parse(row.action_payload) : row.action_payload as Record<string, any>) : null,
      status: row.status as RecommendationStatus,
      fingerprint: row.fingerprint as string,
      run_id: row.run_id as string,
      import_source: (row.import_source as string) || null,
      applied_at: row.applied_at as number | null,
      created_at: row.created_at as number,
      updated_at: row.updated_at as number,
    }
  }

  private mapRunRow(row: Record<string, unknown>): AgentRun {
    return {
      id: row.id as string,
      status: row.status as AgentRun['status'],
      recommendations_count: (row.recommendations_count as number) ?? 0,
      duration_ms: row.duration_ms as number | null,
      error_message: row.error_message as string | null,
      created_at: row.created_at as number,
      completed_at: row.completed_at as number | null,
    }
  }
}

// =============================================
// Pure utility functions
// =============================================

/** Common English stopwords — excluded from synonym analysis to avoid noise */
const STOPWORDS = new Set([
  'a', 'an', 'the', 'is', 'it', 'in', 'on', 'at', 'to', 'of', 'and', 'or',
  'for', 'by', 'as', 'be', 'do', 'he', 'she', 'we', 'my', 'me', 'no', 'so',
  'up', 'if', 'am', 'us', 'i', 'not', 'but', 'are', 'was', 'has', 'had',
  'all', 'can', 'her', 'his', 'its', 'may', 'our', 'own', 'too', 'who',
  'did', 'get', 'got', 'him', 'how', 'let', 'new', 'now', 'old', 'out',
  'say', 'she', 'use', 'way', 'why', 'yes', 'yet', 'you',
])

/** FNV-1a hash for deterministic fingerprinting */
export function fnv1aHash(input: string): string {
  let hash = 0x811c9dc5
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i)
    hash = Math.imul(hash, 0x01000193)
  }
  return (hash >>> 0).toString(16).padStart(8, '0')
}

/** Levenshtein edit distance */
function levenshteinDistance(a: string, b: string): number {
  if (a === b) return 0
  if (a.length === 0) return b.length
  if (b.length === 0) return a.length

  // Use two-row optimization for memory efficiency
  let prev: number[] = Array.from({ length: b.length + 1 }, (_, i) => i)
  let curr: number[] = new Array<number>(b.length + 1).fill(0)

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1
      curr[j] = Math.min(
        prev[j]! + 1,      // deletion
        curr[j - 1]! + 1,  // insertion
        prev[j - 1]! + cost // substitution
      )
    }
    ;[prev, curr] = [curr, prev]
  }

  return prev[b.length]!
}

/** Token overlap ratio (Jaccard-style on words) */
function getTokenOverlap(a: string, b: string): number {
  const tokensA = new Set(a.split(/\s+/).filter(Boolean))
  const tokensB = new Set(b.split(/\s+/).filter(Boolean))

  if (tokensA.size === 0 || tokensB.size === 0) return 0

  let intersection = 0
  for (const t of tokensA) {
    if (tokensB.has(t)) intersection++
  }

  const union = new Set([...tokensA, ...tokensB]).size
  return union > 0 ? intersection / union : 0
}
