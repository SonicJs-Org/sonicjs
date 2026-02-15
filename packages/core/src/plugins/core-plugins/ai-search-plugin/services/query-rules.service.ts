import type { D1Database } from '@cloudflare/workers-types'
import type { QueryRule } from '../types'

/**
 * Query Rules Service
 *
 * Deterministic pre-dispatch query substitution: "if user searches X, replace with Y".
 * Rules are checked priority DESC, first match wins, before any search mode dispatch.
 */
export class QueryRulesService {
  constructor(private db: D1Database) {}

  // === CRUD ===

  async getAll(): Promise<QueryRule[]> {
    try {
      const { results } = await this.db
        .prepare('SELECT id, match_pattern, match_type, substitute_query, enabled, priority, created_at, updated_at FROM ai_search_query_rules ORDER BY priority DESC, created_at DESC')
        .all<{ id: string; match_pattern: string; match_type: string; substitute_query: string; enabled: number; priority: number; created_at: number; updated_at: number }>()

      return (results || []).map(row => ({
        id: row.id,
        match_pattern: row.match_pattern,
        match_type: row.match_type as 'exact' | 'prefix',
        substitute_query: row.substitute_query,
        enabled: row.enabled === 1,
        priority: row.priority,
        created_at: row.created_at,
        updated_at: row.updated_at,
      }))
    } catch {
      return []
    }
  }

  async getById(id: string): Promise<QueryRule | null> {
    try {
      const row = await this.db
        .prepare('SELECT id, match_pattern, match_type, substitute_query, enabled, priority, created_at, updated_at FROM ai_search_query_rules WHERE id = ?')
        .bind(id)
        .first<{ id: string; match_pattern: string; match_type: string; substitute_query: string; enabled: number; priority: number; created_at: number; updated_at: number }>()

      if (!row) return null

      return {
        id: row.id,
        match_pattern: row.match_pattern,
        match_type: row.match_type as 'exact' | 'prefix',
        substitute_query: row.substitute_query,
        enabled: row.enabled === 1,
        priority: row.priority,
        created_at: row.created_at,
        updated_at: row.updated_at,
      }
    } catch {
      return null
    }
  }

  async create(data: {
    match_pattern: string
    match_type?: 'exact' | 'prefix'
    substitute_query: string
    enabled?: boolean
    priority?: number
  }): Promise<QueryRule> {
    const pattern = data.match_pattern.trim()
    const substitute = data.substitute_query.trim()
    if (!pattern) throw new Error('match_pattern is required')
    if (!substitute) throw new Error('substitute_query is required')

    const id = crypto.randomUUID().replace(/-/g, '')
    const matchType = data.match_type || 'exact'
    const enabled = data.enabled !== false
    const priority = data.priority ?? 0

    await this.db
      .prepare('INSERT INTO ai_search_query_rules (id, match_pattern, match_type, substitute_query, enabled, priority) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(id, pattern, matchType, substitute, enabled ? 1 : 0, priority)
      .run()

    const created = await this.getById(id)
    if (!created) throw new Error('Failed to create query rule')
    return created
  }

  async update(id: string, data: {
    match_pattern?: string
    match_type?: 'exact' | 'prefix'
    substitute_query?: string
    enabled?: boolean
    priority?: number
  }): Promise<QueryRule | null> {
    const existing = await this.getById(id)
    if (!existing) return null

    const pattern = data.match_pattern !== undefined ? data.match_pattern.trim() : existing.match_pattern
    const matchType = data.match_type !== undefined ? data.match_type : existing.match_type
    const substitute = data.substitute_query !== undefined ? data.substitute_query.trim() : existing.substitute_query
    const enabled = data.enabled !== undefined ? data.enabled : existing.enabled
    const priority = data.priority !== undefined ? data.priority : existing.priority

    if (!pattern) throw new Error('match_pattern cannot be empty')
    if (!substitute) throw new Error('substitute_query cannot be empty')

    await this.db
      .prepare('UPDATE ai_search_query_rules SET match_pattern = ?, match_type = ?, substitute_query = ?, enabled = ?, priority = ?, updated_at = unixepoch() WHERE id = ?')
      .bind(pattern, matchType, substitute, enabled ? 1 : 0, priority, id)
      .run()

    return this.getById(id)
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.db
      .prepare('DELETE FROM ai_search_query_rules WHERE id = ?')
      .bind(id)
      .run()

    return (result.meta?.changes ?? 0) > 0
  }

  // === Query Substitution ===

  /**
   * Apply substitution rules to a query string.
   * Loads enabled rules (priority DESC), first match wins.
   * - Exact: LOWER(query) === LOWER(pattern)
   * - Prefix: LOWER(query).startsWith(LOWER(pattern)) — preserves suffix
   * Returns the (possibly modified) query plus metadata.
   */
  async applyRules(query: string): Promise<{ query: string; ruleId?: string; originalQuery?: string }> {
    try {
      const rules = await this.getEnabled()
      if (rules.length === 0) return { query }

      const queryLower = query.toLowerCase().trim()

      for (const rule of rules) {
        const patternLower = rule.match_pattern.toLowerCase().trim()

        if (rule.match_type === 'exact') {
          if (queryLower === patternLower) {
            return {
              query: rule.substitute_query,
              ruleId: rule.id,
              originalQuery: query,
            }
          }
        } else if (rule.match_type === 'prefix') {
          if (queryLower.startsWith(patternLower)) {
            // Preserve suffix: "docs api" + rule "docs"→"documentation" = "documentation api"
            const suffix = query.substring(rule.match_pattern.trim().length)
            return {
              query: rule.substitute_query + suffix,
              ruleId: rule.id,
              originalQuery: query,
            }
          }
        }
      }

      return { query }
    } catch (error) {
      console.warn('[QueryRulesService] applyRules error (returning original query):', error)
      return { query }
    }
  }

  // === Helpers ===

  private async getEnabled(): Promise<QueryRule[]> {
    try {
      const { results } = await this.db
        .prepare('SELECT id, match_pattern, match_type, substitute_query, enabled, priority, created_at, updated_at FROM ai_search_query_rules WHERE enabled = 1 ORDER BY priority DESC')
        .all<{ id: string; match_pattern: string; match_type: string; substitute_query: string; enabled: number; priority: number; created_at: number; updated_at: number }>()

      return (results || []).map(row => ({
        id: row.id,
        match_pattern: row.match_pattern,
        match_type: row.match_type as 'exact' | 'prefix',
        substitute_query: row.substitute_query,
        enabled: row.enabled === 1,
        priority: row.priority,
        created_at: row.created_at,
        updated_at: row.updated_at,
      }))
    } catch {
      return []
    }
  }
}
