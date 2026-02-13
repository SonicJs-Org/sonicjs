import type { D1Database } from '@cloudflare/workers-types'
import type { SynonymGroup } from '../types'

/**
 * Synonym Service
 *
 * Manages bidirectional synonym groups and provides query expansion.
 * All terms in a group are equivalent — searching any one expands to all.
 */
export class SynonymService {
  constructor(private db: D1Database) {}

  // === CRUD ===

  async getAll(): Promise<SynonymGroup[]> {
    try {
      const { results } = await this.db
        .prepare('SELECT id, terms, enabled, created_at, updated_at FROM ai_search_synonyms ORDER BY created_at DESC')
        .all<{ id: string; terms: string; enabled: number; created_at: number; updated_at: number }>()

      return (results || []).map(row => ({
        id: row.id,
        terms: JSON.parse(row.terms),
        enabled: row.enabled === 1,
        created_at: row.created_at,
        updated_at: row.updated_at,
      }))
    } catch {
      return []
    }
  }

  async getById(id: string): Promise<SynonymGroup | null> {
    try {
      const row = await this.db
        .prepare('SELECT id, terms, enabled, created_at, updated_at FROM ai_search_synonyms WHERE id = ?')
        .bind(id)
        .first<{ id: string; terms: string; enabled: number; created_at: number; updated_at: number }>()

      if (!row) return null

      return {
        id: row.id,
        terms: JSON.parse(row.terms),
        enabled: row.enabled === 1,
        created_at: row.created_at,
        updated_at: row.updated_at,
      }
    } catch {
      return null
    }
  }

  async create(terms: string[], enabled: boolean = true): Promise<SynonymGroup> {
    const sanitized = this.sanitizeTerms(terms)
    if (sanitized.length < 2) {
      throw new Error('A synonym group must have at least 2 terms')
    }

    const id = crypto.randomUUID().replace(/-/g, '')

    await this.db
      .prepare('INSERT INTO ai_search_synonyms (id, terms, enabled) VALUES (?, ?, ?)')
      .bind(id, JSON.stringify(sanitized), enabled ? 1 : 0)
      .run()

    const created = await this.getById(id)
    if (!created) throw new Error('Failed to create synonym group')
    return created
  }

  async update(id: string, data: { terms?: string[]; enabled?: boolean }): Promise<SynonymGroup | null> {
    const existing = await this.getById(id)
    if (!existing) return null

    const terms = data.terms !== undefined ? this.sanitizeTerms(data.terms) : existing.terms
    if (terms.length < 2) {
      throw new Error('A synonym group must have at least 2 terms')
    }
    const enabled = data.enabled !== undefined ? data.enabled : existing.enabled

    await this.db
      .prepare('UPDATE ai_search_synonyms SET terms = ?, enabled = ?, updated_at = unixepoch() WHERE id = ?')
      .bind(JSON.stringify(terms), enabled ? 1 : 0, id)
      .run()

    return this.getById(id)
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.db
      .prepare('DELETE FROM ai_search_synonyms WHERE id = ?')
      .bind(id)
      .run()

    return (result.meta?.changes ?? 0) > 0
  }

  // === Query Expansion ===

  /**
   * Expand an array of sanitized search terms using enabled synonym groups.
   * For each input term, if it appears in a group, all other terms from
   * that group are added. Returns deduplicated expanded term list.
   */
  async expandQuery(terms: string[]): Promise<string[]> {
    const groups = await this.getEnabled()
    if (groups.length === 0) return terms

    // Build lookup: lowercase term → Set of all synonym terms in its groups
    const synonymMap = new Map<string, Set<string>>()
    for (const group of groups) {
      const lowerTerms = group.terms.map(t => t.toLowerCase())
      for (const term of lowerTerms) {
        if (!synonymMap.has(term)) {
          synonymMap.set(term, new Set())
        }
        for (const synonym of lowerTerms) {
          synonymMap.get(term)!.add(synonym)
        }
      }
    }

    // Expand each input term
    const expanded = new Set<string>()
    for (const term of terms) {
      expanded.add(term.toLowerCase())
      const synonyms = synonymMap.get(term.toLowerCase())
      if (synonyms) {
        for (const syn of synonyms) {
          expanded.add(syn)
        }
      }
    }

    return Array.from(expanded)
  }

  // === Helpers ===

  private async getEnabled(): Promise<SynonymGroup[]> {
    try {
      const { results } = await this.db
        .prepare('SELECT id, terms, enabled, created_at, updated_at FROM ai_search_synonyms WHERE enabled = 1')
        .all<{ id: string; terms: string; enabled: number; created_at: number; updated_at: number }>()

      return (results || []).map(row => ({
        id: row.id,
        terms: JSON.parse(row.terms),
        enabled: row.enabled === 1,
        created_at: row.created_at,
        updated_at: row.updated_at,
      }))
    } catch {
      return []
    }
  }

  /** Sanitize terms: trim, lowercase, deduplicate, remove empties */
  private sanitizeTerms(terms: string[]): string[] {
    const seen = new Set<string>()
    const result: string[] = []
    for (const raw of terms) {
      const term = raw.trim().toLowerCase()
      if (term && !seen.has(term)) {
        seen.add(term)
        result.push(term)
      }
    }
    return result
  }
}
