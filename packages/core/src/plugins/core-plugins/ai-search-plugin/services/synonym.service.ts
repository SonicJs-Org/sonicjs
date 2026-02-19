import type { D1Database } from '@cloudflare/workers-types'
import type { SynonymGroup } from '../types'

type SynonymRow = {
  id: string
  terms: string
  synonym_type: string
  source_term: string | null
  enabled: number
  created_at: number
  updated_at: number
}

/**
 * Synonym Service
 *
 * Manages synonym groups (bidirectional and one-way) and provides query expansion.
 * Bidirectional: all terms in a group are equivalent — searching any one expands to all.
 * One-way: only the source_term triggers expansion to the other terms.
 */
export class SynonymService {
  constructor(private db: D1Database) {}

  // === CRUD ===

  async getAll(): Promise<SynonymGroup[]> {
    try {
      const { results } = await this.db
        .prepare('SELECT id, terms, synonym_type, source_term, enabled, created_at, updated_at FROM ai_search_synonyms ORDER BY created_at DESC')
        .all<SynonymRow>()

      return (results || []).map(this.mapRow)
    } catch {
      return []
    }
  }

  async getById(id: string): Promise<SynonymGroup | null> {
    try {
      const row = await this.db
        .prepare('SELECT id, terms, synonym_type, source_term, enabled, created_at, updated_at FROM ai_search_synonyms WHERE id = ?')
        .bind(id)
        .first<SynonymRow>()

      if (!row) return null
      return this.mapRow(row)
    } catch {
      return null
    }
  }

  async create(
    terms: string[],
    enabled: boolean = true,
    opts?: { synonym_type?: 'bidirectional' | 'one_way'; source_term?: string }
  ): Promise<SynonymGroup> {
    const sanitized = this.sanitizeTerms(terms)
    if (sanitized.length < 2) {
      throw new Error('A synonym group must have at least 2 terms')
    }

    const synonymType = opts?.synonym_type || 'bidirectional'
    const sourceTerm = opts?.source_term?.trim().toLowerCase() || null

    if (synonymType === 'one_way') {
      if (!sourceTerm) {
        throw new Error('One-way synonyms require a source_term (trigger term)')
      }
      if (!sanitized.includes(sourceTerm)) {
        throw new Error('source_term must be one of the terms in the group')
      }
    }

    const id = crypto.randomUUID().replace(/-/g, '')

    await this.db
      .prepare('INSERT INTO ai_search_synonyms (id, terms, synonym_type, source_term, enabled) VALUES (?, ?, ?, ?, ?)')
      .bind(id, JSON.stringify(sanitized), synonymType, synonymType === 'one_way' ? sourceTerm : null, enabled ? 1 : 0)
      .run()

    const created = await this.getById(id)
    if (!created) throw new Error('Failed to create synonym group')
    return created
  }

  async update(id: string, data: {
    terms?: string[]
    enabled?: boolean
    synonym_type?: 'bidirectional' | 'one_way'
    source_term?: string | null
  }): Promise<SynonymGroup | null> {
    const existing = await this.getById(id)
    if (!existing) return null

    const terms = data.terms !== undefined ? this.sanitizeTerms(data.terms) : existing.terms
    if (terms.length < 2) {
      throw new Error('A synonym group must have at least 2 terms')
    }
    const enabled = data.enabled !== undefined ? data.enabled : existing.enabled
    const synonymType = data.synonym_type || existing.synonym_type
    let sourceTerm = data.source_term !== undefined ? data.source_term?.trim().toLowerCase() || null : existing.source_term

    if (synonymType === 'one_way') {
      if (!sourceTerm) {
        throw new Error('One-way synonyms require a source_term (trigger term)')
      }
      if (!terms.includes(sourceTerm)) {
        throw new Error('source_term must be one of the terms in the group')
      }
    } else {
      sourceTerm = null
    }

    await this.db
      .prepare('UPDATE ai_search_synonyms SET terms = ?, synonym_type = ?, source_term = ?, enabled = ?, updated_at = unixepoch() WHERE id = ?')
      .bind(JSON.stringify(terms), synonymType, sourceTerm, enabled ? 1 : 0, id)
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
   * For bidirectional groups: any term in the group triggers expansion to all terms.
   * For one-way groups: only the source_term triggers expansion.
   * Returns deduplicated expanded term list.
   */
  async expandQuery(terms: string[]): Promise<string[]> {
    const groups = await this.getEnabled()
    if (groups.length === 0) return terms

    // Build lookup: lowercase term → Set of all synonym terms it should expand to
    const synonymMap = new Map<string, Set<string>>()
    for (const group of groups) {
      const lowerTerms = group.terms.map(t => t.toLowerCase())

      if (group.synonym_type === 'one_way' && group.source_term) {
        // One-way: only the source_term triggers expansion
        const trigger = group.source_term.toLowerCase()
        if (!synonymMap.has(trigger)) synonymMap.set(trigger, new Set())
        for (const synonym of lowerTerms) {
          synonymMap.get(trigger)!.add(synonym)
        }
        // Do NOT add reverse mappings — that's what makes it one-way
      } else {
        // Bidirectional: all terms map to all terms
        for (const term of lowerTerms) {
          if (!synonymMap.has(term)) synonymMap.set(term, new Set())
          for (const synonym of lowerTerms) {
            synonymMap.get(term)!.add(synonym)
          }
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
        .prepare('SELECT id, terms, synonym_type, source_term, enabled, created_at, updated_at FROM ai_search_synonyms WHERE enabled = 1')
        .all<SynonymRow>()

      return (results || []).map(this.mapRow)
    } catch {
      return []
    }
  }

  private mapRow(row: SynonymRow): SynonymGroup {
    return {
      id: row.id,
      terms: JSON.parse(row.terms),
      synonym_type: (row.synonym_type as 'bidirectional' | 'one_way') || 'bidirectional',
      source_term: row.source_term || null,
      enabled: row.enabled === 1,
      created_at: row.created_at,
      updated_at: row.updated_at,
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
