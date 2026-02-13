/**
 * FacetService — Schema-aware facet discovery and computation
 *
 * Discovers facetable fields from collection JSON schemas,
 * computes facet counts via SQL GROUP BY (full result set),
 * and provides in-memory counting for AI/hybrid modes.
 *
 * Designed as the shared foundation for both manual admin config
 * and the Phase 6 AI Search Quality Agent's facet discovery job.
 */

import type {
  FacetDefinition,
  FacetResult,
  FacetValue,
  DiscoveredField,
  SearchResult,
} from '../types'

// Fields that are never useful as facets
const NON_FACETABLE_FORMATS = new Set(['richtext', 'media', 'date-time', 'slug'])

// Schema field names that shadow built-in facets — skip to avoid duplicates
const BUILTIN_FIELD_NAMES = new Set(['author', 'status'])

export class FacetService {
  constructor(private db: D1Database) {}

  // =============================================
  // Discovery — introspect collection schemas
  // =============================================

  /**
   * Discover facetable fields from all active collection schemas.
   * Returns built-in facets + custom fields classified by type.
   */
  async discoverFields(): Promise<DiscoveredField[]> {
    const discovered: DiscoveredField[] = []

    // Built-in facets (always available)
    discovered.push(
      { field: 'collection_name', title: 'Collection', type: 'builtin', recommended: true, collections: [] },
      { field: 'status', title: 'Status', type: 'builtin', recommended: true, collections: [], enumValues: ['draft', 'published', 'archived'] },
      { field: 'author', title: 'Author', type: 'builtin', recommended: true, collections: [] },
    )

    // Read all active collection schemas
    try {
      const { results } = await this.db
        .prepare(`SELECT id, name, display_name, schema FROM collections WHERE is_active = 1`)
        .all<{ id: string; name: string; display_name: string; schema: string }>()

      if (!results?.length) return discovered

      // Map: fieldPath → { title, type, recommended, collections, enumValues }
      const fieldMap = new Map<string, {
        title: string
        type: 'json_scalar' | 'json_array'
        recommended: boolean
        collections: Array<{ id: string; name: string }>
        enumValues?: string[]
      }>()

      for (const col of results) {
        let schema: any
        try {
          schema = typeof col.schema === 'string' ? JSON.parse(col.schema) : col.schema
        } catch {
          continue
        }

        const properties = schema?.properties
        if (!properties || typeof properties !== 'object') continue

        for (const [fieldName, fieldDef] of Object.entries(properties)) {
          const def = fieldDef as any
          if (!def || typeof def !== 'object') continue

          // Skip fields that shadow built-in facets (e.g. schema "author" vs built-in author)
          if (BUILTIN_FIELD_NAMES.has(fieldName)) continue

          const classification = this.classifyField(fieldName, def)
          if (!classification) continue

          const path = `$.${fieldName}`
          const existing = fieldMap.get(path)
          if (existing) {
            existing.collections.push({ id: col.id, name: col.display_name })
          } else {
            fieldMap.set(path, {
              title: def.title || fieldName,
              type: classification.type,
              recommended: classification.recommended,
              collections: [{ id: col.id, name: col.display_name }],
              enumValues: classification.enumValues,
            })
          }
        }
      }

      // Convert map to DiscoveredField array
      for (const [field, info] of fieldMap) {
        discovered.push({
          field,
          title: info.title,
          type: info.type,
          recommended: info.recommended,
          collections: info.collections,
          enumValues: info.enumValues,
        })
      }
    } catch (error) {
      console.error('[FacetService] Discovery error:', error)
    }

    return discovered
  }

  /**
   * Classify a field definition from collection schema.
   * Returns null if the field is not facetable.
   */
  private classifyField(
    fieldName: string,
    def: any
  ): { type: 'json_scalar' | 'json_array'; recommended: boolean; enumValues?: string[] } | null {
    const fieldType = def.type
    const format = def.format

    // Not facetable: richtext, media, date-time, slug, object, number
    if (format && NON_FACETABLE_FORMATS.has(format)) return null
    if (fieldType === 'object') return null
    if (fieldType === 'number' || fieldType === 'integer') return null

    // Array of strings → json_array, recommended
    if (fieldType === 'array' && def.items?.type === 'string') {
      return { type: 'json_array', recommended: true }
    }

    // String with enum → json_scalar, recommended
    if (fieldType === 'string' && Array.isArray(def.enum) && def.enum.length > 0) {
      return { type: 'json_scalar', recommended: true, enumValues: def.enum }
    }

    // Boolean → json_scalar, recommended
    if (fieldType === 'boolean') {
      return { type: 'json_scalar', recommended: true, enumValues: ['true', 'false'] }
    }

    // Plain string without format → available but not recommended (high cardinality)
    if (fieldType === 'string' && !format) {
      return { type: 'json_scalar', recommended: false }
    }

    return null
  }

  // =============================================
  // Auto-generation — create default config
  // =============================================

  /**
   * Generate default facet config from discovered fields.
   * Only enables recommended fields.
   */
  autoGenerateConfig(discovered: DiscoveredField[]): FacetDefinition[] {
    return discovered
      .filter(d => d.recommended)
      .map((d, i) => ({
        name: d.title,
        field: d.field,
        type: d.type,
        collections: d.collections.map(c => c.id),
        enabled: true,
        source: 'auto' as const,
        position: i,
        sortBy: 'count' as const,
      }))
  }

  // =============================================
  // Computation — SQL GROUP BY (FTS5/keyword)
  // =============================================

  /**
   * Compute facets for FTS5 mode using parallel SQL GROUP BY queries.
   * Counts reflect the full matching result set (not just current page).
   */
  async computeFacetsFts(
    config: FacetDefinition[],
    matchQuery: string,
    collectionIds: string[],
    maxValues: number
  ): Promise<FacetResult[]> {
    const enabled = config.filter(f => f.enabled)
    if (enabled.length === 0 || collectionIds.length === 0) return []

    const collPlaceholders = collectionIds.map(() => '?').join(', ')

    const promises = enabled.map(async (facet): Promise<FacetResult> => {
      const limit = facet.maxValues || maxValues
      try {
        const values = await this.runFtsFacetQuery(facet, matchQuery, collectionIds, collPlaceholders, limit)
        return this.sortFacetValues(facet, values)
      } catch (error) {
        console.error(`[FacetService] Facet query error for ${facet.field}:`, error)
        return { name: facet.name, field: facet.field, values: [] }
      }
    })

    return Promise.all(promises)
  }

  private async runFtsFacetQuery(
    facet: FacetDefinition,
    matchQuery: string,
    collectionIds: string[],
    collPlaceholders: string,
    limit: number
  ): Promise<FacetValue[]> {
    let sql: string
    let params: any[]

    switch (facet.field) {
      case 'collection_name':
        sql = `
          SELECT col.display_name as value, COUNT(*) as count
          FROM content_fts fts
          JOIN content c ON fts.content_id = c.id
          JOIN collections col ON fts.collection_id = col.id
          WHERE content_fts MATCH ?
            AND fts.collection_id IN (${collPlaceholders})
            AND c.status != 'deleted'
          GROUP BY value ORDER BY count DESC LIMIT ?
        `
        params = [matchQuery, ...collectionIds, limit]
        break

      case 'status':
        sql = `
          SELECT c.status as value, COUNT(*) as count
          FROM content_fts fts
          JOIN content c ON fts.content_id = c.id
          WHERE content_fts MATCH ?
            AND fts.collection_id IN (${collPlaceholders})
            AND c.status != 'deleted'
          GROUP BY c.status ORDER BY count DESC LIMIT ?
        `
        params = [matchQuery, ...collectionIds, limit]
        break

      case 'author':
        sql = `
          SELECT COALESCE(u.email, 'Unknown') as value, COUNT(*) as count
          FROM content_fts fts
          JOIN content c ON fts.content_id = c.id
          LEFT JOIN users u ON c.author_id = u.id
          WHERE content_fts MATCH ?
            AND fts.collection_id IN (${collPlaceholders})
            AND c.status != 'deleted'
          GROUP BY value ORDER BY count DESC LIMIT ?
        `
        params = [matchQuery, ...collectionIds, limit]
        break

      default:
        // Custom JSON field
        if (facet.type === 'json_array') {
          const jsonPath = facet.field // e.g. "$.tags"
          sql = `
            SELECT j.value as value, COUNT(*) as count
            FROM content_fts fts
            JOIN content c ON fts.content_id = c.id,
            json_each(json_extract(c.data, '${jsonPath}')) j
            WHERE content_fts MATCH ?
              AND fts.collection_id IN (${collPlaceholders})
              AND c.status != 'deleted'
            GROUP BY j.value ORDER BY count DESC LIMIT ?
          `
        } else {
          const jsonPath = facet.field
          sql = `
            SELECT json_extract(c.data, '${jsonPath}') as value, COUNT(*) as count
            FROM content_fts fts
            JOIN content c ON fts.content_id = c.id
            WHERE content_fts MATCH ?
              AND fts.collection_id IN (${collPlaceholders})
              AND c.status != 'deleted'
              AND json_extract(c.data, '${jsonPath}') IS NOT NULL
            GROUP BY value ORDER BY count DESC LIMIT ?
          `
        }
        params = [matchQuery, ...collectionIds, limit]
    }

    const { results } = await this.db.prepare(sql).bind(...params)
      .all<{ value: string; count: number }>()

    return (results || []).map(r => ({
      value: String(r.value),
      count: r.count,
    }))
  }

  /**
   * Compute facets for keyword mode using parallel SQL GROUP BY queries.
   */
  async computeFacetsKeyword(
    config: FacetDefinition[],
    queryTerm: string,
    collectionIds: string[],
    maxValues: number
  ): Promise<FacetResult[]> {
    const enabled = config.filter(f => f.enabled)
    if (enabled.length === 0 || collectionIds.length === 0) return []

    const collPlaceholders = collectionIds.map(() => '?').join(', ')
    const likeTerm = `%${queryTerm}%`

    const promises = enabled.map(async (facet): Promise<FacetResult> => {
      const limit = facet.maxValues || maxValues
      try {
        const values = await this.runKeywordFacetQuery(facet, likeTerm, collectionIds, collPlaceholders, limit)
        return this.sortFacetValues(facet, values)
      } catch (error) {
        console.error(`[FacetService] Keyword facet error for ${facet.field}:`, error)
        return { name: facet.name, field: facet.field, values: [] }
      }
    })

    return Promise.all(promises)
  }

  private async runKeywordFacetQuery(
    facet: FacetDefinition,
    likeTerm: string,
    collectionIds: string[],
    collPlaceholders: string,
    limit: number
  ): Promise<FacetValue[]> {
    // Base WHERE clause for keyword search
    const baseWhere = `
      c.collection_id IN (${collPlaceholders})
      AND c.status != 'deleted'
      AND (c.title LIKE ? OR c.slug LIKE ? OR c.data LIKE ?)
    `
    const baseParams = [...collectionIds, likeTerm, likeTerm, likeTerm]

    let sql: string
    let params: any[]

    switch (facet.field) {
      case 'collection_name':
        sql = `
          SELECT col.display_name as value, COUNT(*) as count
          FROM content c
          JOIN collections col ON c.collection_id = col.id
          WHERE ${baseWhere}
          GROUP BY value ORDER BY count DESC LIMIT ?
        `
        params = [...baseParams, limit]
        break

      case 'status':
        sql = `
          SELECT c.status as value, COUNT(*) as count
          FROM content c
          WHERE ${baseWhere}
          GROUP BY c.status ORDER BY count DESC LIMIT ?
        `
        params = [...baseParams, limit]
        break

      case 'author':
        sql = `
          SELECT COALESCE(u.email, 'Unknown') as value, COUNT(*) as count
          FROM content c
          LEFT JOIN users u ON c.author_id = u.id
          WHERE ${baseWhere}
          GROUP BY value ORDER BY count DESC LIMIT ?
        `
        params = [...baseParams, limit]
        break

      default:
        if (facet.type === 'json_array') {
          sql = `
            SELECT j.value as value, COUNT(*) as count
            FROM content c,
            json_each(json_extract(c.data, '${facet.field}')) j
            WHERE ${baseWhere}
            GROUP BY j.value ORDER BY count DESC LIMIT ?
          `
        } else {
          sql = `
            SELECT json_extract(c.data, '${facet.field}') as value, COUNT(*) as count
            FROM content c
            WHERE ${baseWhere}
              AND json_extract(c.data, '${facet.field}') IS NOT NULL
            GROUP BY value ORDER BY count DESC LIMIT ?
          `
        }
        params = [...baseParams, limit]
    }

    const { results } = await this.db.prepare(sql).bind(...params)
      .all<{ value: string; count: number }>()

    return (results || []).map(r => ({
      value: String(r.value),
      count: r.count,
    }))
  }

  // =============================================
  // Computation — in-memory (AI/hybrid modes)
  // =============================================

  /**
   * Compute facets from a set of content IDs by fetching their data
   * and counting in-memory. Used for AI and hybrid modes where
   * Vectorize returns max 50 results.
   */
  async computeFacetsFromIds(
    config: FacetDefinition[],
    contentIds: string[],
    maxValues: number
  ): Promise<FacetResult[]> {
    const enabled = config.filter(f => f.enabled)
    if (enabled.length === 0 || contentIds.length === 0) return []

    // Fetch content data for all result IDs
    const placeholders = contentIds.map(() => '?').join(', ')
    const { results: rows } = await this.db
      .prepare(`
        SELECT c.id, c.data, c.status, c.collection_id, c.author_id,
               col.display_name as collection_name,
               u.email as author_email
        FROM content c
        JOIN collections col ON c.collection_id = col.id
        LEFT JOIN users u ON c.author_id = u.id
        WHERE c.id IN (${placeholders})
      `)
      .bind(...contentIds)
      .all<{
        id: string; data: string; status: string; collection_id: string
        collection_name: string; author_email: string | null
      }>()

    if (!rows?.length) {
      return enabled.map(f => ({ name: f.name, field: f.field, values: [] }))
    }

    return enabled.map(facet => {
      const limit = facet.maxValues || maxValues
      const counts = new Map<string, number>()

      for (const row of rows) {
        const values = this.extractFacetValues(facet, row)
        for (const v of values) {
          counts.set(v, (counts.get(v) || 0) + 1)
        }
      }

      let facetValues: FacetValue[] = Array.from(counts.entries())
        .map(([value, count]) => ({ value, count }))

      facetValues = this.sortValues(facet, facetValues).slice(0, limit)

      return { name: facet.name, field: facet.field, values: facetValues }
    })
  }

  /**
   * Also supports counting from already-loaded SearchResult array
   * (used by InstantSearch adapter when facets come from search response).
   */
  computeFacetsFromResults(
    config: FacetDefinition[],
    results: SearchResult[],
    maxValues: number
  ): FacetResult[] {
    const enabled = config.filter(f => f.enabled)
    if (enabled.length === 0 || results.length === 0) {
      return enabled.map(f => ({ name: f.name, field: f.field, values: [] }))
    }

    return enabled.map(facet => {
      const limit = facet.maxValues || maxValues
      const counts = new Map<string, number>()

      for (const r of results) {
        let value: string | undefined
        switch (facet.field) {
          case 'collection_name': value = r.collection_name; break
          case 'status': value = r.status; break
          case 'author': value = r.author_name; break
          default: break // Custom JSON fields not available on SearchResult
        }
        if (value) counts.set(value, (counts.get(value) || 0) + 1)
      }

      let facetValues = Array.from(counts.entries())
        .map(([value, count]) => ({ value, count }))
      facetValues = this.sortValues(facet, facetValues).slice(0, limit)

      return { name: facet.name, field: facet.field, values: facetValues }
    })
  }

  // =============================================
  // Helpers
  // =============================================

  private extractFacetValues(
    facet: FacetDefinition,
    row: { data: string; status: string; collection_name: string; author_email: string | null }
  ): string[] {
    switch (facet.field) {
      case 'collection_name': return [row.collection_name]
      case 'status': return [row.status]
      case 'author': return [row.author_email || 'Unknown']
      default: {
        // Extract from JSON data
        try {
          const parsed = typeof row.data === 'string' ? JSON.parse(row.data) : row.data
          // Strip the "$." prefix to get the field name
          const fieldName = facet.field.startsWith('$.') ? facet.field.slice(2) : facet.field
          const val = parsed[fieldName]

          if (val == null) return []
          if (facet.type === 'json_array' && Array.isArray(val)) {
            return val.filter((v: any) => typeof v === 'string')
          }
          return [String(val)]
        } catch {
          return []
        }
      }
    }
  }

  private sortFacetValues(facet: FacetDefinition, values: FacetValue[]): FacetResult {
    return {
      name: facet.name,
      field: facet.field,
      values: this.sortValues(facet, values),
    }
  }

  private sortValues(facet: FacetDefinition, values: FacetValue[]): FacetValue[] {
    if (facet.sortBy === 'alpha') {
      return values.sort((a, b) => a.value.localeCompare(b.value))
    }
    return values.sort((a, b) => b.count - a.count)
  }

  /**
   * Sanitize a query string for FTS5 MATCH syntax.
   * Mirrors the logic in FTS5Service.sanitizeFTS5Query so facet GROUP BY
   * queries use the same MATCH expression as the main search.
   */
  static sanitizeFTS5Query(query: string): string {
    if (!query || typeof query !== 'string') return '""'

    let sanitized = query
      .replace(/-/g, ' ')
      .replace(/[^a-zA-Z0-9\s]/g, '')
      .replace(/\s+/g, ' ')
      .trim()
      .toLowerCase()

    const stopWords = new Set([
      'a','an','the','is','are','was','were','be','to','of','in','on','at',
      'by','or','and','not','for','it','as','do','if','no','so','up','but',
      'its','has','had','near',
    ])
    const terms = sanitized.split(/\s+/).filter(t => t.length > 1 && !stopWords.has(t))

    if (terms.length === 0) return '""'
    if (terms.length === 1) return `${terms[0]}*`
    return terms.join(' OR ')
  }
}
