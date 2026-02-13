import type { D1Database } from '@cloudflare/workers-types'
import type {
  AISearchSettings,
  InstantSearchHit,
  InstantSearchParams,
  InstantSearchRequest,
  InstantSearchResult,
  SearchQuery,
  SearchResponse,
  SearchResult,
} from '../types'

/**
 * InstantSearch Adapter Service
 *
 * Translates between Algolia's InstantSearch protocol and SonicJS search API.
 * Enables drop-in compatibility for any InstantSearch.js / React / Vue frontend.
 */
export class InstantSearchAdapter {
  private collectionCache = new Map<string, string[]>()

  constructor(private db: D1Database) {}

  /**
   * Convert an InstantSearch request to a SonicJS SearchQuery
   */
  async toSonicQuery(
    request: InstantSearchRequest,
    settings: AISearchSettings
  ): Promise<SearchQuery> {
    const params = request.params || {}
    const page = params.page ?? 0
    const hitsPerPage = Math.min(params.hitsPerPage ?? 20, 200)

    const collections = await this.resolveCollections(request.indexName)
    const mode = this.determineSearchMode(settings)

    return {
      query: params.query || '',
      mode,
      limit: hitsPerPage,
      offset: page * hitsPerPage,
      filters: {
        collections: collections.length > 0 ? collections : undefined,
        status: this.parseStatusFilter(params.filters),
      },
    }
  }

  /**
   * Convert a SonicJS SearchResponse to an InstantSearch result
   */
  toInstantSearchResult(
    response: SearchResponse,
    request: InstantSearchRequest,
    queryTime: number
  ): InstantSearchResult {
    const params = request.params || {}
    const page = params.page ?? 0
    const hitsPerPage = Math.min(params.hitsPerPage ?? 20, 200)

    const hits = response.results.map((r) => this.toHit(r, params))
    const nbPages = hitsPerPage > 0 ? Math.ceil(response.total / hitsPerPage) : 0
    const facets = this.computeFacets(response.results, params.facets)

    return {
      hits,
      nbHits: response.total,
      page,
      nbPages,
      hitsPerPage,
      processingTimeMS: queryTime,
      query: params.query || '',
      params: this.buildParamsString(params),
      exhaustiveNbHits: true,
      ...(Object.keys(facets).length > 0 ? { facets } : {}),
      index: request.indexName,
    }
  }

  // --------------------------------------------------
  // Private helpers
  // --------------------------------------------------

  private toHit(result: SearchResult, params: InstantSearchParams): InstantSearchHit {
    const pre = params.highlightPreTag || '<em>'
    const post = params.highlightPostTag || '</em>'

    const hit: InstantSearchHit = {
      objectID: result.id,
      title: result.title,
      slug: result.slug,
      collection_id: result.collection_id,
      collection_name: result.collection_name,
      status: result.status,
      created_at: result.created_at,
      updated_at: result.updated_at,
      ...(result.author_name ? { author_name: result.author_name } : {}),
      ...(result.url ? { url: result.url } : {}),
      ...(result.relevance_score != null ? { relevance_score: result.relevance_score } : {}),
    }

    // _highlightResult
    if (result.highlights) {
      const hr: Record<string, { value: string; matchLevel: 'none' | 'partial' | 'full'; matchedWords?: string[] }> = {}
      if (result.highlights.title) {
        hr.title = {
          value: this.convertTags(result.highlights.title, pre, post),
          matchLevel: this.matchLevel(result.highlights.title),
        }
      }
      if (result.highlights.body) {
        hr.body = {
          value: this.convertTags(result.highlights.body, pre, post),
          matchLevel: this.matchLevel(result.highlights.body),
        }
      }
      if (Object.keys(hr).length > 0) {
        hit._highlightResult = hr
      }
    }

    // _snippetResult
    if (result.snippet) {
      hit._snippetResult = {
        body: {
          value: this.convertTags(result.snippet, pre, post),
          matchLevel: this.matchLevel(result.snippet),
        },
      }
    }

    return hit
  }

  /**
   * Resolve collection name(s) to IDs.
   * "*" / "all" / "" → empty array (search all indexed collections).
   */
  private async resolveCollections(indexName: string): Promise<string[]> {
    if (!indexName || indexName === '*' || indexName === 'all') {
      return []
    }

    // Check cache first (valid for the lifetime of this request)
    const cached = this.collectionCache.get(indexName)
    if (cached) return cached

    try {
      const row = await this.db
        .prepare('SELECT id FROM collections WHERE name = ? AND is_active = 1 LIMIT 1')
        .bind(indexName)
        .first<{ id: string }>()

      const ids = row?.id ? [String(row.id)] : []
      this.collectionCache.set(indexName, ids)
      return ids
    } catch {
      return []
    }
  }

  private determineSearchMode(settings: AISearchSettings): SearchQuery['mode'] {
    if (settings.ai_mode_enabled) return 'hybrid'
    return 'fts5'
  }

  /**
   * Minimal Algolia filter parser. MVP supports:
   *   status:published   status:'draft'   status:"archived"
   */
  private parseStatusFilter(filters?: string): string[] | undefined {
    if (!filters) return undefined
    const m = filters.match(/status\s*:\s*['"]?(\w+)['"]?/i)
    return m?.[1] ? [m[1]] : undefined
  }

  /**
   * Compute facet counts from the current result page.
   * MVP: collection_name and status only.
   */
  private computeFacets(
    results: SearchResult[],
    requested?: string[]
  ): Record<string, Record<string, number>> {
    if (!requested || requested.length === 0) return {}
    const facets: Record<string, Record<string, number>> = {}

    for (const name of requested) {
      if (name === 'collection_name') {
        const counts: Record<string, number> = {}
        for (const r of results) {
          counts[r.collection_name] = (counts[r.collection_name] || 0) + 1
        }
        facets.collection_name = counts
      } else if (name === 'status') {
        const counts: Record<string, number> = {}
        for (const r of results) {
          counts[r.status] = (counts[r.status] || 0) + 1
        }
        facets.status = counts
      }
    }

    return facets
  }

  /** Replace <mark>...</mark> with the requested highlight tags. */
  private convertTags(text: string, open: string, close: string): string {
    return text.replace(/<mark>/g, open).replace(/<\/mark>/g, close)
  }

  /** Detect Algolia match level from presence of <mark> tags in the source text. */
  private matchLevel(text: string): 'none' | 'partial' | 'full' {
    if (!text.includes('<mark>')) return 'none'
    const plain = text.replace(/<\/?mark>/g, '')
    const highlighted = (text.match(/<mark>([\s\S]*?)<\/mark>/g) || [])
      .map((m) => m.replace(/<\/?mark>/g, ''))
      .join('')
    return highlighted.length / Math.max(plain.length, 1) > 0.5 ? 'full' : 'partial'
  }

  private buildParamsString(params: InstantSearchParams): string {
    const parts: string[] = []
    if (params.query != null) parts.push(`query=${encodeURIComponent(params.query)}`)
    if (params.page != null) parts.push(`page=${params.page}`)
    if (params.hitsPerPage != null) parts.push(`hitsPerPage=${params.hitsPerPage}`)
    if (params.facets) parts.push(`facets=${encodeURIComponent(JSON.stringify(params.facets))}`)
    if (params.filters) parts.push(`filters=${encodeURIComponent(params.filters)}`)
    return parts.join('&')
  }
}
