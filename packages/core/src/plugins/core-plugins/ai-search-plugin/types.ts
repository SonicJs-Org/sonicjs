/**
 * AI Search Plugin Types
 */

export interface AISearchSettings {
  id?: number
  enabled: boolean
  ai_mode_enabled: boolean
  selected_collections: string[] // Collection IDs to index (TEXT/UUID)
  dismissed_collections: string[] // Collection IDs user dismissed (TEXT/UUID)
  autocomplete_enabled: boolean
  cache_duration: number // hours
  results_limit: number
  index_media: boolean
  index_status?: Record<string, IndexStatus> // Collection ID -> status
  last_indexed_at?: number
  created_at?: number
  updated_at?: number
  // Phase 2: Hybrid search settings
  query_rewriting_enabled?: boolean // Off by default, adds ~100-300ms latency
  reranking_enabled?: boolean // On by default, adds ~50-150ms latency
  // Phase 2: FTS5 field weight tuning (BM25 boosting)
  fts5_title_boost?: number // Default: 5.0
  fts5_slug_boost?: number  // Default: 2.0
  fts5_body_boost?: number  // Default: 1.0
  // Phase 2C: Query Synonyms
  query_synonyms_enabled?: boolean // Default: true
}

export interface IndexStatus {
  collection_id: string // Collection ID (TEXT/UUID)
  collection_name: string
  total_items: number
  indexed_items: number
  last_sync_at?: number
  status: 'pending' | 'indexing' | 'completed' | 'error'
  error_message?: string
}

export interface SearchQuery {
  query: string
  mode: 'ai' | 'keyword' | 'fts5' | 'hybrid'
  filters?: SearchFilters
  limit?: number
  offset?: number
}

export interface SearchFilters {
  collections?: string[] // Collection IDs to search (TEXT/UUID)
  dateRange?: {
    start: Date
    end: Date
    field?: 'created_at' | 'updated_at'
  }
  status?: string[] // draft, published, archived, etc.
  tags?: string[]
  author?: string // author_id (TEXT/UUID)
  custom?: Record<string, any> // Custom metadata filters
}

export interface SearchResult {
  id: string
  title: string
  slug: string
  collection_id: string // Collection ID (TEXT/UUID)
  collection_name: string
  snippet?: string
  relevance_score?: number // For AI and FTS5 search
  status: string
  created_at: number
  updated_at: number
  author_name?: string
  url?: string
  // FTS5-specific fields
  highlights?: {
    title?: string  // Full title with <mark> tags around matches
    body?: string   // Body snippet with <mark> tags around matches
  }
  bm25_score?: number // Raw BM25 score (positive, higher = better match)
  // Phase 2: Hybrid search fields
  rrf_score?: number // Reciprocal Rank Fusion score (internal sorting)
  rerank_score?: number // Cross-encoder reranking score
  pipeline_score?: number // Composite ranking pipeline score [0, 1]
}

export interface SearchResponse {
  results: SearchResult[]
  total: number
  query_time_ms: number
  mode: 'ai' | 'keyword' | 'fts5' | 'hybrid'
  search_id?: string // ID linking to ai_search_history row for click tracking
  suggestions?: string[] // Autocomplete suggestions
}

export interface SearchHistory {
  id: number
  query: string
  mode: 'ai' | 'keyword' | 'fts5' | 'hybrid'
  results_count: number
  user_id?: number
  created_at: number
}

export interface CollectionInfo {
  id: string // Collection ID (TEXT/UUID)
  name: string
  display_name: string
  description?: string
  item_count?: number
  is_indexed: boolean
  is_dismissed: boolean
  is_new?: boolean
}

export interface NewCollectionNotification {
  collection: CollectionInfo
  message: string
}

/** Configuration for a single ranking pipeline stage */
export interface RankingStage {
  type: 'exactMatch' | 'bm25' | 'semantic' | 'recency' | 'popularity' | 'custom'
  weight: number      // 0-10, step 0.1
  enabled: boolean
  config?: Record<string, any>  // Stage-specific (e.g. recency half_life_days)
}

/** A bidirectional synonym group — searching any term expands to all terms */
export interface SynonymGroup {
  id: string
  terms: string[]
  enabled: boolean
  created_at: number
  updated_at: number
}

/** Default pipeline — used when no config exists in DB */
export const DEFAULT_RANKING_PIPELINE: RankingStage[] = [
  { type: 'exactMatch', weight: 10, enabled: true },
  { type: 'bm25',       weight: 5,  enabled: true },
  { type: 'semantic',    weight: 3,  enabled: true },
  { type: 'recency',     weight: 1,  enabled: true,  config: { half_life_days: 30 } },
  { type: 'popularity',  weight: 0,  enabled: false },
  { type: 'custom',      weight: 0,  enabled: false },
]

// ==========================================
// InstantSearch.js Protocol Types (Algolia-compatible)
// ==========================================

export interface InstantSearchRequest {
  indexName: string
  params?: InstantSearchParams
}

export interface InstantSearchParams {
  query?: string
  page?: number
  hitsPerPage?: number
  facets?: string[]
  filters?: string
  highlightPreTag?: string
  highlightPostTag?: string
  attributesToRetrieve?: string[]
  attributesToHighlight?: string[]
  attributesToSnippet?: string[]
}

export interface InstantSearchHit {
  objectID: string
  [key: string]: any
  // eslint-disable-next-line @typescript-eslint/naming-convention -- Algolia protocol field name
  _highlightResult?: Record<string, {
    value: string
    matchLevel: 'none' | 'partial' | 'full'
    matchedWords?: string[]
  }>
  // eslint-disable-next-line @typescript-eslint/naming-convention -- Algolia protocol field name
  _snippetResult?: Record<string, {
    value: string
    matchLevel: 'none' | 'partial' | 'full'
  }>
}

export interface InstantSearchResult {
  hits: InstantSearchHit[]
  nbHits: number
  page: number
  nbPages: number
  hitsPerPage: number
  processingTimeMS: number
  query: string
  params: string
  exhaustiveNbHits?: boolean
  facets?: Record<string, Record<string, number>>
  index?: string
}

export interface InstantSearchMultiResponse {
  results: InstantSearchResult[]
}
