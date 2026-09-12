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
  mode: 'ai' | 'keyword'
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
  relevance_score?: number // For AI search
  status: string
  created_at: number
  updated_at: number
  author_name?: string
  url?: string
}

export interface SearchResponse {
  results: SearchResult[]
  total: number
  query_time_ms: number
  mode: 'ai' | 'keyword'
  suggestions?: string[] // Autocomplete suggestions
  degraded?: boolean // true when an 'ai' request was served by the lexical (keyword) floor (LA4)
}

export interface SearchHistory {
  id: number
  query: string
  mode: 'ai' | 'keyword'
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
