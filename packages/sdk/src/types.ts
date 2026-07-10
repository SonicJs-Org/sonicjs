// Content API — timestamps in milliseconds, offset pagination
export interface ContentListMeta {
  count: number
  timestamp: string
  filter?: unknown
  cache?: unknown
}
export interface ListResponse<T> {
  data: T[]
  meta: ContentListMeta
}
export interface ItemResponse<T> {
  data: T
}

// Documents API — timestamps in seconds, keyset pagination
export interface KeysetCursor {
  updatedAt: number
  id: string
}
export interface DocumentsPage<T> {
  data: T[]
  nextCursor: KeysetCursor | null
}

export interface ContentRecord {
  id: string
  title: string
  slug: string
  status: 'draft' | 'published' | 'archived'
  collectionId: string
  data: Record<string, unknown>
  created_at: number // ms
  updated_at: number // ms
}

export interface DocumentRow {
  id: string
  rootId: string
  typeId: string
  title: string | null
  slug: string | null
  path: string | null
  locale: string
  publishedAt: number // seconds
  updatedAt: number // seconds
  data: Record<string, unknown>
}

export interface MediaAsset {
  id: string
  filename: string
  originalName: string
  mimeType: string
  size: number
  publicUrl: string
  thumbnailUrl: string | null
  uploadedAt: string
}

export interface AuthResult {
  token: string
  user: {
    id?: string
    userId?: string
    email: string
    role: string
  }
}

export interface CollectionInfo {
  name: string
  displayName?: string
  slug?: string
  schema?: {
    type?: string
    properties?: Record<string, unknown>
    required?: string[]
  }
  settings?: Record<string, unknown>
}

export interface ListOptions {
  limit?: number
  offset?: number
  status?: 'draft' | 'published' | 'archived'
  sort?: string
  dir?: 'asc' | 'desc'
  fields?: string[]
  include?: string[]
  where?: Record<string, Record<string, unknown> | unknown[] | string | number | boolean>
  resolveVariables?: boolean
}

export interface DocumentsListOptions {
  type: string
  locale?: string
  limit?: number
  cursor?: KeysetCursor | null
  sort?: string
  dir?: 'asc' | 'desc'
  filter?: Record<string, unknown>
  facet?: Record<string, unknown>
}
