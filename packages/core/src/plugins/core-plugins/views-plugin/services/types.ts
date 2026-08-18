// packages/core/src/views/types.ts

// ─────────────────────────────────────────────────────────────────────────
// Filter types
// ─────────────────────────────────────────────────────────────────────────

export type FilterOperator =
  | '_eq' | '_neq' | '_gt' | '_gte' | '_lt' | '_lte' | '_between'
  | '_in' | '_contains' | '_starts' | '_null'

export interface FilterRule {
  field: string
  operator: FilterOperator
  value: unknown
}

export interface FilterShorthand {
  param: string
  field: string
  operator: FilterOperator
}

/**
 * An OR/AND group of rules (Views OR-logic). The group's `rules` are joined by
 * `match`; the group as a whole is AND-ed with the top-level rules and every other
 * group. OR exists ONLY inside a group — there is deliberately NO top-level `match`
 * on FilterConfig: top-level composition is ALWAYS AND, which is what keeps the
 * public surface's forced `status='published' AND (…)` un-leakable (SQL AND is
 * monotonically restrictive). `rules` must be non-empty (an empty group would emit
 * invalid `()` SQL).
 */
export interface FilterGroup {
  match: 'and' | 'or'
  rules: FilterRule[]
}

export interface FilterConfig {
  rules: FilterRule[]
  /** Each group AND-ed with the top-level rules and with each other. */
  groups?: FilterGroup[]
  shorthands?: FilterShorthand[]
}

// ─────────────────────────────────────────────────────────────────────────
// Sort types
// ─────────────────────────────────────────────────────────────────────────

export interface SortRule {
  field: string
  direction: 'asc' | 'desc'
}

export type SortConfig = SortRule[]

// ─────────────────────────────────────────────────────────────────────────
// Column + pagination types
// ─────────────────────────────────────────────────────────────────────────

export interface ColumnConfig {
  fields: string[] // empty = all columns
}

export interface PaginationConfig {
  defaultLimit: number
  maxLimit: number
}

// ─────────────────────────────────────────────────────────────────────────
// Enriched column — output of column resolver
// ─────────────────────────────────────────────────────────────────────────

export interface EnrichedColumn {
  name: string          // from PRAGMA
  sqliteType: string    // TEXT, INTEGER, REAL
  storageType?: string  // text, integer, real, json, reference
  fieldType?: string    // inferred registry ID
  category?: string     // basic, text, number, date, choice, media, reference, layout, advanced
  isSystem: boolean
  notNull: boolean      // from PRAGMA notnull — a NOT-NULL column is keyset-safe (no NULL ordering gaps)
}

// ─────────────────────────────────────────────────────────────────────────
// Schema property — shape from collection schema JSON
// ─────────────────────────────────────────────────────────────────────────

export interface SchemaProperty {
  type?: string
  format?: string
  enum?: string[]
  [key: string]: unknown
}

// ─────────────────────────────────────────────────────────────────────────
// Parsed query string — output of query parser
// ─────────────────────────────────────────────────────────────────────────

export interface ParsedQueryParams {
  filters: FilterRule[]
  sort: SortRule[]
  page: number
  limit: number
  format: 'json' | 'csv'
  /** Opaque keyset-cursor token (opt-in cursor pagination — JSON API only). */
  cursor?: string
  /** Request cursor mode for the FIRST page (no token yet). */
  paginate?: 'cursor'
}

// ─────────────────────────────────────────────────────────────────────────
// Handler family — determines which filter/coercion logic to apply
// ─────────────────────────────────────────────────────────────────────────

export type HandlerFamily = 'text' | 'numeric' | 'json' | 'date'
