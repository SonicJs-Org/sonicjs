// packages/core/src/views/query-parser.ts

import type { FilterRule, FilterOperator, SortRule, FilterShorthand, ParsedQueryParams } from './types'

const VALID_OPERATORS = new Set<FilterOperator>([
  '_eq', '_neq', '_gt', '_gte', '_lt', '_lte', '_between',
  '_in', '_contains', '_starts', '_null',
])

// ─────────────────────────────────────────────────────────────────────────
// Parse query string parameters into structured filter/sort/pagination
// ─────────────────────────────────────────────────────────────────────────

export function parseQueryParams(
  query: Record<string, string>,
  shorthands?: FilterShorthand[]
): ParsedQueryParams {
  const filters: FilterRule[] = []
  const sort: SortRule[] = []

  // Parse bracket-style filters: filter[field][_op]=value
  for (const [key, value] of Object.entries(query)) {
    const match = key.match(/^filter\[([^\]]+)\]\[([^\]]+)\]$/)
    if (match) {
      const field = match[1]!
      const operator = match[2]! as FilterOperator
      if (!VALID_OPERATORS.has(operator)) continue
      filters.push({ field, operator, value })
    }
  }

  // Resolve shorthands: ?category=shoes → filter[category][_eq]=shoes
  if (shorthands) {
    for (const sh of shorthands) {
      const value = query[sh.param]
      if (value !== undefined) {
        filters.push({ field: sh.field, operator: sh.operator, value })
      }
    }
  }

  // Parse sort: sort=-created_at,title → [{field:'created_at',direction:'desc'},{field:'title',direction:'asc'}]
  const sortParam = query['sort']
  if (sortParam) {
    for (const part of sortParam.split(',')) {
      const trimmed = part.trim()
      if (!trimmed) continue
      if (trimmed.startsWith('-')) {
        sort.push({ field: trimmed.slice(1), direction: 'desc' })
      } else {
        sort.push({ field: trimmed, direction: 'asc' })
      }
    }
  }

  // Pagination
  // Clamp page: floor at 1, ceiling at 1000 (matches the embed) so a hostile `?page=1e9`
  // can't force an unbounded OFFSET scan on the public API.
  const page = Math.min(Math.max(1, parseInt(query['page'] || '1', 10) || 1), 1000)
  const limit = parseInt(query['limit'] || '0', 10) || 0 // 0 = use view default

  // Format
  const format = query['format'] === 'csv' ? 'csv' as const : 'json' as const

  // Cursor pagination (opt-in): a token, or `paginate=cursor` for the first page.
  const cursor = query['cursor'] || undefined
  const paginate = query['paginate'] === 'cursor' ? ('cursor' as const) : undefined

  return { filters, sort, page, limit, format, cursor, paginate }
}
