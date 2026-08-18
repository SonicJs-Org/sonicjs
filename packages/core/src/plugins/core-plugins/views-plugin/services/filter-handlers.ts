// views-plugin/services/filter-handlers.ts
//
// The shared filter GRAMMAR for Views on the document substrate: operator families,
// value coercion, and the _in/_between/LIKE parsing shared between the runtime engine
// (DocumentQueryProvider) and the save-time gate (validateFilterServeability). The two
// consume the SAME parsers/coercers so save-accepts and read-serves can't drift.
//
// NOTE: the origin implementation also carried per-family SQL fragment builders
// (buildFilterFragment + handle*) targeting the per-collection c_* tables. Those tables
// do not exist on this substrate — SQL is built by ViewsDocumentRepository — so the
// builders were stripped (deep-review 2026-07-04 hardening item 3), leaving only the
// grammar pieces something actually calls.

import type { EnrichedColumn, FilterOperator, HandlerFamily } from './types'

// ─────────────────────────────────────────────────────────────────────────
// Error class
// ─────────────────────────────────────────────────────────────────────────

export class FilterError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'FilterError'
  }
}

// ─────────────────────────────────────────────────────────────────────────
// Supported operators per handler family
// ─────────────────────────────────────────────────────────────────────────

const TEXT_OPS: Set<FilterOperator> = new Set([
  '_eq', '_neq', '_contains', '_starts', '_in', '_null',
])

const NUMERIC_OPS: Set<FilterOperator> = new Set([
  '_eq', '_neq', '_gt', '_gte', '_lt', '_lte', '_between', '_in', '_null',
])

const DATE_OPS: Set<FilterOperator> = new Set([
  '_eq', '_neq', '_gt', '_gte', '_lt', '_lte', '_between', '_in', '_null',
])

const JSON_OPS: Set<FilterOperator> = new Set([
  '_eq', '_contains', '_in', '_null',
])

export const OPS_BY_FAMILY: Record<HandlerFamily, Set<FilterOperator>> = {
  text: TEXT_OPS,
  numeric: NUMERIC_OPS,
  date: DATE_OPS,
  json: JSON_OPS,
}

/** Return the supported operators for a handler family as an array (not a Set). */
export function getSupportedOperators(family: HandlerFamily): FilterOperator[] {
  return [...(OPS_BY_FAMILY[family] || [])]
}

// ─────────────────────────────────────────────────────────────────────────
// Value coercion
// ─────────────────────────────────────────────────────────────────────────

export function coerceNumericValue(value: string, col: EnrichedColumn): number {
  if (col.fieldType === 'boolean' || col.fieldType === 'checkbox') {
    if (value === 'true' || value === '1') return 1
    if (value === 'false' || value === '0') return 0
    throw new FilterError(`Invalid boolean value: ${value}. Use true/false or 1/0.`)
  }
  const num = Number(value)
  if (isNaN(num)) throw new FilterError(`Invalid numeric value: ${value}`)
  return num
}

export function coerceDateValue(value: string): number {
  // Accept a raw epoch directly — date-family values on THIS substrate are epoch SECONDS
  // (documents.created_at/updated_at store `Math.floor(Date.now()/1000)`; documentSecondsToMs()
  // exists precisely because seconds is the storage convention). The origin implementation returned
  // MILLISECONDS — internally consistent there (it stores ms), silently wrong here: a ms bind
  // against a seconds column makes _gte match nothing and _lte match everything.
  const asNum = Number(value)
  if (!isNaN(asNum)) return asNum

  // ISO string → epoch SECONDS
  const ts = new Date(value).getTime()
  if (isNaN(ts)) throw new FilterError(`Invalid date value: ${value}`)
  return Math.floor(ts / 1000)
}

// ─────────────────────────────────────────────────────────────────────────
// Parse helpers
// ─────────────────────────────────────────────────────────────────────────

// Exported so the doc-model adapter (DocumentQueryProvider, option (b)) reuses the EXACT
// c_* IN value-parsing — one implementation, so the parity oracle can't drift.
export function parseInValues(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(String)
  return String(value).split(',').map(s => s.trim()).filter(Boolean)
}

// Exported so the doc-model adapter (DocumentQueryProvider) reuses the EXACT c_* _between
// value-parsing — including the comma-STRING form ("10,20"), which is how runtime
// `?filter[x][_between]=10,20` query params ALWAYS arrive (S6). One parser, so the two engines'
// _between can't diverge on the parse boundary.
export function parseBetweenValues(value: unknown): [string, string] {
  let parts: string[]
  if (Array.isArray(value)) {
    parts = value.map(String)
  } else {
    parts = String(value).split(',').map(s => s.trim())
  }
  if (parts.length !== 2) {
    throw new FilterError(`_between requires exactly 2 values, got ${parts.length}`)
  }
  return [parts[0]!, parts[1]!]
}

// Exported so the doc-model adapter reuses the EXACT c_* LIKE escaping (parity). Escapes the
// backslash FIRST (it is the ESCAPE char), then `%`/`_` — paired with `LIKE ? ESCAPE '\'` on both
// engines so a search term containing `%`/`_`/`\` matches LITERALLY (issue #1122). Both the escaping
// here and the `ESCAPE` clause must move together or the two engines' LIKE diverges (parity oracle).
export function escapeLike(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/%/g, '\\%').replace(/_/g, '\\_')
}
