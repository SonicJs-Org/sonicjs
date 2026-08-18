/**
 * column-meta.ts — column metadata for the Views editor / visual builder (Views MVP PR-4).
 *
 * Builds the per-column descriptor the `GET /admin/views/api/collection-columns/:name` endpoint
 * returns: name + fieldType + handler family + supported operators (already present), PLUS the
 * typed value-widget data the visual builder needs (deep-review F5):
 *   - `enumOptions` — labelled choices for select/radio/multiselect, from the schema property's
 *     `enum` (+ optional `enumLabels`); same source the content form's `getCollectionFields` uses.
 *   - `referenceTarget` — the target collection(s) for reference fields, from the property's
 *     `collection` (string or string[]).
 * Pure (no DB) so it unit-tests directly; the endpoint just supplies resolved columns + schema.
 */

import { resolveHandlerFamily } from './column-resolver'
import { getSupportedOperators } from './filter-handlers'
import type { EnrichedColumn, HandlerFamily, FilterOperator } from './types'

export interface ColumnMeta {
  name: string
  fieldType: string
  handler: HandlerFamily
  operators: FilterOperator[]
  /** Labelled choices for select/radio/multiselect (present only when the field has an enum). */
  enumOptions?: Array<{ value: string; label: string }>
  /** Target collection(s) for reference fields (present only for reference-type fields). */
  referenceTarget?: string[]
}

export function buildColumnMeta(
  enrichedColumns: EnrichedColumn[],
  schemaProperties?: Record<string, Record<string, unknown>>,
): ColumnMeta[] {
  return enrichedColumns.map((col) => {
    const handler = resolveHandlerFamily(col)
    const meta: ColumnMeta = {
      name: col.name,
      fieldType: col.fieldType || col.sqliteType.toLowerCase(),
      handler,
      operators: getSupportedOperators(handler),
    }

    const prop = schemaProperties?.[col.name]
    if (prop && Array.isArray(prop.enum)) {
      const labels = Array.isArray(prop.enumLabels) ? (prop.enumLabels as string[]) : undefined
      meta.enumOptions = (prop.enum as string[]).map((value, i) => ({ value, label: labels?.[i] ?? value }))
    }
    if (prop && prop.collection) {
      meta.referenceTarget = Array.isArray(prop.collection)
        ? (prop.collection as string[])
        : [prop.collection as string]
    }
    return meta
  })
}
