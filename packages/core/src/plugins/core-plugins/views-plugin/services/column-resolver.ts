/**
 * column-resolver.ts — field-type inference + filter-handler dispatch for Views columns.
 *
 * Ported from the origin's Views column resolver, MINUS the c_* machinery: the PRAGMA
 * ground-truth reader and the dynamic field-type registry are gone (this codebase has no
 * per-collection tables and the plugin carries a static type map instead). Column lists are
 * resolved from `document_types` by `view-collection-resolver.ts`; this module owns the two
 * pure pieces the engine still needs:
 *
 *   - `inferFieldTypeFromSchema` — reverse-maps a JSON-schema property to a field-type id.
 *   - `resolveHandlerFamily` — which filter-handler family (text/numeric/date/json) serves
 *     a resolved column; the LIKE/IN text-family guard depends on it.
 */

import type { EnrichedColumn, SchemaProperty, HandlerFamily } from './types'

/** Static field-type traits (replaces the origin's dynamic fieldTypeRegistry for the subset
 *  Views renders/filters). `storageType` drives handler dispatch; `category` the widgets. */
export const FIELD_TYPE_TRAITS: Readonly<Record<string, { storageType: string; category: string }>> = {
  text: { storageType: 'text', category: 'basic' },
  slug: { storageType: 'text', category: 'basic' },
  richtext: { storageType: 'text', category: 'text' },
  quill: { storageType: 'text', category: 'text' },
  mdxeditor: { storageType: 'text', category: 'text' },
  date: { storageType: 'integer', category: 'date' },
  media: { storageType: 'text', category: 'media' },
  boolean: { storageType: 'integer', category: 'basic' },
  number: { storageType: 'real', category: 'number' },
  integer: { storageType: 'integer', category: 'number' },
  tags: { storageType: 'json', category: 'choice' },
  select: { storageType: 'text', category: 'choice' },
  reference: { storageType: 'reference', category: 'reference' },
}

// ─────────────────────────────────────────────────────────────────────────
// inferFieldTypeFromSchema — reverse-maps JSON Schema → field-type id
// ─────────────────────────────────────────────────────────────────────────

export function inferFieldTypeFromSchema(prop: SchemaProperty): string | undefined {
  // Direct type overrides — type IS the field-type id
  if (prop.type === 'slug') return 'slug'
  if (prop.type === 'quill') return 'quill'
  if (prop.type === 'mdxeditor') return 'mdxeditor'
  if (prop.type === 'reference') return 'reference'

  // Format-based disambiguation
  if (prop.format === 'richtext') return 'richtext'
  if (prop.format === 'date-time') return 'date'
  if (prop.format === 'media') return 'media'

  // JSON Schema type-based
  if (prop.type === 'boolean') return 'boolean'
  if (prop.type === 'number') return 'number'
  if (prop.type === 'integer') return 'integer'
  if (prop.type === 'array') return 'tags'
  if (prop.enum) return 'select'
  if (prop.type === 'string') return 'text'

  // A stored field-type id with known traits (e.g. a Zod-derived custom marker).
  if (prop.type && FIELD_TYPE_TRAITS[prop.type]) return prop.type

  return undefined
}

// ─────────────────────────────────────────────────────────────────────────
// resolveHandlerFamily — determines which filter handler serves a column
// ─────────────────────────────────────────────────────────────────────────

export function resolveHandlerFamily(col: EnrichedColumn): HandlerFamily {
  // Date category — split by storageType
  if (col.category === 'date') {
    if (col.storageType === 'integer') return 'date'   // date, datetime → ISO→epoch
    if (col.storageType === 'text') return 'text'       // time → "14:30" string
    if (col.storageType === 'json') return 'json'       // daterange → JSON object
    return 'date'
  }

  // Boolean — check fieldType, not category (no 'boolean' category exists)
  if (col.fieldType === 'boolean' || col.fieldType === 'checkbox') return 'numeric'

  // storageType dispatch
  if (col.storageType === 'json') return 'json'
  if (col.storageType === 'real') return 'numeric'
  if (col.storageType === 'integer') return 'numeric'
  if (col.storageType === 'text' || col.storageType === 'reference') return 'text'

  // Declared-SQL-type fallback
  if (col.sqliteType === 'TEXT') return 'text'
  if (col.sqliteType === 'INTEGER') return 'numeric'
  if (col.sqliteType === 'REAL') return 'numeric'

  return 'text'
}
