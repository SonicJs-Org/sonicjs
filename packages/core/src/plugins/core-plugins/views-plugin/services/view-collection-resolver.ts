/**
 * view-collection-resolver.ts — Views' collection/column resolution over `document_types`.
 *
 * Ported from the origin's resolution seam (the C5 resolution seam) with the c_* impl dropped:
 * on this codebase collections are code-registered and content lives in `documents`, so the
 * document-type registry rows are the ONLY resolution source. Columns come from the type's
 * `schema` (JSON-schema properties, when the registering plugin supplies one) plus its
 * `queryable_fields`; structural `documents` columns are always present.
 *
 * The seam carries SUBSTRATE facts only; user-facing error text stays in the callers —
 * `ViewService` translates the two error classes into its `ViewServiceError` shapes.
 */

import type { D1Database } from '@cloudflare/workers-types'
import { inferFieldTypeFromSchema, FIELD_TYPE_TRAITS } from './column-resolver'
import type { QueryableField } from './views-document-repository'
import type { EnrichedColumn, SchemaProperty } from './types'
import { getCollectionRegistry } from '../../../../services/collection-registry'

// ─────────────────────────────────────────────────────────────────────────
// Seam contract
// ─────────────────────────────────────────────────────────────────────────

/** Everything `ViewService.runResolvedView` needs before the provider call. */
export interface ResolvedViewCollection {
  collectionName: string
  /** The provider request's table identifier — always `'documents'` here. */
  tableName: string
  schemaProperties: Record<string, SchemaProperty> | undefined
  enrichedColumns: EnrichedColumn[]
}

/** A collection choice for the builder dropdown. */
export interface ViewCollectionOption {
  id: string
  name: string
  display_name: string
}

/** The editor column-metadata endpoint's resolution result (keyed by collection NAME). */
export interface ResolvedCollectionColumns {
  enrichedColumns: EnrichedColumn[]
  schemaProperties: Record<string, SchemaProperty> | undefined
}

/** The collection resolved but is not servable yet. */
export class CollectionNotReadyError extends Error {
  constructor(message = 'collection is not ready') {
    super(message)
    this.name = 'CollectionNotReadyError'
  }
}

/** Resolution failed with a substrate message worth surfacing (unknown id, inactive type). */
export class CollectionResolutionError extends Error {
  constructor(
    message: string,
    public readonly httpStatus: 404 | 409,
  ) {
    super(message)
    this.name = 'CollectionResolutionError'
  }
}

export interface ViewCollectionResolver {
  /** Collection + schema + columns for the execute pipeline. Throws the two error classes
   *  above; anything else propagates raw. */
  resolve(collectionId: string): Promise<ResolvedViewCollection>
  /** Active document types for the builder dropdown, name-ordered. */
  listCollections(): Promise<ViewCollectionOption[]>
  /** Save-time validation: does this collection id exist (and is active)? */
  collectionExists(collectionId: string): Promise<boolean>
  /** Column names of the collection's backing store — the publish whitelist / status-column
   *  safety bar. `null` = unknown collection (callers 400). */
  collectionColumns(collectionId: string): Promise<string[] | null>
  /** NOT-NULL column names the keyset engine may cursor-sort on beyond the structural
   *  defaults. Constant here — the doc engine keysets on structural columns only. */
  notNullFields(collectionId: string): Promise<ReadonlySet<string>>
  /** Editor metadata: enriched columns for a collection resolved BY NAME. `null` = unknown. */
  columnsByName(collectionName: string): Promise<ResolvedCollectionColumns | null>
  /** Does the collection's document type grant PUBLIC read (`settings.baseGrants.public`
   *  includes `read`)? Gates the anonymous public surfaces so a view can never expose a
   *  non-public collection — the D5 "no is_published-only fast path" rule. `false` for an
   *  unknown/malformed type (fail-closed). */
  isCollectionPublic(collectionId: string): Promise<boolean>
}

// ─────────────────────────────────────────────────────────────────────────
// Document-type impl
// ─────────────────────────────────────────────────────────────────────────

/** Structural `documents` columns every view can select/filter — enriched with the same
 *  defaults the engine's handler dispatch expects. `notNull` marks the structurally
 *  guaranteed trio the keyset engine may cursor on. NOTE: timestamps on this codebase are
 *  epoch SECONDS (unixepoch defaults), not milliseconds. */
const DOC_SYSTEM_COLUMNS: ReadonlyArray<EnrichedColumn> = [
  { name: 'id',         sqliteType: 'TEXT',    storageType: 'text',    fieldType: 'text', category: 'basic', isSystem: true, notNull: true },
  { name: 'title',      sqliteType: 'TEXT',    storageType: 'text',    fieldType: 'text', category: 'basic', isSystem: true, notNull: false },
  { name: 'slug',       sqliteType: 'TEXT',    storageType: 'text',    fieldType: 'slug', category: 'basic', isSystem: true, notNull: false },
  { name: 'status',     sqliteType: 'TEXT',    storageType: 'text',    fieldType: 'text', category: 'basic', isSystem: true, notNull: false },
  { name: 'created_by', sqliteType: 'TEXT',    storageType: 'text',    fieldType: 'text', category: 'basic', isSystem: true, notNull: false },
  { name: 'updated_by', sqliteType: 'TEXT',    storageType: 'text',    fieldType: 'text', category: 'basic', isSystem: true, notNull: false },
  { name: 'created_at', sqliteType: 'INTEGER', storageType: 'integer', fieldType: 'date', category: 'date',  isSystem: true, notNull: true },
  { name: 'updated_at', sqliteType: 'INTEGER', storageType: 'integer', fieldType: 'date', category: 'date',  isSystem: true, notNull: true },
]

const SYSTEM_NAMES: ReadonlySet<string> = new Set(DOC_SYSTEM_COLUMNS.map((c) => c.name))

/** Fallback enrichment for a queryable field that has no schema property. */
function enrichFromQueryableField(f: QueryableField): EnrichedColumn {
  if (f.kind === 'facet') {
    return { name: f.name, sqliteType: 'TEXT', storageType: 'json', fieldType: 'tags', isSystem: false, notNull: false }
  }
  if (f.kind === 'reference') {
    return { name: f.name, sqliteType: 'TEXT', storageType: 'reference', fieldType: 'reference', isSystem: false, notNull: false }
  }
  switch (f.type) {
    case 'integer':
      return { name: f.name, sqliteType: 'INTEGER', storageType: 'integer', fieldType: 'integer', isSystem: false, notNull: false }
    case 'number':
      return { name: f.name, sqliteType: 'REAL', storageType: 'real', fieldType: 'number', isSystem: false, notNull: false }
    case 'boolean':
      return { name: f.name, sqliteType: 'INTEGER', storageType: 'integer', fieldType: 'boolean', isSystem: false, notNull: false }
    case 'date':
      return { name: f.name, sqliteType: 'INTEGER', storageType: 'integer', fieldType: 'date', category: 'date', isSystem: false, notNull: false }
    default:
      return { name: f.name, sqliteType: 'TEXT', storageType: 'text', fieldType: 'text', isSystem: false, notNull: false }
  }
}

/** Row projection of `document_types` this resolver reads. */
interface DocumentTypeRow {
  id: string
  name: string
  display_name: string | null
  schema: string | null
  queryable_fields: string | null
}

export class DocumentCollectionResolver implements ViewCollectionResolver {
  constructor(
    private readonly db: D1Database,
    private readonly tenantId: string = 'default',
  ) {}

  async resolve(collectionId: string): Promise<ResolvedViewCollection> {
    const row = await this.loadType('id', collectionId)
    if (!row) {
      throw new CollectionResolutionError(
        `No document type provisioned for collection "${collectionId}"`,
        404,
      )
    }
    const schemaProperties = this.resolveSchemaProperties(row)
    const enrichedColumns = this.enrichColumns(row, schemaProperties)
    return { collectionName: row.name, tableName: 'documents', schemaProperties, enrichedColumns }
  }

  async listCollections(): Promise<ViewCollectionOption[]> {
    const { results } = await this.db
      .prepare(`SELECT id, name, display_name FROM document_types WHERE is_active = 1 ORDER BY name`)
      .all<{ id: string; name: string; display_name: string | null }>()
    return (results || []).map((r) => ({
      id: r.id,
      name: r.name,
      display_name: r.display_name || r.name,
    }))
  }

  async collectionExists(collectionId: string): Promise<boolean> {
    const row = await this.db
      .prepare('SELECT id FROM document_types WHERE id = ? AND is_active = 1')
      .bind(collectionId)
      .first<{ id: string }>()
    return !!row
  }

  async collectionColumns(collectionId: string): Promise<string[] | null> {
    const row = await this.loadType('id', collectionId)
    if (!row) return null
    return this.enrichColumns(row, this.resolveSchemaProperties(row)).map((c) => c.name)
  }

  async notNullFields(_collectionId: string): Promise<ReadonlySet<string>> {
    // The doc keyset engine sorts on structural columns only; the structurally guaranteed
    // NOT-NULL set is constant — no per-collection read.
    return new Set(DOC_SYSTEM_COLUMNS.filter((c) => c.notNull).map((c) => c.name))
  }

  async columnsByName(collectionName: string): Promise<ResolvedCollectionColumns | null> {
    const row = await this.loadType('name', collectionName)
    if (!row) return null
    const schemaProperties = this.resolveSchemaProperties(row)
    return { enrichedColumns: this.enrichColumns(row, schemaProperties), schemaProperties }
  }

  async isCollectionPublic(collectionId: string): Promise<boolean> {
    const row = await this.db
      .prepare(`SELECT settings FROM document_types WHERE id = ? AND is_active = 1`)
      .bind(collectionId)
      .first<{ settings: string | null }>()
    if (!row?.settings) return false // unknown/inactive type → fail-closed
    try {
      const settings = JSON.parse(row.settings) as { baseGrants?: { public?: unknown } }
      const publicGrants = settings.baseGrants?.public
      return Array.isArray(publicGrants) && publicGrants.includes('read')
    } catch {
      return false // malformed settings → fail-closed
    }
  }

  /**
   * Field schema for a type, for the builder's field pickers. The `document_types.schema`
   * column stores `{queryableFields, settings}` (no `properties`) for code-defined
   * collections, so `parseSchemaProperties` finds nothing and the builder would see only
   * structural columns. Fall back to the in-memory CollectionRegistry, which carries the
   * real `CollectionConfig.schema.properties`, so the builder can offer a code collection's
   * own fields (first_name, department, …). The query engine already serves those via
   * json_extract; this just lets the UI discover them. Registry-empty (e.g. a bare unit
   * test) → returns the stored value, i.e. structural-only, unchanged.
   */
  private resolveSchemaProperties(row: DocumentTypeRow): Record<string, SchemaProperty> | undefined {
    const stored = parseSchemaProperties(row.schema)
    if (stored && Object.keys(stored).length > 0) return stored
    const registry = getCollectionRegistry()
    const record = registry.getById(row.id) ?? registry.getBySlugOrName(row.name)
    const props = (record?.schema as { properties?: Record<string, SchemaProperty> } | undefined)?.properties
    return props && Object.keys(props).length > 0 ? props : stored
  }

  private async loadType(key: 'id' | 'name', value: string): Promise<DocumentTypeRow | null> {
    return this.db
      .prepare(
        `SELECT id, name, display_name, schema, queryable_fields FROM document_types WHERE ${key} = ? AND is_active = 1`,
      )
      .bind(value)
      .first<DocumentTypeRow>()
  }

  /**
   * Structural columns first, then user fields: schema-property enrichment when the type
   * carries a JSON schema, else the queryable-field fallback; `queryable_fields` entries
   * missing from the schema are appended after (doc-native types register fields without a
   * serializable schema — e.g. Zod-object types store `schema='{}'`).
   */
  private enrichColumns(
    row: DocumentTypeRow,
    schemaProperties: Record<string, SchemaProperty> | undefined,
  ): EnrichedColumn[] {
    const out: EnrichedColumn[] = [...DOC_SYSTEM_COLUMNS]
    const seen = new Set<string>(SYSTEM_NAMES)

    let queryableFields: QueryableField[] = []
    if (row.queryable_fields) {
      try {
        const parsed: unknown = JSON.parse(row.queryable_fields)
        if (Array.isArray(parsed)) queryableFields = parsed as QueryableField[]
      } catch {
        // malformed queryable_fields — schema properties still resolve below
      }
    }
    const qfByName = new Map(queryableFields.map((f) => [f.name, f]))

    for (const [name, prop] of Object.entries(schemaProperties ?? {})) {
      if (seen.has(name)) continue
      seen.add(name)
      const inferredId = inferFieldTypeFromSchema(prop)
      const traits = inferredId ? FIELD_TYPE_TRAITS[inferredId] : undefined
      if (inferredId && traits) {
        out.push({
          name,
          sqliteType: storageToSqliteType(traits.storageType),
          storageType: traits.storageType,
          fieldType: inferredId,
          category: traits.category,
          isSystem: false,
          notNull: false,
        })
        continue
      }
      const qf = qfByName.get(name)
      out.push(qf ? enrichFromQueryableField(qf) : { name, sqliteType: 'TEXT', storageType: 'text', fieldType: 'text', isSystem: false, notNull: false })
    }

    for (const f of queryableFields) {
      if (seen.has(f.name)) continue
      seen.add(f.name)
      out.push(enrichFromQueryableField(f))
    }

    return out
  }
}

function parseSchemaProperties(
  schema: string | null,
): Record<string, SchemaProperty> | undefined {
  if (!schema) return undefined
  try {
    const parsed = JSON.parse(schema)
    return parsed?.properties as Record<string, SchemaProperty> | undefined
  } catch {
    return undefined
  }
}

function storageToSqliteType(storageType: string): string {
  if (storageType === 'integer') return 'INTEGER'
  if (storageType === 'real') return 'REAL'
  return 'TEXT'
}
