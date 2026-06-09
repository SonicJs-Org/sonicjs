import { D1Database } from '@cloudflare/workers-types'
import { nanoid } from 'nanoid'
import type {
  PluginDocumentType,
  DocumentType,
  DocumentTypeRow,
} from '../schemas/document'

function rowToDocumentType(row: DocumentTypeRow): DocumentType {
  return {
    id: row.id,
    name: row.name,
    displayName: row.display_name,
    description: row.description,
    schema: JSON.parse(row.schema),
    queryableFields: JSON.parse(row.queryable_fields),
    settings: JSON.parse(row.settings),
    pluginId: row.plugin_id,
    source: row.source,
    schemaVersion: row.schema_version,
    isSystem: row.is_system === 1,
    isActive: row.is_active === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

export class DocumentTypeRegistry {
  private cache = new Map<string, DocumentType>()

  constructor(private db: D1Database) {}

  // Register or update a document type. Idempotent: bumps schema_version only when schema changes.
  async register(def: PluginDocumentType & { pluginId?: string; source?: 'code' | 'plugin' | 'system' }): Promise<DocumentType> {
    const now = Math.floor(Date.now() / 1000)
    const existing = await this.findById(def.id)

    // A z.ZodSchema is not JSON-serializable, so persist a stable serializable shape derived from
    // the type's queryable fields + settings. This is what schemaChanged compares, so schema_version
    // bumps whenever a type's filterable shape changes (and is stamped onto documents.type_version).
    const schemaJson = JSON.stringify({ queryableFields: def.queryableFields ?? [], settings: def.settings ?? {} })
    const queryableJson = JSON.stringify(def.queryableFields ?? [])
    const settingsJson = JSON.stringify(def.settings ?? {})

    if (existing) {
      const schemaChanged = schemaJson !== JSON.stringify(existing.schema)
      const newVersion = schemaChanged ? existing.schemaVersion + 1 : existing.schemaVersion

      await this.db
        .prepare(
          `UPDATE document_types SET
             display_name = ?,
             description = ?,
             schema = ?,
             queryable_fields = ?,
             settings = ?,
             plugin_id = ?,
             schema_version = ?,
             is_active = 1,
             updated_at = ?
           WHERE id = ?`,
        )
        .bind(
          def.displayName,
          def.description ?? null,
          schemaJson,
          queryableJson,
          settingsJson,
          def.pluginId ?? null,
          newVersion,
          now,
          def.id,
        )
        .run()

      const updated = await this.findById(def.id)
      this.cache.set(def.id, updated!)
      return updated!
    }

    await this.db
      .prepare(
        `INSERT INTO document_types (id, name, display_name, description, schema, queryable_fields, settings, plugin_id, source, schema_version, is_system, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 1, ?, ?)`,
      )
      .bind(
        def.id,
        def.name ?? def.id,
        def.displayName,
        def.description ?? null,
        schemaJson,
        queryableJson,
        settingsJson,
        def.pluginId ?? null,
        def.source ?? 'code',
        now,
        now,
      )
      .run()

    const created = await this.findById(def.id)
    this.cache.set(def.id, created!)
    return created!
  }

  async findById(id: string): Promise<DocumentType | null> {
    if (this.cache.has(id)) return this.cache.get(id)!

    const row = await this.db
      .prepare('SELECT * FROM document_types WHERE id = ?')
      .bind(id)
      .first<DocumentTypeRow>()

    if (!row) return null
    const dt = rowToDocumentType(row)
    this.cache.set(id, dt)
    return dt
  }

  async findAll(activeOnly = true): Promise<DocumentType[]> {
    const sql = activeOnly
      ? 'SELECT * FROM document_types WHERE is_active = 1 ORDER BY name'
      : 'SELECT * FROM document_types ORDER BY name'

    const result = await this.db.prepare(sql).all<DocumentTypeRow>()
    return (result.results ?? []).map(rowToDocumentType)
  }

  async deactivate(id: string): Promise<void> {
    const now = Math.floor(Date.now() / 1000)
    await this.db
      .prepare('UPDATE document_types SET is_active = 0, updated_at = ? WHERE id = ?')
      .bind(now, id)
      .run()
    this.cache.delete(id)
  }

  clearCache(): void {
    this.cache.clear()
  }
}
