import { D1Database } from '@cloudflare/workers-types'
import { nanoid } from 'nanoid'
import type { Document, QueryableField, DocumentRow } from '../schemas/document'
import { extractSearchableText } from './searchable-text'

// D1 hard limit: 100 bound parameters per statement. Keep under 90 for safety.
const MAX_PARAMS = 90

function chunkArray<T>(arr: T[], size: number): T[][] {
  const chunks: T[][] = []
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size))
  }
  return chunks
}

interface FacetInsert {
  id: string
  tenant_id: string
  document_id: string
  root_id: string
  type_id: string
  field_name: string
  ordinal: number
  value_text: string | null
  value_number: number | null
  now: number
}

interface ReferenceInsert {
  id: string
  tenant_id: string
  from_root_id: string
  from_document_id: string
  field_name: string
  ordinal: number
  to_root_id: string
  ref_strength: string
  now: number
}

export class DocumentProjection {
  constructor(private db: D1Database) {}

  // Build D1 PreparedStatement arrays for inserting facets/references for a document.
  // Returns raw D1 PreparedStatement objects suitable for inclusion in db.batch([...]).
  buildDerivedInsertStatements(
    doc: Document,
    queryableFields: QueryableField[],
    now: number,
  ): D1PreparedStatement[] {
    const statements: D1PreparedStatement[] = []
    const facets: FacetInsert[] = []
    const refs: ReferenceInsert[] = []

    for (const field of queryableFields) {
      const rawValue = this.extractPath(doc.data, field.path ?? `$.${field.name}`)

      if (field.kind === 'facet') {
        const values = Array.isArray(rawValue) ? rawValue : rawValue != null ? [rawValue] : []
        values.forEach((v, ordinal) => {
          const isNum = typeof v === 'number'
          facets.push({
            id: nanoid(),
            tenant_id: doc.tenantId,
            document_id: doc.id,
            root_id: doc.rootId,
            type_id: doc.typeId,
            field_name: field.name,
            ordinal,
            value_text: isNum ? null : String(v),
            value_number: isNum ? v : null,
            now,
          })
        })
      } else if (field.kind === 'reference') {
        const roots = Array.isArray(rawValue) ? rawValue : rawValue != null ? [rawValue] : []
        roots.forEach((rootId, ordinal) => {
          refs.push({
            id: nanoid(),
            tenant_id: doc.tenantId,
            from_root_id: doc.rootId,
            from_document_id: doc.id,
            field_name: field.name,
            ordinal,
            to_root_id: String(rootId),
            ref_strength: field.refStrength ?? 'weak',
            now,
          })
        })
      }
      // 'scalar' fields are VIRTUAL generated columns; no derived rows needed.
    }

    // Insert facets in chunks to respect the 100-param D1 limit (9 params per row).
    const FACET_COLS = 10
    for (const chunk of chunkArray(facets, Math.floor(MAX_PARAMS / FACET_COLS))) {
      const placeholders = chunk.map(() => '(?,?,?,?,?,?,?,?,?,?)').join(',')
      const params: (string | number | null)[] = []
      for (const f of chunk) {
        params.push(f.id, f.tenant_id, f.document_id, f.root_id, f.type_id, f.field_name, f.ordinal, f.value_text, f.value_number, f.now)
      }
      statements.push(
        this.db.prepare(
          `INSERT INTO document_facets (id, tenant_id, document_id, root_id, type_id, field_name, ordinal, value_text, value_number, created_at) VALUES ${placeholders}`,
        ).bind(...params),
      )
    }

    // Insert references in chunks (9 params per row).
    const REF_COLS = 9
    for (const chunk of chunkArray(refs, Math.floor(MAX_PARAMS / REF_COLS))) {
      const placeholders = chunk.map(() => '(?,?,?,?,?,?,?,?,?)').join(',')
      const params: (string | number | null)[] = []
      for (const r of chunk) {
        params.push(r.id, r.tenant_id, r.from_root_id, r.from_document_id, r.field_name, r.ordinal, r.to_root_id, r.ref_strength, r.now)
      }
      statements.push(
        this.db.prepare(
          `INSERT INTO document_references (id, tenant_id, from_root_id, from_document_id, field_name, ordinal, to_root_id, ref_strength, created_at) VALUES ${placeholders}`,
        ).bind(...params),
      )
    }

    return statements
  }

  buildDerivedDeleteStatements(documentId: string): D1PreparedStatement[] {
    return [
      this.db.prepare('DELETE FROM document_facets WHERE document_id = ?').bind(documentId),
      this.db.prepare('DELETE FROM document_references WHERE from_document_id = ?').bind(documentId),
    ]
  }

  // ─── Full-text projection (documents_fts) ─────────────────────────────────
  // The FTS index is one more write-time projection alongside facets/references (spike Q6), keyed by
  // document_id. Callers in DocumentsService fold these statements into the same atomic db.batch as the
  // document row write, so the index can never silently diverge. Visibility/soft-delete is kept native
  // (no query JOIN): a soft-deleted or visible=0 row emits the DELETE only, so the index holds only live,
  // visible rows and the public query filters on is_published/tenant_id directly (LA2).

  /** Render a document's declared `kind:'fulltext'` fields to the plain text indexed into `body`. */
  private computeFtsBody(doc: Document, queryableFields: QueryableField[]): string {
    const parts: string[] = []
    for (const field of queryableFields) {
      if (field.kind !== 'fulltext') continue
      const raw = this.extractPath(doc.data, field.path ?? `$.${field.name}`)
      const text = extractSearchableText(raw)
      if (text) parts.push(text)
    }
    return parts.join(' ').replace(/\s+/g, ' ').trim()
  }

  /**
   * Upsert a document's FTS row to match its CURRENT state. Always DELETEs the existing row first
   * (idempotent re-index), then INSERTs only if the row is live + visible. `doc` must carry the
   * post-mutation flags (e.g. is_published after publish), since the index snapshots is_published.
   */
  buildFtsUpsertStatements(doc: Document, queryableFields: QueryableField[]): D1PreparedStatement[] {
    const statements: D1PreparedStatement[] = [
      this.db.prepare('DELETE FROM documents_fts WHERE document_id = ?').bind(doc.id),
    ]
    if (doc.deletedAt == null && doc.visible) {
      const body = this.computeFtsBody(doc, queryableFields)
      // R5: 10 columns / 10 binds — matches the 10-column documents_fts layout (migration 0003).
      statements.push(
        this.db
          .prepare(
            `INSERT INTO documents_fts (title, slug, body, document_id, type_id, status, created_at, updated_at, tenant_id, is_published)
             VALUES (?,?,?,?,?,?,?,?,?,?)`,
          )
          .bind(
            doc.title ?? '',
            doc.slug ?? '',
            body,
            doc.id,
            doc.typeId,
            doc.status,
            doc.createdAt,
            doc.updatedAt,
            doc.tenantId,
            doc.isPublished ? 1 : 0,
          ),
      )
    }
    return statements
  }

  /** Deindex a document (used on supersede-to-history, soft delete, and erase). */
  buildFtsDeleteStatements(documentId: string): D1PreparedStatement[] {
    return [this.db.prepare('DELETE FROM documents_fts WHERE document_id = ?').bind(documentId)]
  }

  // Rebuild derived rows for all current-draft and published rows of a type.
  // One bounded admin action; not chunked cron orchestration.
  async reindexType(typeId: string, tenantId: string, queryableFields: QueryableField[]): Promise<number> {
    // Only reindex rows that participate in queries (current-draft or published).
    const result = await this.db
      .prepare(
        `SELECT * FROM documents
         WHERE type_id = ? AND tenant_id = ? AND (is_current_draft = 1 OR is_published = 1) AND deleted_at IS NULL`,
      )
      .bind(typeId, tenantId)
      .all<DocumentRow>()

    const rows = result.results ?? []
    if (rows.length === 0) return 0

    const now = Math.floor(Date.now() / 1000)
    let rebuilt = 0

    // Process in batches of 20 documents to stay well under D1's 1000-rows-per-batch guidance.
    for (const chunk of chunkArray(rows, 20)) {
      const statements: D1PreparedStatement[] = []

      for (const row of chunk) {
        const doc = rowToDocument(row)
        statements.push(...this.buildDerivedDeleteStatements(doc.id))
        statements.push(...this.buildDerivedInsertStatements(doc, queryableFields, now))
        // Rebuild the FTS row too (idempotent upsert) — this is also the backfill primitive (T0.5).
        statements.push(...this.buildFtsUpsertStatements(doc, queryableFields))
      }

      if (statements.length > 0) {
        await this.db.batch(statements)
        rebuilt += chunk.length
      }
    }

    return rebuilt
  }

  private extractPath(data: Record<string, unknown>, path: string): unknown {
    // Supports simple $.<key> paths only; full JSONPath is overkill for the POC.
    if (path.startsWith('$.')) {
      const key = path.slice(2)
      return data[key] ?? null
    }
    return null
  }
}

function rowToDocument(row: DocumentRow): Document {
  return {
    id: row.id,
    rootId: row.root_id,
    typeId: row.type_id,
    typeVersion: row.type_version,
    versionOfId: row.version_of_id,
    versionNumber: row.version_number,
    isCurrentDraft: row.is_current_draft === 1,
    isPublished: row.is_published === 1,
    status: row.status,
    parentRootId: row.parent_root_id,
    slug: row.slug,
    path: row.path,
    title: row.title,
    zone: row.zone,
    sortOrder: row.sort_order,
    visible: row.visible === 1,
    publishedAt: row.published_at,
    scheduledAt: row.scheduled_at,
    expiresAt: row.expires_at,
    deletedAt: row.deleted_at,
    tenantId: row.tenant_id,
    locale: row.locale,
    translationGroupId: row.translation_group_id,
    data: JSON.parse(row.data),
    metadata: JSON.parse(row.metadata),
    ownerId: row.owner_id,
    createdBy: row.created_by,
    updatedBy: row.updated_by,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}
