import { D1Database } from '@cloudflare/workers-types'
import { nanoid } from 'nanoid'
import type {
  Document,
  DocumentRow,
  CreateDocumentInput,
  UpdateDocumentInput,
  QueryableField,
} from '../schemas/document'
import { DocumentProjection } from './document-projection'

const DEFAULT_MAX_VERSIONS = 50

/**
 * D29: documents store `created_at`/`updated_at` in SECONDS (see `create`/`saveDraft`), but the legacy
 * `content` table — and therefore the public/CRUD `/api/content` contract — used MILLISECONDS. Any code
 * that shapes a document row into the content response must convert so `new Date(item.created_at)` keeps
 * working for API consumers. Null/undefined pass through unchanged.
 */
export function documentSecondsToMs(ts: number | null | undefined): number | null {
  return ts == null ? null : ts * 1000
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

export interface DocumentsServiceOptions {
  queryableFields?: QueryableField[]
  typeSchemaVersion?: number
  maxVersionsPerRoot?: number
  /** Tenant this service operates within. Every root-keyed lookup is scoped to it (R3). POC default: 'default'. */
  tenantId?: string
}

export class DocumentsService {
  private projection: DocumentProjection
  private tenantId: string

  constructor(
    private db: D1Database,
    private opts: DocumentsServiceOptions = {},
  ) {
    this.projection = new DocumentProjection(db)
    this.tenantId = opts.tenantId ?? 'default'
  }

  // ─── Create ───────────────────────────────────────────────────────────────

  async create(input: CreateDocumentInput, createdBy?: string): Promise<Document> {
    // D23: document timestamps are stored in SECONDS (legacy `content` rows use milliseconds). Any
    // Date() rendering of a document timestamp must multiply by 1000.
    const now = Math.floor(Date.now() / 1000)
    const id = nanoid()
    const publish = input.publishOnCreate ?? false
    // D34: backfill may carry the source row's original timestamps; normal creates default to now.
    const createdAt = input.createdAt ?? now
    const updatedAt = input.updatedAt ?? now

    const doc: Document = {
      id,
      rootId: id,
      typeId: input.typeId,
      typeVersion: this.opts.typeSchemaVersion ?? 1,
      versionOfId: null,
      versionNumber: 1,
      isCurrentDraft: true,
      isPublished: publish,
      status: publish ? 'published' : 'draft',
      parentRootId: input.parentRootId ?? '',
      slug: input.slug ?? null,
      path: null,
      title: input.title ?? null,
      zone: input.zone ?? null,
      sortOrder: input.sortOrder ?? 0,
      visible: input.visible ?? true,
      publishedAt: publish ? createdAt : null,
      scheduledAt: input.scheduledAt ?? null,
      expiresAt: input.expiresAt ?? null,
      deletedAt: null,
      tenantId: input.tenantId,
      locale: input.locale ?? 'default',
      translationGroupId: '',
      data: input.data ?? {},
      metadata: input.metadata ?? {},
      ownerId: input.ownerId ?? null,
      createdBy: createdBy ?? null,
      updatedBy: createdBy ?? null,
      createdAt,
      updatedAt,
    }

    const insertDoc = this.db.prepare(
      `INSERT INTO documents (id, root_id, type_id, type_version, version_of_id, version_number,
         is_current_draft, is_published, status, parent_root_id, slug, path, title, zone,
         sort_order, visible, published_at, scheduled_at, expires_at, deleted_at,
         tenant_id, locale, translation_group_id, data, metadata,
         owner_id, created_by, updated_by, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    ).bind(
      doc.id, doc.rootId, doc.typeId, doc.typeVersion, null, 1,
      1, publish ? 1 : 0, doc.status, doc.parentRootId, doc.slug, null, doc.title, doc.zone,
      doc.sortOrder, doc.visible ? 1 : 0, doc.publishedAt, doc.scheduledAt, doc.expiresAt, null,
      doc.tenantId, doc.locale, '', JSON.stringify(doc.data), JSON.stringify(doc.metadata),
      doc.ownerId, doc.createdBy, doc.updatedBy, createdAt, updatedAt,
    )

    const derivedInserts = this.projection.buildDerivedInsertStatements(doc, this.opts.queryableFields ?? [], now)

    await this.db.batch([insertDoc, ...derivedInserts])
    return doc
  }

  // ─── Save new draft ───────────────────────────────────────────────────────
  // Atomically: demote previous draft → delete its derived rows (if not published) →
  // insert new draft → materialize derived rows → prune excess versions.

  async saveDraft(rootId: string, input: UpdateDocumentInput, updatedBy?: string): Promise<Document> {
    const now = Math.floor(Date.now() / 1000)
    const newId = nanoid()

    // Fetch current state synchronously before starting the batch. Tenant-scoped (R3): a service
    // for tenant B must not find or mutate tenant A's root.
    const prevDraftRow = await this.db
      .prepare('SELECT * FROM documents WHERE root_id = ? AND tenant_id = ? AND is_current_draft = 1')
      .bind(rootId, this.tenantId)
      .first<DocumentRow>()

    if (!prevDraftRow) throw new Error(`No current draft found for root ${rootId}`)

    const prevDraft = rowToDocument(prevDraftRow)

    const mergedData = { ...prevDraft.data, ...(input.data ?? {}) }
    const mergedMeta = { ...prevDraft.metadata, ...(input.metadata ?? {}) }

    const newDoc: Document = {
      ...prevDraft,
      id: newId,
      rootId,
      typeVersion: this.opts.typeSchemaVersion ?? prevDraft.typeVersion,
      versionOfId: prevDraft.id,
      versionNumber: 0, // computed by SQL below
      isCurrentDraft: true,
      isPublished: false,
      status: 'draft',
      slug: input.slug !== undefined ? input.slug ?? null : prevDraft.slug,
      title: input.title !== undefined ? input.title ?? null : prevDraft.title,
      zone: input.zone !== undefined ? input.zone ?? null : prevDraft.zone,
      sortOrder: input.sortOrder ?? prevDraft.sortOrder,
      visible: input.visible ?? prevDraft.visible,
      scheduledAt: input.scheduledAt !== undefined ? input.scheduledAt : prevDraft.scheduledAt,
      expiresAt: input.expiresAt !== undefined ? input.expiresAt : prevDraft.expiresAt,
      data: mergedData,
      metadata: mergedMeta,
      updatedBy: updatedBy ?? prevDraft.updatedBy,
      updatedAt: now,
      createdAt: now,
    }

    const prevIsPublished = prevDraftRow.is_published === 1

    const statements: D1PreparedStatement[] = [
      // 1. Demote previous current draft FIRST (unique index: never two current drafts mid-batch).
      this.db.prepare('UPDATE documents SET is_current_draft = 0, updated_at = ? WHERE id = ? AND tenant_id = ?')
        .bind(now, prevDraft.id, this.tenantId),

      // 2. If the previous draft was not also the published row, delete its derived rows.
      ...(!prevIsPublished ? this.projection.buildDerivedDeleteStatements(prevDraft.id) : []),

      // 3. Insert new draft. version_number derived in SQL (COALESCE(MAX)+1 from existing rows).
      // R5 arithmetic — keep balanced: 30 columns = 5 leading '?' + 1 version_number subquery
      //   + 3 literals (1,0,'draft') + 21 trailing '?'. Total placeholders: 5 + 1 (subquery
      //   root_id) + 21 = 27, which MUST equal the 27 .bind() args below. Do not change one side
      //   without recounting the other.
      this.db.prepare(
        `INSERT INTO documents (id, root_id, type_id, type_version, version_of_id, version_number,
           is_current_draft, is_published, status, parent_root_id, slug, path, title, zone,
           sort_order, visible, published_at, scheduled_at, expires_at, deleted_at,
           tenant_id, locale, translation_group_id, data, metadata,
           owner_id, created_by, updated_by, created_at, updated_at)
         SELECT ?,?,?,?,?,
           (SELECT COALESCE(MAX(version_number), 0) + 1 FROM documents WHERE root_id = ?),
           1,0,'draft',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
         WHERE 1=1`,
      ).bind(
        newId, rootId, newDoc.typeId, newDoc.typeVersion, prevDraft.id,
        rootId,
        newDoc.parentRootId, newDoc.slug, null, newDoc.title, newDoc.zone,
        newDoc.sortOrder, newDoc.visible ? 1 : 0, null, newDoc.scheduledAt, newDoc.expiresAt, null,
        newDoc.tenantId, newDoc.locale, newDoc.translationGroupId,
        JSON.stringify(newDoc.data), JSON.stringify(newDoc.metadata),
        newDoc.ownerId, newDoc.createdBy, newDoc.updatedBy, now, now,
      ),

      // 4. Materialize derived rows for new draft.
      ...this.projection.buildDerivedInsertStatements(newDoc, this.opts.queryableFields ?? [], now),
    ]

    // 5. Prune excess versions (beyond maxVersionsPerRoot), never the published or current-draft row,
    //    and never a version still referenced as version_of_id by another row (FK RESTRICT).
    const maxVersions = this.opts.maxVersionsPerRoot ?? DEFAULT_MAX_VERSIONS
    statements.push(
      this.db.prepare(
        `DELETE FROM documents WHERE root_id = ? AND tenant_id = ? AND is_current_draft = 0 AND is_published = 0
         AND id NOT IN (
           SELECT id FROM documents WHERE root_id = ? AND tenant_id = ? AND is_current_draft = 0 AND is_published = 0
           ORDER BY version_number DESC LIMIT ?
         )
         AND id NOT IN (SELECT version_of_id FROM documents WHERE version_of_id IS NOT NULL AND root_id = ? AND tenant_id = ?)`,
      ).bind(rootId, this.tenantId, rootId, this.tenantId, maxVersions, rootId, this.tenantId),
    )

    await this.db.batch(statements)

    // Fetch the saved row to get the SQL-computed version_number.
    const saved = await this.db
      .prepare('SELECT * FROM documents WHERE id = ?')
      .bind(newId)
      .first<DocumentRow>()
    return rowToDocument(saved!)
  }

  // ─── Publish ──────────────────────────────────────────────────────────────

  async publish(documentId: string, publishedBy?: string): Promise<Document> {
    const now = Math.floor(Date.now() / 1000)

    const targetRow = await this.db
      .prepare('SELECT * FROM documents WHERE id = ? AND tenant_id = ?')
      .bind(documentId, this.tenantId)
      .first<DocumentRow>()

    if (!targetRow) throw new Error(`Document ${documentId} not found`)

    const prevPublishedRow = await this.db
      .prepare('SELECT * FROM documents WHERE root_id = ? AND tenant_id = ? AND is_published = 1 AND id != ?')
      .bind(targetRow.root_id, this.tenantId, documentId)
      .first<DocumentRow>()

    const statements: D1PreparedStatement[] = []

    if (prevPublishedRow) {
      // Clear published flag on the old published row.
      statements.push(
        this.db.prepare('UPDATE documents SET is_published = 0, updated_at = ? WHERE id = ?')
          .bind(now, prevPublishedRow.id),
      )
      // If the old published row is not the current draft, remove its derived rows.
      if (prevPublishedRow.is_current_draft !== 1) {
        statements.push(...this.projection.buildDerivedDeleteStatements(prevPublishedRow.id))
      }
    }

    // Set published on target row.
    statements.push(
      this.db.prepare(
        `UPDATE documents SET is_published = 1, status = 'published', published_at = ?, updated_at = ?, updated_by = ? WHERE id = ?`,
      ).bind(now, now, publishedBy ?? null, documentId),
    )

    // Ensure derived rows exist for the target (they do if it was current draft; materialize if not).
    if (targetRow.is_current_draft !== 1) {
      const targetDoc = rowToDocument(targetRow)
      statements.push(...this.projection.buildDerivedInsertStatements(targetDoc, this.opts.queryableFields ?? [], now))
    }

    await this.db.batch(statements)

    const saved = await this.db.prepare('SELECT * FROM documents WHERE id = ?').bind(documentId).first<DocumentRow>()
    return rowToDocument(saved!)
  }

  // ─── Unpublish ────────────────────────────────────────────────────────────

  async unpublish(documentId: string): Promise<Document> {
    const now = Math.floor(Date.now() / 1000)

    const row = await this.db
      .prepare('SELECT * FROM documents WHERE id = ? AND tenant_id = ?')
      .bind(documentId, this.tenantId)
      .first<DocumentRow>()

    if (!row) throw new Error(`Document ${documentId} not found`)
    if (!row.is_published) throw new Error(`Document ${documentId} is not published`)

    const statements: D1PreparedStatement[] = [
      this.db.prepare(`UPDATE documents SET is_published = 0, status = 'draft', updated_at = ? WHERE id = ?`)
        .bind(now, documentId),
    ]

    // If the unpublished row is not the current draft, remove its derived rows.
    if (row.is_current_draft !== 1) {
      statements.push(...this.projection.buildDerivedDeleteStatements(documentId))
    }

    await this.db.batch(statements)

    const saved = await this.db.prepare('SELECT * FROM documents WHERE id = ?').bind(documentId).first<DocumentRow>()
    return rowToDocument(saved!)
  }

  // ─── Soft delete ──────────────────────────────────────────────────────────

  async softDelete(documentId: string): Promise<void> {
    const now = Math.floor(Date.now() / 1000)
    await this.db
      .prepare('UPDATE documents SET deleted_at = ?, updated_at = ? WHERE id = ? AND tenant_id = ?')
      .bind(now, now, documentId, this.tenantId)
      .run()
  }

  // ─── Hard erase (PII types) ───────────────────────────────────────────────
  // Deletes every version row for a root plus all derived data, in dependency order.

  async erase(rootId: string, tenantId: string): Promise<void> {
    // Get all document IDs for this root.
    const result = await this.db
      .prepare('SELECT id FROM documents WHERE root_id = ? AND tenant_id = ?')
      .bind(rootId, tenantId)
      .all<{ id: string }>()

    const docIds = (result.results ?? []).map(r => r.id)
    if (docIds.length === 0) return

    const statements: D1PreparedStatement[] = []

    // Delete derived tables first (explicit; don't rely on FK cascade).
    for (const id of docIds) {
      statements.push(this.db.prepare('DELETE FROM document_facets WHERE document_id = ?').bind(id))
      statements.push(this.db.prepare('DELETE FROM document_references WHERE from_document_id = ?').bind(id))
    }

    statements.push(this.db.prepare('DELETE FROM document_permissions WHERE root_id = ? AND tenant_id = ?').bind(rootId, tenantId))

    // Delete all version rows.
    for (const id of docIds) {
      statements.push(this.db.prepare('DELETE FROM documents WHERE id = ?').bind(id))
    }

    await this.db.batch(statements)
  }
}
