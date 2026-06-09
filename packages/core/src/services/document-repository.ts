import { D1Database } from '@cloudflare/workers-types'
import type { Document, DocumentRow, PrincipalRef, Permission, DocumentTypeSettings } from '../schemas/document'
import { DocumentPermissionsService } from './document-permissions'

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

export type ListStatus = 'published' | 'draft' | 'all'

export interface ListDocumentsOptions {
  typeId?: string
  /** Which lifecycle axis to list: published row, current-draft row, or either. */
  status?: ListStatus
  locale?: string
  parentRootId?: string
  limit?: number
  cursorUpdatedAt?: number
  cursorId?: string
  now?: number
  /** Resolved generated-column filters, e.g. { column: 'q_tst_rating', value: 4 }. Caller maps
   *  field→column via the type's queryableFields; column names are format-guarded here too. */
  scalarFilters?: Array<{ column: string; value: string | number }>
  /** Multi-valued facet filter, e.g. { field: 'tags', value: 'homepage' }. Bound as params. */
  facetFilter?: { field: string; value: string }
  /** Generated-column to sort by (else keyset on updated_at). Format-guarded. */
  sortColumn?: string | null
  sortDir?: 'ASC' | 'DESC'
  /** Apply the schedule window (scheduled_at/expires_at) — public reads only. */
  timeWindow?: boolean
}

// Generated-column / sort identifiers are interpolated into SQL (column names cannot be bound), so
// every interpolated identifier must match this before it reaches a query. Callers resolve them from
// trusted queryableFields config; this is defense-in-depth against a raw user string slipping through.
const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/

// Single tenant-scoped data-access chokepoint. All reads and writes go through here.
// tenant_id is injected from constructor context; route handlers never build raw SQL.
export class DocumentRepository {
  private permissions: DocumentPermissionsService

  constructor(
    private db: D1Database,
    private tenantId: string,
  ) {
    this.permissions = new DocumentPermissionsService(db)
  }

  // ─── Reads ───────────────────────────────────────────────────────────────

  async getById(id: string): Promise<Document | null> {
    const row = await this.db
      .prepare('SELECT * FROM documents WHERE id = ? AND tenant_id = ?')
      .bind(id, this.tenantId)
      .first<DocumentRow>()
    return row ? rowToDocument(row) : null
  }

  async getCurrentDraft(rootId: string): Promise<Document | null> {
    const row = await this.db
      .prepare('SELECT * FROM documents WHERE root_id = ? AND tenant_id = ? AND is_current_draft = 1')
      .bind(rootId, this.tenantId)
      .first<DocumentRow>()
    return row ? rowToDocument(row) : null
  }

  async getPublished(rootId: string): Promise<Document | null> {
    const row = await this.db
      .prepare('SELECT * FROM documents WHERE root_id = ? AND tenant_id = ? AND is_published = 1')
      .bind(rootId, this.tenantId)
      .first<DocumentRow>()
    return row ? rowToDocument(row) : null
  }

  // Unified, tenant-scoped list with optional generated-column / facet filters and sort. This is the
  // single place document list SQL is built — route handlers must call this, never inline SQL (R4).
  async list(opts: ListDocumentsOptions = {}): Promise<Document[]> {
    const limit = Math.min(opts.limit ?? 50, 200)
    const status: ListStatus = opts.status ?? 'published'
    const useFacetJoin = !!opts.facetFilter
    const p = useFacetJoin ? 'd.' : '' // column prefix when joining facets

    const params: (string | number)[] = [this.tenantId]
    let sql = useFacetJoin
      ? 'SELECT d.* FROM documents d JOIN document_facets f ON f.document_id = d.id WHERE d.tenant_id = ?'
      : 'SELECT * FROM documents WHERE tenant_id = ?'

    sql += ` AND ${p}deleted_at IS NULL`

    if (opts.typeId) { sql += ` AND ${p}type_id = ?`; params.push(opts.typeId) }

    if (status === 'published') sql += ` AND ${p}is_published = 1`
    else if (status === 'draft') sql += ` AND ${p}is_current_draft = 1`
    else sql += ` AND (${p}is_published = 1 OR ${p}is_current_draft = 1)`

    if (opts.facetFilter) {
      sql += ' AND f.field_name = ? AND f.value_text = ?'
      params.push(opts.facetFilter.field, opts.facetFilter.value)
    }

    if (opts.timeWindow) {
      const now = opts.now ?? Math.floor(Date.now() / 1000)
      sql += ` AND (${p}scheduled_at IS NULL OR ${p}scheduled_at <= ?) AND (${p}expires_at IS NULL OR ${p}expires_at > ?)`
      params.push(now, now)
    }

    if (opts.locale && opts.locale !== 'default') { sql += ` AND ${p}locale = ?`; params.push(opts.locale) }
    if (opts.parentRootId !== undefined) { sql += ` AND ${p}parent_root_id = ?`; params.push(opts.parentRootId) }

    for (const sf of opts.scalarFilters ?? []) {
      if (!SAFE_IDENTIFIER.test(sf.column)) throw new Error(`Unsafe filter column: ${sf.column}`)
      sql += ` AND ${p}${sf.column} = ?`
      params.push(sf.value)
    }

    if (opts.cursorUpdatedAt !== undefined && opts.cursorId) {
      sql += ` AND (${p}updated_at < ? OR (${p}updated_at = ? AND ${p}id < ?))`
      params.push(opts.cursorUpdatedAt, opts.cursorUpdatedAt, opts.cursorId)
    }

    const dir = opts.sortDir === 'ASC' ? 'ASC' : 'DESC'
    if (opts.sortColumn) {
      if (!SAFE_IDENTIFIER.test(opts.sortColumn)) throw new Error(`Unsafe sort column: ${opts.sortColumn}`)
      sql += ` ORDER BY ${p}${opts.sortColumn} ${dir}, ${p}id ${dir} LIMIT ?`
    } else {
      sql += ` ORDER BY ${p}updated_at ${dir}, ${p}id ${dir} LIMIT ?`
    }
    params.push(limit)

    const result = await this.db.prepare(sql).bind(...params).all<DocumentRow>()
    return (result.results ?? []).map(rowToDocument)
  }

  listPublished(opts: ListDocumentsOptions = {}): Promise<Document[]> {
    return this.list({ ...opts, status: 'published', timeWindow: true })
  }

  listDrafts(opts: ListDocumentsOptions = {}): Promise<Document[]> {
    return this.list({ ...opts, status: 'draft' })
  }

  async getVersionHistory(rootId: string): Promise<Document[]> {
    const result = await this.db
      .prepare('SELECT * FROM documents WHERE root_id = ? AND tenant_id = ? ORDER BY version_number DESC')
      .bind(rootId, this.tenantId)
      .all<DocumentRow>()
    return (result.results ?? []).map(rowToDocument)
  }

  // ─── "Where Used" lookup ──────────────────────────────────────────────────

  async getInboundReferences(toRootId: string): Promise<Array<{ fromDocumentId: string; fieldName: string; refStrength: string }>> {
    const result = await this.db
      .prepare(
        `SELECT r.from_document_id, r.field_name, r.ref_strength
         FROM document_references r
         JOIN documents d ON d.id = r.from_document_id
         WHERE r.tenant_id = ? AND r.to_root_id = ?
           AND (d.is_published = 1 OR d.is_current_draft = 1)
           AND d.deleted_at IS NULL`,
      )
      .bind(this.tenantId, toRootId)
      .all<{ from_document_id: string; field_name: string; ref_strength: string }>()

    return (result.results ?? []).map(r => ({
      fromDocumentId: r.from_document_id,
      fieldName: r.field_name,
      refStrength: r.ref_strength,
    }))
  }

  // ─── ACL ──────────────────────────────────────────────────────────────────

  async isAllowed(
    principalSet: PrincipalRef[],
    rootId: string,
    permission: Permission,
    typeSettings: DocumentTypeSettings,
  ): Promise<boolean> {
    return this.permissions.isAllowed(principalSet, rootId, permission, typeSettings, this.tenantId)
  }
}
