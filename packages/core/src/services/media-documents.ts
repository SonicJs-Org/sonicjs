import { D1Database } from '@cloudflare/workers-types'
import type { Document, QueryableField } from '../schemas/document'
import { DocumentsService } from './documents'
import { DocumentRepository } from './document-repository'
import { createDocumentSchema } from '../schemas/document'

// Media as documents (Phase 6). File bytes stay in R2; metadata becomes a `media_asset` document.
// The document payload stores only intrinsic facts (r2Key, dimensions, mime…) — NOT publicUrl/
// thumbnailUrl, which are DERIVED at read time so the URL/transform strategy can change without
// rewriting stored data. The adapters below reproduce the legacy `media` row + MediaFile view-model
// shapes so existing consumers keep working.

export interface MediaUploadMeta {
  filename: string
  originalName: string
  mimeType: string
  size: number
  width?: number | null
  height?: number | null
  folder: string
  r2Key: string
  alt?: string
  caption?: string
  tags?: string[]
}

export interface MediaUrlOptions {
  /** R2 public host, e.g. 'pub-xxxx.r2.dev' (matches the upload path's publicUrl). */
  r2PublicHost?: string
  /** Cloudflare Images account id for thumbnail delivery. */
  imagesAccountId?: string
}

// media_asset queryable fields — mirror migration 043 (q_media_*) + the document type registration.
export const MEDIA_QUERYABLE: QueryableField[] = [
  { name: 'mimeType', kind: 'scalar', type: 'text', column: 'q_media_mime' },
  { name: 'folder', kind: 'scalar', type: 'text', column: 'q_media_folder' },
  { name: 'size', kind: 'scalar', type: 'integer', column: 'q_media_size' },
  { name: 'tags', kind: 'facet', type: 'text' },
]

export function deriveMediaPublicUrl(r2Key: string, opts: MediaUrlOptions = {}): string {
  // Default matches the admin media library's serving route (/files/<r2Key>); pass r2PublicHost for
  // the public R2 domain instead.
  return opts.r2PublicHost ? `https://${opts.r2PublicHost}/${r2Key}` : `/files/${r2Key}`
}

export function deriveMediaThumbnailUrl(r2Key: string, mimeType: string, opts: MediaUrlOptions = {}): string | null {
  return mimeType.startsWith('image/') && opts.imagesAccountId
    ? `https://imagedelivery.net/${opts.imagesAccountId}/${r2Key}/thumbnail`
    : null
}

function formatFileSize(bytes: number): string {
  if (!bytes) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

/** Map a media_asset document to the legacy `media` table row shape (URLs derived). */
export function mediaDocToRecord(doc: Document, opts: MediaUrlOptions = {}) {
  const d = doc.data as Record<string, any>
  return {
    id: doc.rootId,
    filename: d.filename ?? '',
    original_name: d.originalName ?? d.filename ?? '',
    mime_type: d.mimeType ?? '',
    size: d.size ?? 0,
    width: d.width ?? null,
    height: d.height ?? null,
    folder: d.folder ?? 'uploads',
    r2_key: d.r2Key ?? '',
    public_url: deriveMediaPublicUrl(d.r2Key ?? '', opts),
    thumbnail_url: deriveMediaThumbnailUrl(d.r2Key ?? '', d.mimeType ?? '', opts),
    alt: d.alt ?? null,
    caption: d.caption ?? null,
    tags: Array.isArray(d.tags) ? d.tags : [],
    uploaded_by: doc.ownerId ?? doc.createdBy ?? null,
    uploaded_at: doc.createdAt,
    updated_at: doc.updatedAt,
  }
}

/** Map a media_asset document to the MediaFile view-model used by the media grid. */
export function mediaDocToFile(doc: Document, opts: MediaUrlOptions = {}) {
  const d = doc.data as Record<string, any>
  const mime = d.mimeType ?? ''
  const iso = new Date((doc.createdAt ?? 0) * 1000).toISOString()
  return {
    id: doc.rootId,
    filename: d.filename ?? '',
    original_name: d.originalName ?? d.filename ?? '',
    mime_type: mime,
    size: d.size ?? 0,
    public_url: deriveMediaPublicUrl(d.r2Key ?? '', opts),
    thumbnail_url: deriveMediaThumbnailUrl(d.r2Key ?? '', mime, opts) ?? undefined,
    alt: d.alt ?? undefined,
    caption: d.caption ?? undefined,
    tags: Array.isArray(d.tags) ? d.tags : [],
    uploaded_at: iso,
    fileSize: formatFileSize(d.size ?? 0),
    uploadedAt: iso,
    isImage: mime.startsWith('image/'),
    isVideo: mime.startsWith('video/'),
    isDocument: !mime.startsWith('image/') && !mime.startsWith('video/'),
  }
}

function rowToMinimalDoc(row: Record<string, any>): Document {
  return {
    id: row.id,
    rootId: row.root_id,
    typeId: row.type_id,
    data: typeof row.data === 'string' ? JSON.parse(row.data) : (row.data ?? {}),
    ownerId: row.owner_id ?? null,
    createdBy: row.created_by ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  } as unknown as Document
}

export interface MediaListOptions {
  folder?: string
  type?: 'all' | 'images' | 'videos' | 'documents' | string
  limit?: number
  offset?: number
}

export interface MediaListResult {
  files: Document[]
  folders: Array<{ folder: string; count: number; totalSize: number }>
  types: Array<{ type: string; count: number }>
}

export interface MediaDeleteImpact {
  canHardDelete: boolean
  strongRefs: Array<{ fromDocumentId: string; fieldName: string }>
  weakRefs: Array<{ fromDocumentId: string; fieldName: string }>
}

export class MediaDocumentService {
  constructor(private db: D1Database, private tenantId = 'default') {}

  /** Create a media_asset document from R2 upload metadata. Published-on-create (immediately usable). */
  async createFromUpload(meta: MediaUploadMeta, createdBy?: string): Promise<Document> {
    const svc = new DocumentsService(this.db, { queryableFields: MEDIA_QUERYABLE, tenantId: this.tenantId, maxVersionsPerRoot: 5 })
    return svc.create(
      createDocumentSchema.parse({
        typeId: 'media_asset',
        tenantId: this.tenantId,
        locale: 'default',
        title: meta.originalName || meta.filename,
        data: {
          filename: meta.filename,
          originalName: meta.originalName,
          mimeType: meta.mimeType,
          size: meta.size,
          width: meta.width ?? null,
          height: meta.height ?? null,
          folder: meta.folder,
          r2Key: meta.r2Key,
          alt: meta.alt ?? '',
          caption: meta.caption ?? '',
          tags: meta.tags ?? [],
        },
        ownerId: createdBy ?? null,
        publishOnCreate: true,
      }),
      createdBy,
    )
  }

  /**
   * Media library list sourced from media_asset documents — folder/type filters + folder/type
   * aggregations all run off the q_media_* generated columns (the same shape the legacy `media` query
   * used). Building block for flipping the admin media library reads to documents.
   */
  async list(opts: MediaListOptions = {}): Promise<MediaListResult> {
    const limit = Math.min(opts.limit ?? 24, 200)
    const offset = opts.offset ?? 0
    const base = "type_id = 'media_asset' AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL"

    const where = [base]
    const params: (string | number)[] = [this.tenantId]
    if (opts.folder && opts.folder !== 'all') {
      where.push('q_media_folder = ?')
      params.push(opts.folder)
    }
    if (opts.type && opts.type !== 'all') {
      if (opts.type === 'images') where.push("q_media_mime LIKE 'image/%'")
      else if (opts.type === 'videos') where.push("q_media_mime LIKE 'video/%'")
      else if (opts.type === 'documents') where.push("q_media_mime IN ('application/pdf', 'text/plain', 'application/msword')")
    }

    const listed = await this.db
      .prepare(`SELECT * FROM documents WHERE ${where.join(' AND ')} ORDER BY updated_at DESC LIMIT ? OFFSET ?`)
      .bind(...params, limit, offset)
      .all<Record<string, any>>()
    const files = (listed.results ?? []).map(rowToMinimalDoc)

    // Aggregations cover ALL media (not the folder/type-filtered page), matching the legacy sidebar.
    const folderAgg = await this.db
      .prepare(`SELECT q_media_folder AS folder, COUNT(*) AS count, SUM(q_media_size) AS totalSize FROM documents WHERE ${base} GROUP BY q_media_folder ORDER BY q_media_folder`)
      .bind(this.tenantId)
      .all<{ folder: string; count: number; totalSize: number }>()
    const typeAgg = await this.db
      .prepare(`SELECT CASE WHEN q_media_mime LIKE 'image/%' THEN 'images' WHEN q_media_mime LIKE 'video/%' THEN 'videos' WHEN q_media_mime IN ('application/pdf', 'text/plain') THEN 'documents' ELSE 'other' END AS type, COUNT(*) AS count FROM documents WHERE ${base} GROUP BY type`)
      .bind(this.tenantId)
      .all<{ type: string; count: number }>()

    return {
      files,
      folders: (folderAgg.results ?? []).map(f => ({ folder: f.folder, count: f.count, totalSize: f.totalSize ?? 0 })),
      types: (typeAgg.results ?? []).map(t => ({ type: t.type, count: t.count })),
    }
  }

  /** Fetch the current-draft media_asset document by its root id (tenant-scoped). Null if absent/deleted. */
  async getByRootId(rootId: string): Promise<Document | null> {
    const row = await this.db
      .prepare("SELECT * FROM documents WHERE root_id = ? AND type_id = 'media_asset' AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL")
      .bind(rootId, this.tenantId)
      .first<Record<string, any>>()
    return row ? rowToMinimalDoc(row) : null
  }

  /**
   * Soft-delete every version row of a media_asset root (sets deleted_at). The library list and
   * getByRootId both filter `deleted_at IS NULL`, so the asset disappears from reads but the rows
   * (and R2 object lifecycle) remain for audit. Returns true if any row was updated.
   */
  async softDelete(rootId: string): Promise<boolean> {
    const res = await this.db
      .prepare("UPDATE documents SET deleted_at = ?, updated_at = ? WHERE root_id = ? AND type_id = 'media_asset' AND tenant_id = ? AND deleted_at IS NULL")
      .bind(Math.floor(Date.now() / 1000), Math.floor(Date.now() / 1000), rootId, this.tenantId)
      .run()
    return (res.meta?.changes ?? 0) > 0
  }

  /**
   * In-place metadata edit of the current media_asset row (alt / caption / folder). Uses json_set so the
   * q_media_* generated columns recompute; media metadata is not versioned content, so this avoids draft
   * churn. (tags faceting is owned by the create path — not updated here.) Returns true if a row changed.
   */
  async updateMetadata(rootId: string, patch: Record<string, any>): Promise<boolean> {
    const allowed = ['alt', 'caption', 'folder']
    const sets: string[] = []
    const binds: (string | number)[] = []
    for (const k of allowed) {
      if (k in patch && patch[k] != null) {
        sets.push(`'$.${k}', ?`)
        binds.push(String(patch[k]))
      }
    }
    if (sets.length === 0) return false
    const res = await this.db
      .prepare(
        `UPDATE documents SET data = json_set(data, ${sets.join(', ')}), updated_at = ?
         WHERE root_id = ? AND type_id = 'media_asset' AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL`,
      )
      .bind(...binds, Math.floor(Date.now() / 1000), rootId, this.tenantId)
      .run()
    return (res.meta?.changes ?? 0) > 0
  }

  /** Reference-aware delete: strong inbound references block hard-delete (offer archive instead). */
  async getDeleteImpact(mediaRootId: string): Promise<MediaDeleteImpact> {
    const refs = await new DocumentRepository(this.db, this.tenantId).getInboundReferences(mediaRootId)
    const strongRefs = refs.filter(r => r.refStrength === 'strong').map(r => ({ fromDocumentId: r.fromDocumentId, fieldName: r.fieldName }))
    const weakRefs = refs.filter(r => r.refStrength !== 'strong').map(r => ({ fromDocumentId: r.fromDocumentId, fieldName: r.fieldName }))
    return { canHardDelete: strongRefs.length === 0, strongRefs, weakRefs }
  }
}

/**
 * Whether the legacy `media` table still exists. The greenfield (document-model) schema never creates
 * it, so every legacy `media` read/write must be guarded with this — media is authoritative in
 * `documents` (media_asset). Legacy writes are best-effort dual-writes only where the table is present.
 */
export async function legacyMediaTableExists(db: D1Database): Promise<boolean> {
  try {
    const row = await db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'media'")
      .first()
    return !!row
  } catch {
    return false
  }
}
