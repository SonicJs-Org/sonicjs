// @ts-nocheck
// Real-SQLite tests for media-as-document (Phase 6): the media_asset create path, the legacy-shape
// compatibility adapters (URLs derived from r2Key), and reference-aware delete.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'
import { DocumentsService } from '../../services/documents'
import {
  MediaDocumentService,
  MEDIA_QUERYABLE,
  mediaDocToRecord,
  mediaDocToFile,
  deriveMediaPublicUrl,
  deriveMediaThumbnailUrl,
} from '../../services/media-documents'

const META = {
  filename: 'hero.jpg',
  originalName: 'Hero.jpg',
  mimeType: 'image/jpeg',
  size: 123456,
  width: 1600,
  height: 900,
  folder: 'uploads',
  r2Key: 'uploads/hero.jpg',
  alt: 'Hero',
  tags: ['homepage'],
}

describe('media-as-document (Phase 6)', () => {
  let db
  beforeEach(async () => {
    db = createTestD1()
    await bootstrapDocumentTypes(db)
    // Migrations ship only the base documents schema; add the media_asset q_media_* generated columns.
    await db.applyScalarSchema('media_asset', MEDIA_QUERYABLE)
  })
  afterEach(() => db.close())

  it('createFromUpload stores a media_asset doc with generated columns + tags facet', async () => {
    const doc = await new MediaDocumentService(db).createFromUpload(META, 'u1')
    expect(doc.typeId).toBe('media_asset')
    expect(doc.isPublished).toBe(true)

    const row = db.raw.prepare('SELECT q_media_mime m, q_media_folder f, q_media_size s FROM documents WHERE id=?').get(doc.id)
    expect(row.m).toBe('image/jpeg')
    expect(row.f).toBe('uploads')
    expect(row.s).toBe(123456)

    const facets = db.raw.prepare("SELECT value_text v FROM document_facets WHERE document_id=? AND field_name='tags'").all(doc.id)
    expect(facets.map(f => f.v)).toEqual(['homepage'])
  })

  it('adapter reproduces the legacy media row shape with derived URLs', () => {
    const doc = { rootId: 'r1', data: { ...META }, ownerId: 'u1', createdAt: 1000, updatedAt: 1000 }
    const rec = mediaDocToRecord(doc, { r2PublicHost: 'pub-x.r2.dev', imagesAccountId: 'acct1' })
    expect(rec.id).toBe('r1')
    expect(rec.original_name).toBe('Hero.jpg')
    expect(rec.mime_type).toBe('image/jpeg')
    expect(rec.r2_key).toBe('uploads/hero.jpg')
    expect(rec.public_url).toBe('https://pub-x.r2.dev/uploads/hero.jpg')
    expect(rec.thumbnail_url).toBe('https://imagedelivery.net/acct1/uploads/hero.jpg/thumbnail')
    expect(rec.tags).toEqual(['homepage'])
    expect(rec.uploaded_by).toBe('u1')
  })

  it('adapter reproduces the MediaFile view-model (fileSize, isImage)', () => {
    const doc = { rootId: 'r1', data: { ...META }, ownerId: 'u1', createdAt: 1000, updatedAt: 1000 }
    const file = mediaDocToFile(doc)
    expect(file.isImage).toBe(true)
    expect(file.isVideo).toBe(false)
    expect(file.isDocument).toBe(false)
    expect(file.fileSize).toBe('120.6 KB')
    expect(file.public_url).toBe('/files/uploads/hero.jpg') // no host configured → relative
  })

  it('mediaDocToFile converts seconds-based createdAt to a valid non-1970 uploadedAt (issue #889)', () => {
    // Regression: createdAt is stored in SECONDS (not ms). mediaDocToFile must multiply by 1000
    // before passing to Date, otherwise new Date(seconds) resolves to ~1970.
    const nowSeconds = Math.floor(Date.now() / 1000) // e.g. 1750000000
    const doc = { rootId: 'r1', data: { ...META }, ownerId: 'u1', createdAt: nowSeconds, updatedAt: nowSeconds }
    const file = mediaDocToFile(doc)

    const uploadedDate = new Date(file.uploadedAt)
    expect(uploadedDate.getFullYear()).toBeGreaterThanOrEqual(2024)
    // Sanity: uploaded_at from the ISO string must NOT be epoch (1970)
    expect(uploadedDate.getFullYear()).not.toBe(1970)
  })

  it('createFromUpload produces a doc whose uploadedAt is a valid current-year date (issue #889)', async () => {
    const svc = new MediaDocumentService(db)
    const doc = await svc.createFromUpload(META, 'u1')
    const file = mediaDocToFile(doc)

    const uploadedDate = new Date(file.uploadedAt)
    expect(uploadedDate.getFullYear()).toBeGreaterThanOrEqual(2024)
    expect(uploadedDate.getFullYear()).not.toBe(1970)
    // uploaded_at string must be a valid ISO 8601 date
    expect(file.uploadedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })

  it('list() returns newest uploads first (updated_at DESC, issue #889 sort regression)', async () => {
    const svc = new MediaDocumentService(db)
    // Upload three files with a small delay to ensure distinct updated_at values
    const a = await svc.createFromUpload({ ...META, filename: 'old.jpg', r2Key: 'uploads/old.jpg' }, 'u1')
    // Force older updated_at on first file to guarantee ordering
    db.raw.prepare('UPDATE documents SET updated_at = updated_at - 10 WHERE id = ?').run(a.id)
    const b = await svc.createFromUpload({ ...META, filename: 'new.jpg', r2Key: 'uploads/new.jpg' }, 'u1')

    const { files } = await svc.list()
    expect(files).toHaveLength(2)
    // Newest file (b) must appear first
    expect((files[0].data as any).filename).toBe('new.jpg')
    expect((files[1].data as any).filename).toBe('old.jpg')
    // Both dates must be valid non-1970
    for (const f of files) {
      const year = new Date(mediaDocToFile(f).uploadedAt).getFullYear()
      expect(year).toBeGreaterThanOrEqual(2024)
    }
  })

  it('thumbnail only for images with an Images account', () => {
    expect(deriveMediaThumbnailUrl('a/b.pdf', 'application/pdf', { imagesAccountId: 'x' })).toBeNull()
    expect(deriveMediaThumbnailUrl('a/b.jpg', 'image/jpeg', {})).toBeNull()
    expect(deriveMediaPublicUrl('a/b.jpg', {})).toBe('/files/a/b.jpg')
  })

  it('list() filters by folder/type and aggregates folders/types via generated columns', async () => {
    const svc = new MediaDocumentService(db)
    await svc.createFromUpload({ ...META, filename: 'a.jpg', r2Key: 'uploads/a.jpg', mimeType: 'image/jpeg', folder: 'uploads', size: 10 }, 'u1')
    await svc.createFromUpload({ ...META, filename: 'b.png', r2Key: 'photos/b.png', mimeType: 'image/png', folder: 'photos', size: 20, tags: [] }, 'u1')
    await svc.createFromUpload({ ...META, filename: 'c.pdf', r2Key: 'docs/c.pdf', mimeType: 'application/pdf', folder: 'docs', size: 30, tags: [] }, 'u1')

    const all = await svc.list()
    expect(all.files).toHaveLength(3)

    const images = await svc.list({ type: 'images' })
    expect(images.files).toHaveLength(2)

    const docs = await svc.list({ type: 'documents' })
    expect(docs.files.map(f => f.data.filename)).toEqual(['c.pdf'])

    const inPhotos = await svc.list({ folder: 'photos' })
    expect(inPhotos.files.map(f => f.data.filename)).toEqual(['b.png'])

    // aggregations cover all media regardless of the page filter
    const folderCounts = Object.fromEntries(all.folders.map(f => [f.folder, f.count]))
    expect(folderCounts).toMatchObject({ uploads: 1, photos: 1, docs: 1 })
    const typeCounts = Object.fromEntries(all.types.map(t => [t.type, t.count]))
    expect(typeCounts).toMatchObject({ images: 2, documents: 1 })
    // a listed file maps cleanly to the MediaFile view-model
    expect(mediaDocToFile(inPhotos.files[0]).isImage).toBe(true)
  })

  it('reference-aware delete: a strong inbound reference blocks hard-delete; weak does not', async () => {
    const mediaSvc = new MediaDocumentService(db)
    const media = await mediaSvc.createFromUpload(META, 'u1')

    // A live consumer document that references the media root.
    const consumer = await new DocumentsService(db, { tenantId: 'default' }).create(
      { typeId: 'faq', tenantId: 'default', data: { category: 'g' }, publishOnCreate: true },
      'u1',
    )

    // Distinct field_name per ref so they don't collide on idx_docref_unique(from_document_id,field_name,ordinal).
    const addRef = (strength) =>
      db.raw
        .prepare("INSERT INTO document_references (id,tenant_id,from_root_id,from_document_id,field_name,ordinal,to_root_id,ref_strength,created_at) VALUES (?,?,?,?,?,?,?,?,?)")
        .run(`ref-${strength}`, 'default', consumer.rootId, consumer.id, `image_${strength}`, 0, media.rootId, strength, 1)

    addRef('weak')
    let impact = await mediaSvc.getDeleteImpact(media.rootId)
    expect(impact.canHardDelete).toBe(true)
    expect(impact.weakRefs).toHaveLength(1)

    addRef('strong')
    impact = await mediaSvc.getDeleteImpact(media.rootId)
    expect(impact.canHardDelete).toBe(false)
    expect(impact.strongRefs).toHaveLength(1)
  })
})
