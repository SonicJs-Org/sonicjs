// @ts-nocheck
// Real-SQLite coverage for the FTS projection seam (T0.2): every DocumentsService write path
// (de)indexes documents_fts atomically. Guards the v1-missed updateInPlace path and the
// publish/unpublish is_published refresh (FTS snapshots is_published for the native public filter).
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import { DocumentsService } from '../../services/documents'
import { DocumentProjection } from '../../services/document-projection'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'
import { MigrationService } from '../../services/migrations'

const FTS_FIELDS = [{ name: 'body', kind: 'fulltext' }]

function svc(db, versioning = false) {
  return new DocumentsService(db, { queryableFields: FTS_FIELDS, tenantId: 'default', typeSchemaVersion: 1, versioning })
}

function search(db, q) {
  return db.raw.prepare('SELECT document_id FROM documents_fts WHERE documents_fts MATCH ?').all(q).map((r) => r.document_id)
}
function searchPublished(db, q) {
  return db.raw
    .prepare('SELECT document_id FROM documents_fts WHERE documents_fts MATCH ? AND is_published = 1')
    .all(q)
    .map((r) => r.document_id)
}

describe('FTS projection seam (T0.2) — real SQLite', () => {
  let db
  beforeEach(() => {
    db = createTestD1()
    db.raw
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
         VALUES ('article','article','Article','{}','[]','{}','system',1,1,1,1,1)`,
      )
      .run()
  })
  afterEach(() => db.close())

  it('create indexes title and body (both searchable)', async () => {
    const s = svc(db)
    const doc = await s.create({ typeId: 'article', tenantId: 'default', title: 'Brewing Coffee', data: { body: 'the quick brown fox' } }, 'u1')
    expect(search(db, 'coffee')).toContain(doc.id) // title
    expect(search(db, 'fox')).toContain(doc.id) // body
  })

  it('flattens a Quill Delta body into searchable prose', async () => {
    const s = svc(db)
    const doc = await s.create(
      { typeId: 'article', tenantId: 'default', title: 'D', data: { body: { ops: [{ insert: 'flamingo paragraph here' }] } } },
      'u1',
    )
    expect(search(db, 'flamingo')).toContain(doc.id)
  })

  it('updateInPlace (default versioning off) reindexes: old text gone, new present', async () => {
    const s = svc(db, false)
    const doc = await s.create({ typeId: 'article', tenantId: 'default', title: 'T', data: { body: 'original walrus text' } }, 'u1')
    expect(search(db, 'walrus')).toContain(doc.id)
    // versioning off + pure draft → updateInPlace (the path v1 missed)
    await s.saveDraft(doc.rootId, { data: { body: 'updated penguin text' } }, 'u1')
    expect(search(db, 'walrus')).toHaveLength(0)
    expect(search(db, 'penguin').length).toBeGreaterThan(0)
  })

  it('saveDraft (versioned) reindexes the new draft', async () => {
    const s = svc(db, true)
    const doc = await s.create({ typeId: 'article', tenantId: 'default', title: 'T', data: { body: 'original aardvark' } }, 'u1')
    const draft = await s.saveDraft(doc.rootId, { data: { body: 'revised meerkat' } }, 'u1')
    expect(search(db, 'meerkat')).toContain(draft.id)
    expect(search(db, 'aardvark')).toHaveLength(0) // prev pure draft deindexed
  })

  it('publish sets is_published=1 in the FTS row (staleness fix)', async () => {
    const s = svc(db)
    const doc = await s.create({ typeId: 'article', tenantId: 'default', title: 'P', data: { body: 'telescope content' } }, 'u1')
    expect(searchPublished(db, 'telescope')).toHaveLength(0) // draft: is_published=0
    await s.publish(doc.id, 'u1')
    expect(searchPublished(db, 'telescope')).toContain(doc.id) // now visible to public filter
  })

  it('unpublish clears is_published in the FTS row', async () => {
    const s = svc(db)
    const doc = await s.create({ typeId: 'article', tenantId: 'default', title: 'P', data: { body: 'nebula content' } }, 'u1')
    await s.publish(doc.id, 'u1')
    expect(searchPublished(db, 'nebula')).toContain(doc.id)
    await s.unpublish(doc.id)
    expect(searchPublished(db, 'nebula')).toHaveLength(0)
    expect(search(db, 'nebula')).toContain(doc.id) // still indexed as a draft (is_published=0)
  })

  it('softDelete deindexes the document', async () => {
    const s = svc(db)
    const doc = await s.create({ typeId: 'article', tenantId: 'default', title: 'X', data: { body: 'mongoose facts' } }, 'u1')
    expect(search(db, 'mongoose')).toContain(doc.id)
    await s.softDelete(doc.id)
    expect(search(db, 'mongoose')).toHaveLength(0)
  })

  it('a hidden (visible=0) document is not indexed', async () => {
    const s = svc(db)
    await s.create({ typeId: 'article', tenantId: 'default', title: 'H', visible: false, data: { body: 'hidden zebra' } }, 'u1')
    expect(search(db, 'zebra')).toHaveLength(0)
  })

  it('erase removes the FTS row', async () => {
    const s = svc(db)
    const doc = await s.create({ typeId: 'article', tenantId: 'default', title: 'E', data: { body: 'erasable octopus' } }, 'u1')
    expect(search(db, 'octopus')).toContain(doc.id)
    await s.erase(doc.rootId, 'default')
    expect(search(db, 'octopus')).toHaveLength(0)
  })

  it('reindexType backfills rows missing from FTS, idempotently (T0.5)', async () => {
    const s = svc(db)
    const doc = await s.create({ typeId: 'article', tenantId: 'default', title: 'Backfill', data: { body: 'pangolin prose' } }, 'u1')
    db.raw.prepare('DELETE FROM documents_fts WHERE document_id = ?').run(doc.id) // simulate a pre-seam doc
    expect(search(db, 'pangolin')).toHaveLength(0)
    const n = await new DocumentProjection(db).reindexType('article', 'default', FTS_FIELDS)
    expect(n).toBeGreaterThanOrEqual(1)
    expect(search(db, 'pangolin')).toContain(doc.id)
    await new DocumentProjection(db).reindexType('article', 'default', FTS_FIELDS) // re-run
    expect(search(db, 'pangolin')).toEqual([doc.id]) // still exactly one (idempotent)
  })

  it('seeded blog_post type indexes HTML content into body (lexical stores HTML)', async () => {
    await bootstrapDocumentTypes(db)
    const row = db.raw.prepare(`SELECT queryable_fields FROM document_types WHERE id = 'blog_post'`).get()
    const fields = JSON.parse(row.queryable_fields)
    expect(fields).toContainEqual(expect.objectContaining({ name: 'content', kind: 'fulltext' }))

    const s = new DocumentsService(db, { queryableFields: fields, tenantId: 'default', typeSchemaVersion: 1, versioning: true })
    const doc = await s.create(
      {
        typeId: 'blog_post',
        tenantId: 'default',
        title: 'Ridge Guide',
        data: { content: '<h2>Trail notes</h2><p>the zebra crossing at dawn</p>', difficulty: 'hard', author: 'trail-team' },
      },
      'u1',
    )
    expect(search(db, 'zebra')).toContain(doc.id) // body prose searchable
    expect(search(db, 'h2')).toHaveLength(0) // HTML tags stripped, not indexed
  })

  it('ensureSchemaCompatibility self-heals a missing documents_fts (upgrade-gap brick guard)', async () => {
    // Simulate an install that upgraded core past 0003 but never ran `wrangler d1 migrations apply`.
    db.raw.prepare('DROP TABLE IF EXISTS documents_fts').run()
    expect(
      db.raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='documents_fts'").get(),
    ).toBeUndefined()

    await new MigrationService(db).ensureSchemaCompatibility()

    expect(
      db.raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='documents_fts'").get(),
    ).toBeTruthy()
    // ...and the recreated table is a usable 10-col FTS5 index — a write path indexes again.
    const doc = await svc(db).create({ typeId: 'article', tenantId: 'default', title: 'Rehealed', data: { body: 'aardvark' } }, 'u1')
    expect(search(db, 'aardvark')).toContain(doc.id)
  })
})
