// @ts-nocheck
// Real-SQLite tests for document-type bootstrap defaults.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes, autoRegisterCollectionDocumentTypes } from '../../services/document-types-seed'
import { DocumentTypeRegistry } from '../../services/document-type-registry'

describe('autoRegisterCollectionDocumentTypes', () => {
  let db
  beforeEach(() => {
    db = createTestD1()
    db.raw.prepare("INSERT INTO collections (id,name,display_name,is_active,source_type,created_at,updated_at) VALUES ('n','news','News',1,NULL,1,1)").run()
    db.raw.prepare("INSERT INTO collections (id,name,display_name,is_active,source_type,created_at,updated_at) VALUES ('p','pages','Pages',1,'user',1,1)").run()
    db.raw.prepare("INSERT INTO collections (id,name,display_name,is_active,source_type,created_at,updated_at) VALUES ('f','contact_form','Contact Form',1,'form',1,1)").run()
    db.raw.prepare("INSERT INTO collections (id,name,display_name,is_active,source_type,created_at,updated_at) VALUES ('x','archived_coll','Archived',0,NULL,1,1)").run()
  })
  afterEach(() => db.close())

  it('does not auto-register DB-driven collections as document types', async () => {
    const registered = await autoRegisterCollectionDocumentTypes(db)
    expect(registered).toEqual([])

    const registry = new DocumentTypeRegistry(db)
    expect(await registry.findById('news')).toBeNull()
    expect(await registry.findById('pages')).toBeNull()
    expect(await registry.findById('contact_form')).toBeNull()
    expect(await registry.findById('archived_coll')).toBeNull()
  })

  it('keeps the code-defined blog_post type hand-tuned', async () => {
    db.raw.prepare("INSERT INTO collections (id,name,display_name,is_active,source_type,created_at,updated_at) VALUES ('b','blog_post','Blog Posts',1,NULL,1,1)").run()
    await bootstrapDocumentTypes(db) // registers blog_post with q_blog_* queryable fields

    const registered = await autoRegisterCollectionDocumentTypes(db)
    expect(registered).toEqual([])

    // blog_post keeps its hand-tuned queryable fields (not flattened to []).
    const blog = await new DocumentTypeRegistry(db).findById('blog_post')
    expect(blog.queryableFields.some(f => f.name === 'difficulty')).toBe(true)
  })

  it('registers only the default blog_post document type', async () => {
    await bootstrapDocumentTypes(db)

    const registry = new DocumentTypeRegistry(db)
    const types = await registry.findAll()

    expect(types.map(t => t.id)).toEqual(['blog_post'])
  })

  it('no-ops when the collections table is absent', async () => {
    const freshDb = createTestD1()
    freshDb.raw.exec('DROP TABLE collections')
    const registered = await autoRegisterCollectionDocumentTypes(freshDb)
    expect(registered).toEqual([])
    freshDb.close()
  })
})
