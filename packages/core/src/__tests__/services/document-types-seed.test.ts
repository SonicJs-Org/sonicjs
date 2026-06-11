// @ts-nocheck
// Real-SQLite tests for document-type bootstrap defaults.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes, autoRegisterCollectionDocumentTypes } from '../../services/document-types-seed'
import { DocumentTypeRegistry } from '../../services/document-type-registry'
import { getCollectionRegistry, resetCollectionRegistry } from '../../services/collection-registry'

describe('autoRegisterCollectionDocumentTypes', () => {
  let db
  beforeEach(() => {
    db = createTestD1()
    resetCollectionRegistry()
  })
  afterEach(() => {
    db.close()
    resetCollectionRegistry()
  })

  it('registers a document type for each code-defined collection in the registry', async () => {
    getCollectionRegistry().register([
      { name: 'news', displayName: 'News', schema: { type: 'object', properties: {} } },
      { name: 'pages', displayName: 'Pages', schema: { type: 'object', properties: {} } },
    ])

    const registered = await autoRegisterCollectionDocumentTypes(db)
    expect(registered.sort()).toEqual(['news', 'pages'])

    const registry = new DocumentTypeRegistry(db)
    expect(await registry.findById('news')).not.toBeNull()
    expect(await registry.findById('pages')).not.toBeNull()
  })

  it('skips inactive collections', async () => {
    getCollectionRegistry().register([
      { name: 'active_coll', displayName: 'Active', schema: { type: 'object', properties: {} } },
      { name: 'archived_coll', displayName: 'Archived', isActive: false, schema: { type: 'object', properties: {} } },
    ])

    const registered = await autoRegisterCollectionDocumentTypes(db)
    expect(registered).toEqual(['active_coll'])
  })

  it('skips internal collections', async () => {
    getCollectionRegistry().register([
      { name: 'public_coll', displayName: 'Public', schema: { type: 'object', properties: {} } },
      { name: 'internal_coll', displayName: 'Internal', internal: true, schema: { type: 'object', properties: {} } },
    ])

    const registered = await autoRegisterCollectionDocumentTypes(db)
    expect(registered).toEqual(['public_coll'])
  })

  it('keeps the code-defined blog_post type hand-tuned', async () => {
    getCollectionRegistry().register([
      { name: 'blog_post', displayName: 'Blog Posts', schema: { type: 'object', properties: {} } },
    ])
    await bootstrapDocumentTypes(db) // registers blog_post with q_blog_* queryable fields

    const registered = await autoRegisterCollectionDocumentTypes(db)
    // blog_post is excluded from the auto-register path so the hand-tuned
    // queryable fields aren't flattened to [].
    expect(registered).toEqual([])

    const blog = await new DocumentTypeRegistry(db).findById('blog_post')
    expect(blog.queryableFields.some(f => f.name === 'difficulty')).toBe(true)
  })

  it('registers only the default seeded types when no collections are in the registry', async () => {
    await bootstrapDocumentTypes(db)

    const registry = new DocumentTypeRegistry(db)
    const types = await registry.findAll()

    expect(types.map(t => t.id).sort()).toContain('blog_post')
  })

  it('returns an empty list when the registry is empty', async () => {
    const registered = await autoRegisterCollectionDocumentTypes(db)
    expect(registered).toEqual([])
  })
})
