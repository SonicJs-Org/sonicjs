// @ts-nocheck
// Real-SQLite coverage for the lexical FTS5 query engine (T1.1) over documents_fts.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import { DocumentsService } from '../../services/documents'
import { Fts5Engine } from '../../plugins/core-plugins/ai-search-plugin/services/fts5-engine'

const FTS_FIELDS = [{ name: 'body', kind: 'fulltext' }]

describe('Fts5Engine — real SQLite', () => {
  let db
  let svc
  beforeEach(() => {
    db = createTestD1()
    db.raw
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
         VALUES ('article','article','Article','{}','[]','{}','system',1,1,1,1,1)`,
      )
      .run()
    svc = new DocumentsService(db, { queryableFields: FTS_FIELDS, tenantId: 'default', typeSchemaVersion: 1, versioning: false })
  })
  afterEach(() => db.close())

  async function published(input) {
    const doc = await svc.create({ typeId: 'article', tenantId: 'default', ...input }, 'u1')
    await svc.publish(doc.id, 'u1')
    return doc
  }

  it('ranks a title hit above a body-only hit and counts total', async () => {
    const a = await published({ title: 'Telescope Guide', slug: 'telescope-guide', data: { body: 'stars and planets' } })
    await published({ title: 'Random Notes', slug: 'random', data: { body: 'a passing telescope mention' } })
    const res = await new Fts5Engine(db).search({ query: 'telescope', tenantId: 'default' })
    expect(res.total).toBe(2)
    expect(res.hits[0].documentId).toBe(a.id) // title boost wins
    expect(res.hits[0].score).toBeGreaterThan(0)
  })

  it('highlights the title and returns a body snippet', async () => {
    await published({ title: 'Brewing Coffee', slug: 'brewing', data: { body: 'the quick brown fox jumps' } })
    const res = await new Fts5Engine(db).search({ query: 'coffee', tenantId: 'default' })
    expect(res.hits[0].title).toContain('<mark>')
  })

  it('matches across porter stemming and folded diacritics', async () => {
    const run = await published({ title: 'Running', slug: 'running', data: { body: 'she runs daily' } })
    const cafe = await published({ title: 'Café Notes', slug: 'cafe', data: { body: 'espresso' } })
    expect((await new Fts5Engine(db).search({ query: 'run', tenantId: 'default' })).hits.map((h) => h.documentId)).toContain(run.id)
    expect((await new Fts5Engine(db).search({ query: 'cafe', tenantId: 'default' })).hits.map((h) => h.documentId)).toContain(cafe.id)
  })

  it('excludes drafts from published-only (default) search', async () => {
    const draft = await svc.create({ typeId: 'article', tenantId: 'default', title: 'Draft telescope piece', data: { body: '' } }, 'u1')
    await published({ title: 'Live telescope piece', slug: 'live', data: { body: '' } })
    const res = await new Fts5Engine(db).search({ query: 'telescope', tenantId: 'default' })
    expect(res.hits.map((h) => h.documentId)).not.toContain(draft.id)
  })

  it('isolates by tenant', async () => {
    await published({ title: 'Telescope', slug: 't', data: { body: '' } })
    const res = await new Fts5Engine(db).search({ query: 'telescope', tenantId: 'other-tenant' })
    expect(res.total).toBe(0)
  })

  it('restricts to requested type ids', async () => {
    db.raw
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
         VALUES ('note','note','Note','{}','[]','{}','system',1,1,1,1,1)`,
      )
      .run()
    const noteSvc = new DocumentsService(db, { queryableFields: FTS_FIELDS, tenantId: 'default', typeSchemaVersion: 1, versioning: false })
    const article = await published({ title: 'Telescope article', slug: 'a', data: { body: '' } })
    const note = await noteSvc.create({ typeId: 'note', tenantId: 'default', title: 'Telescope note', data: { body: '' } }, 'u1')
    await noteSvc.publish(note.id, 'u1')
    const res = await new Fts5Engine(db).search({ query: 'telescope', tenantId: 'default', typeIds: ['article'] })
    expect(res.hits.map((h) => h.documentId)).toEqual([article.id])
  })

  it('returns empty for a query that sanitizes away', async () => {
    await published({ title: 'Hello', slug: 'h', data: { body: 'world' } })
    const res = await new Fts5Engine(db).search({ query: '!!! @#$', tenantId: 'default' })
    expect(res).toEqual({ hits: [], total: 0 })
  })
})
