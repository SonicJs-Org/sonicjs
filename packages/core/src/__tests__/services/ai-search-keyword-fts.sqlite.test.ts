// @ts-nocheck
// Integration coverage for T1.2: the ai-search-plugin keyword mode now serves FTS5 over documents_fts,
// and an 'ai' request with no bindings degrades to the lexical floor (LA4).
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import { DocumentsService } from '../../services/documents'
import { AISearchService } from '../../plugins/core-plugins/ai-search-plugin/services/ai-search'

const FTS_FIELDS = [{ name: 'body', kind: 'fulltext' }]

describe('AISearchService keyword mode = FTS5 (T1.2)', () => {
  let db
  let docs
  beforeEach(() => {
    db = createTestD1()
    db.raw
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
         VALUES ('article','article','Article','{}','[]','{}','system',1,1,1,1,1)`,
      )
      .run()
    docs = new DocumentsService(db, { queryableFields: FTS_FIELDS, tenantId: 'default', typeSchemaVersion: 1, versioning: false })
  })
  afterEach(() => db.close())

  async function pub(input) {
    const d = await docs.create({ typeId: 'article', tenantId: 'default', ...input }, 'u1')
    await docs.publish(d.id, 'u1')
    return d
  }

  it('keyword mode returns FTS-ranked published results', async () => {
    const a = await pub({ title: 'Telescope Guide', slug: 'tg', data: { body: 'stars' } })
    await pub({ title: 'Sidebar', slug: 'sb', data: { body: 'a telescope mention' } })
    const svc = new AISearchService(db, undefined, undefined, 'default')
    const res = await svc.search({ query: 'telescope', mode: 'keyword', filters: {}, limit: 10 })
    expect(res.mode).toBe('keyword')
    expect(res.total).toBe(2)
    expect(res.results[0].id).toBe(a.id) // title boost wins
    expect(res.results[0].relevance_score).toBeGreaterThan(0)
    expect(res.results[0].collection_id).toBe('article') // type_id surfaced as collection_id
  })

  it('excludes drafts from public keyword search', async () => {
    const draft = await docs.create({ typeId: 'article', tenantId: 'default', title: 'Draft penguin', data: { body: '' } }, 'u1')
    await pub({ title: 'Live penguin', slug: 'lp', data: { body: '' } })
    const svc = new AISearchService(db, undefined, undefined, 'default')
    const res = await svc.search({ query: 'penguin', mode: 'keyword', filters: {} })
    expect(res.results.map((r) => r.id)).not.toContain(draft.id)
  })

  it("an 'ai' request with no AI bindings degrades to the lexical floor (degraded:true)", async () => {
    await pub({ title: 'Nebula', slug: 'n', data: { body: 'cosmic dust' } })
    const svc = new AISearchService(db, undefined, undefined, 'default') // no ai/vectorize → no customRAG
    const res = await svc.search({ query: 'nebula', mode: 'ai', filters: {} })
    expect(res.degraded).toBe(true)
    expect(res.results.length).toBeGreaterThan(0)
  })

  it('scopes results by tenant', async () => {
    await pub({ title: 'Telescope', slug: 't', data: { body: '' } })
    const other = new AISearchService(db, undefined, undefined, 'other-tenant')
    const res = await other.search({ query: 'telescope', mode: 'keyword', filters: {} })
    expect(res.total).toBe(0)
  })
})
