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
         VALUES ('article','article','Article','{}','[]','{"baseGrants":{"public":["read"]}}','system',1,1,1,1,1)`,
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

  // ── SECURITY regressions (fresh-review findings) ─────────────────────────────────────────────

  it('excludes internal (non-public-read) types from public search — even if requested by name (D5)', async () => {
    // An admin-only type: baseGrants has NO public read. Mirrors api_key/security_event/analytics_event.
    db.raw
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
         VALUES ('api_key','api_key','API Key','{}','[]','{"baseGrants":{"admin":["read"]}}','system',1,1,1,1,1)`,
      )
      .run()
    const secret = new DocumentsService(db, { queryableFields: [], tenantId: 'default', typeSchemaVersion: 1, versioning: false })
    const k = await secret.create({ typeId: 'api_key', tenantId: 'default', title: 'Stripe webhook key', slug: 'sk', data: {} }, 'u1')
    await secret.publish(k.id, 'u1') // published + visible → the row IS in documents_fts

    // Precondition: the internal doc really is indexed (so exclusion, not absence, is what's tested).
    const indexed = db.raw.prepare('SELECT document_id FROM documents_fts WHERE documents_fts MATCH ?').all('stripe')
    expect(indexed.map((r) => r.document_id)).toContain(k.id)

    const svc = new AISearchService(db, undefined, undefined, 'default')
    // default scope
    expect((await svc.search({ query: 'stripe', mode: 'keyword', filters: {} })).results.map((r) => r.id)).not.toContain(k.id)
    // even when the client explicitly asks for the internal type — the allowlist only narrows
    const forced = await svc.search({ query: 'stripe', mode: 'keyword', filters: { collections: ['api_key'] } })
    expect(forced.results.map((r) => r.id)).not.toContain(k.id)
    expect(forced.total).toBe(0)
  })

  it('does NOT expose drafts even when the client sends filters.status:[draft] (published gate is server-authoritative)', async () => {
    const draft = await docs.create({ typeId: 'article', tenantId: 'default', title: 'Secret zebra draft', data: { body: '' } }, 'u1') // never published
    const svc = new AISearchService(db, undefined, undefined, 'default')
    const res = await svc.search({ query: 'zebra', mode: 'keyword', filters: { status: ['draft'] } })
    expect(res.results.map((r) => r.id)).not.toContain(draft.id)
    expect(res.total).toBe(0)
  })

  it('escapes HTML in title/snippet, preserving only <mark> highlights (R8)', async () => {
    // Title is indexed RAW → the escaping is the only defense. Body goes through the harvester's
    // stripHtml first (so well-formed tags never reach the index), but a bare `<` survives stripping
    // and must still be escaped in the snippet — the escaping backstop.
    const x = await pub({
      title: 'zephyr <img src=x onerror=alert(1)>',
      slug: 'x',
      data: { body: 'a zephyr < unescaped body marker' },
    })
    const svc = new AISearchService(db, undefined, undefined, 'default')
    const hit = (await svc.search({ query: 'zephyr', mode: 'keyword', filters: {} })).results.find((r) => r.id === x.id)
    expect(hit).toBeTruthy()
    expect(hit.title).toContain('<mark>') // the matched term is still wrapped
    expect(hit.title).not.toContain('<img') // injected tag neutralized
    expect(hit.title).toContain('&lt;img')
    expect(hit.snippet).toContain('<mark>zephyr</mark>') // highlight preserved in the body snippet
    expect(hit.snippet).toContain('&lt;') // the bare `<` is escaped, not passed through raw
  })

  it('escapes HTML in slug too, not just title/snippet (R8)', async () => {
    // slug has no charset restriction at the schema layer, and unlike title/snippet it was never
    // routed through the escape pipeline — inconsistent with the rest of this same hardening pass.
    const x = await pub({
      title: 'kestrel result',
      slug: 'kestrel"><img src=x onerror=alert(1)>',
      data: { body: 'about a kestrel' },
    })
    const svc = new AISearchService(db, undefined, undefined, 'default')
    const hit = (await svc.search({ query: 'kestrel', mode: 'keyword', filters: {} })).results.find((r) => r.id === x.id)
    expect(hit).toBeTruthy()
    expect(hit.slug).not.toContain('<img')
    expect(hit.slug).toContain('&lt;img')
  })

  it('returns result timestamps in milliseconds, not seconds (response boundary)', async () => {
    const a = await pub({ title: 'chronometer', slug: 'c', data: { body: '' } })
    const svc = new AISearchService(db, undefined, undefined, 'default')
    const hit = (await svc.search({ query: 'chronometer', mode: 'keyword', filters: {} })).results.find((r) => r.id === a.id)
    expect(hit.created_at).toBeGreaterThan(1e12) // ms ≈ 1.7e12; seconds would be ≈ 1.7e9
  })

  it('clamps an oversized caller limit (DoS guard)', async () => {
    for (let i = 0; i < 3; i++) await pub({ title: `widget ${i}`, slug: `w${i}`, data: { body: 'widget' } })
    const svc = new AISearchService(db, undefined, undefined, 'default')
    // limit far above MAX_LIMIT (100) must not throw and must be capped; 3 docs → 3 results
    const res = await svc.search({ query: 'widget', mode: 'keyword', filters: {}, limit: 1_000_000_000 })
    expect(res.results.length).toBe(3)
  })
})
