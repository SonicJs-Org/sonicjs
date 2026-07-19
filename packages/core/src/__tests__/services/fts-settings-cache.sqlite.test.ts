// @ts-nocheck
// Coverage for T1.3: FTS settings persist in KV (bm25 weights tune ranking) and the KV result cache
// serves repeat queries + busts on invalidation.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import { makeMockKVNamespace } from '../utils/mock-factories'
import { DocumentsService } from '../../services/documents'
import { AISearchService } from '../../plugins/core-plugins/ai-search-plugin/services/ai-search'
import {
  getFtsSettings,
  saveFtsSettings,
  DEFAULT_FTS_SETTINGS,
} from '../../plugins/core-plugins/ai-search-plugin/services/fts-settings.service'
import { invalidateResultCache } from '../../plugins/core-plugins/ai-search-plugin/services/fts-search-cache'

const FTS_FIELDS = [{ name: 'body', kind: 'fulltext' }]

describe('FTS settings + result cache (T1.3)', () => {
  let db
  let docs
  let kv
  beforeEach(() => {
    db = createTestD1()
    db.raw
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
         VALUES ('article','article','Article','{}','[]','{}','system',1,1,1,1,1)`,
      )
      .run()
    docs = new DocumentsService(db, { queryableFields: FTS_FIELDS, tenantId: 'default', typeSchemaVersion: 1, versioning: false })
    kv = makeMockKVNamespace()
  })
  afterEach(() => db.close())

  async function pub(input) {
    const d = await docs.create({ typeId: 'article', tenantId: 'default', ...input }, 'u1')
    await docs.publish(d.id, 'u1')
    return d
  }

  it('settings round-trip through KV (defaults when empty / absent, partial merge)', async () => {
    expect(await getFtsSettings(undefined)).toEqual(DEFAULT_FTS_SETTINGS)
    expect(await getFtsSettings(kv)).toEqual(DEFAULT_FTS_SETTINGS)
    const saved = await saveFtsSettings(kv, { titleBoost: 9, cacheTtlSeconds: 0 })
    expect(saved.titleBoost).toBe(9)
    const reloaded = await getFtsSettings(kv)
    expect(reloaded.titleBoost).toBe(9)
    expect(reloaded.slugBoost).toBe(DEFAULT_FTS_SETTINGS.slugBoost) // unspecified fields keep defaults
  })

  it('a bm25 weight change flips ranking', async () => {
    const a = await pub({ title: 'quantum', slug: 'a', data: { body: 'unrelated prose' } })
    const b = await pub({ title: 'unrelated title', slug: 'b', data: { body: 'quantum quantum quantum quantum quantum' } })

    // Default weights (title 5 ≫ body 1): the title hit (A) ranks first. Cache off so each search re-ranks.
    await saveFtsSettings(kv, { cacheTtlSeconds: 0 })
    let res = await new AISearchService(db, undefined, undefined, 'default', kv).search({ query: 'quantum', mode: 'keyword', filters: {} })
    expect(res.results[0].id).toBe(a.id)

    // Crank body weight up, drop title: the body hit (B) should now win.
    await saveFtsSettings(kv, { titleBoost: 0.1, bodyBoost: 50, cacheTtlSeconds: 0 })
    res = await new AISearchService(db, undefined, undefined, 'default', kv).search({ query: 'quantum', mode: 'keyword', filters: {} })
    expect(res.results[0].id).toBe(b.id)
  })

  it('result cache (opt-in) serves repeats and invalidation forces a fresh read', async () => {
    // Caching is OFF by default (cacheTtlSeconds=0): there is no write-path invalidation yet, so an
    // unpublished/deleted doc would otherwise linger in public search for the TTL (E2E 82 regression).
    // Opt the cache IN here to verify the mechanism itself (repeat-serving + settings invalidation).
    await saveFtsSettings(kv, { cacheTtlSeconds: 60 })
    const a = await pub({ title: 'cacheable', slug: 'c', data: { body: '' } })
    const svc = new AISearchService(db, undefined, undefined, 'default', kv)
    const r1 = await svc.search({ query: 'cacheable', mode: 'keyword', filters: {} })
    expect(r1.total).toBe(1)

    // Mutate the index out-of-band WITHOUT busting the cache → the stale cached hit is still served.
    await docs.softDelete(a.id)
    const r2 = await svc.search({ query: 'cacheable', mode: 'keyword', filters: {} })
    expect(r2.total).toBe(1)

    // Invalidate → the next read reflects the deletion.
    await invalidateResultCache(kv)
    const r3 = await svc.search({ query: 'cacheable', mode: 'keyword', filters: {} })
    expect(r3.total).toBe(0)
  })
})
