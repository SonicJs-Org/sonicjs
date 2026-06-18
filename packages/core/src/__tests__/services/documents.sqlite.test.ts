// @ts-nocheck
// Real-SQLite coverage (migration 037 applied) for the document write path.
// Unlike documents.test.ts (pure vi.fn() mock, logic-only), these tests execute actual SQL,
// so they catch bind/column/placeholder mismatches, constraint violations, batch atomicity,
// and generated-column behavior. Each test below maps to a Phase-0/1 defect (D1/D3/D9).
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import { DocumentsService } from '../../services/documents'
import { DocumentProjection } from '../../services/document-projection'
import { DocumentRepository } from '../../services/document-repository'
import { DocumentPermissionsService } from '../../services/document-permissions'

const TST_FIELDS = [
  { name: 'rating', kind: 'scalar', type: 'integer', column: 'q_tst_rating' },
  { name: 'authorCompany', kind: 'scalar', type: 'text', column: 'q_tst_company' },
  { name: 'sortOrder', kind: 'scalar', type: 'integer', column: 'q_tst_sort_order' },
  { name: 'tags', kind: 'facet', type: 'text' },
]

function svc(db, tenantId = 'default') {
  // Existing tests were written against the versioned (new-row) path; keep versioning:true here.
  return new DocumentsService(db, { queryableFields: TST_FIELDS, tenantId, typeSchemaVersion: 1, versioning: true })
}

function count(db, sql, ...args) {
  return db.raw.prepare(sql).get(...args)
}

describe('DocumentsService — real SQLite (migration 037)', () => {
  let db
  beforeEach(async () => {
    db = createTestD1()
    db.raw
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
         VALUES ('testimonial','testimonial','Testimonial','{}','[]','{}','system',1,1,1,1,1)`,
      )
      .run()
    // Migrations ship only the base documents schema; add this type's q_* generated columns.
    await db.applyScalarSchema('testimonial', TST_FIELDS)
  })
  afterEach(() => db.close())

  it('create persists a row and computes generated columns + facets', async () => {
    const s = svc(db)
    const doc = await s.create(
      { typeId: 'testimonial', tenantId: 'default', title: 'Jane', data: { rating: 5, authorCompany: 'Acme', sortOrder: 1, tags: ['vip'] } },
      'u1',
    )
    expect(doc.versionNumber).toBe(1)
    expect(doc.isCurrentDraft).toBe(true)

    const row = db.raw.prepare('SELECT q_tst_rating r, q_tst_company c FROM documents WHERE id=?').get(doc.id)
    expect(row.r).toBe(5)
    expect(row.c).toBe('Acme')

    const facets = db.raw.prepare('SELECT value_text FROM document_facets WHERE document_id=? ORDER BY ordinal').all(doc.id)
    expect(facets.map((f) => f.value_text)).toEqual(['vip'])
  })

  it('D34: create preserves supplied createdAt/updatedAt (backfill fidelity) and seeds publishedAt', async () => {
    const s = svc(db)
    const createdAt = 1_600_000_000 // a fixed past timestamp (seconds)
    const updatedAt = 1_600_500_000
    const doc = await s.create(
      { typeId: 'testimonial', tenantId: 'default', title: 'Old', data: { rating: 5 }, publishOnCreate: true, createdAt, updatedAt },
      'u1',
    )
    const row = db.raw.prepare('SELECT created_at, updated_at, published_at FROM documents WHERE id=?').get(doc.id)
    expect(row.created_at).toBe(createdAt)
    expect(row.updated_at).toBe(updatedAt)
    expect(row.published_at).toBe(createdAt) // published backfill seeds publishedAt from createdAt

    // Omitting the overrides still defaults to "now" (normal create path unchanged).
    const fresh = await s.create({ typeId: 'testimonial', tenantId: 'default', title: 'New', data: {} })
    const freshRow = db.raw.prepare('SELECT created_at FROM documents WHERE id=?').get(fresh.id)
    expect(freshRow.created_at).toBeGreaterThan(createdAt)
  })

  it('D1 regression: saveDraft inserts v2 with all columns, merges data, demotes prev draft', async () => {
    const s = svc(db)
    const doc = await s.create({ typeId: 'testimonial', tenantId: 'default', title: 'Jane', data: { rating: 5, authorCompany: 'Acme', sortOrder: 1 } })

    // Pre-fix this threw (30 cols / 26 placeholders / 27 binds).
    const v2 = await s.saveDraft(doc.rootId, { data: { rating: 4 } })

    expect(v2.versionNumber).toBe(2)
    expect(v2.isCurrentDraft).toBe(true)
    expect(v2.data.rating).toBe(4)
    expect(v2.data.authorCompany).toBe('Acme') // merged from prev draft
    expect(count(db, 'SELECT COUNT(*) n FROM documents WHERE root_id=? AND is_current_draft=1', doc.rootId).n).toBe(1)
  })

  it('two-axis: saveDraft of a published doc keeps it live; publish moves the flag; unpublish clears it', async () => {
    const s = svc(db)
    const doc = await s.create({ typeId: 'testimonial', tenantId: 'default', data: { rating: 5 }, publishOnCreate: true })
    expect(doc.isPublished).toBe(true)

    const v2 = await s.saveDraft(doc.rootId, { data: { rating: 4 } })
    // v1 still published, v2 is the current draft and not published
    expect(db.raw.prepare('SELECT version_number FROM documents WHERE root_id=? AND is_published=1').get(doc.rootId).version_number).toBe(1)
    expect(v2.isPublished).toBe(false)

    const pubV2 = await s.publish(v2.id)
    expect(count(db, 'SELECT COUNT(*) n FROM documents WHERE root_id=? AND is_published=1', doc.rootId).n).toBe(1)
    expect(db.raw.prepare('SELECT version_number FROM documents WHERE root_id=? AND is_published=1').get(doc.rootId).version_number).toBe(2)

    await s.unpublish(pubV2.id)
    expect(count(db, 'SELECT COUNT(*) n FROM documents WHERE root_id=? AND is_published=1', doc.rootId).n).toBe(0)
  })

  it('D9: a service for tenant B cannot saveDraft tenant A’s root', async () => {
    const a = svc(db, 'tenantA')
    const doc = await a.create({ typeId: 'testimonial', tenantId: 'tenantA', data: { rating: 5 } })

    const b = svc(db, 'tenantB')
    await expect(b.saveDraft(doc.rootId, { data: { rating: 1 } })).rejects.toThrow()

    // Tenant A's root is untouched — no v2 leaked in.
    expect(count(db, 'SELECT COUNT(*) n FROM documents WHERE root_id=?', doc.rootId).n).toBe(1)
  })

  it('version_number is monotonic and the one-current-draft partial unique index is enforced', async () => {
    const s = svc(db)
    const doc = await s.create({ typeId: 'testimonial', tenantId: 'default', data: { rating: 5 } })
    await s.saveDraft(doc.rootId, { data: { rating: 4 } })
    await s.saveDraft(doc.rootId, { data: { rating: 3 } })

    const agg = count(db, 'SELECT MAX(version_number) m, COUNT(*) c FROM documents WHERE root_id=? AND is_current_draft=1', doc.rootId)
    expect(agg.m).toBe(3)
    expect(agg.c).toBe(1)

    // Forcing a second current draft must violate idx_documents_one_current_draft.
    const old = db.raw.prepare('SELECT id FROM documents WHERE root_id=? AND is_current_draft=0 LIMIT 1').get(doc.rootId)
    expect(() => db.raw.prepare('UPDATE documents SET is_current_draft=1 WHERE id=?').run(old.id)).toThrow(/UNIQUE/i)
  })

  it('golden: incremental projection == reindexType rebuild', async () => {
    const s = svc(db)
    const doc = await s.create({ typeId: 'testimonial', tenantId: 'default', data: { rating: 5, tags: ['a', 'b'] } })

    const before = db.raw.prepare('SELECT field_name, ordinal, value_text FROM document_facets WHERE document_id=? ORDER BY field_name, ordinal').all(doc.id)

    await new DocumentProjection(db).reindexType('testimonial', 'default', TST_FIELDS)

    const after = db.raw.prepare('SELECT field_name, ordinal, value_text FROM document_facets WHERE document_id=? ORDER BY field_name, ordinal').all(doc.id)
    expect(after).toEqual(before)
    expect(after.map((f) => f.value_text)).toEqual(['a', 'b'])
  })

  it('erase removes every version row and all derived rows for a root', async () => {
    const s = svc(db)
    const doc = await s.create({ typeId: 'testimonial', tenantId: 'default', data: { rating: 5, tags: ['x'] } })
    await s.saveDraft(doc.rootId, { data: { rating: 4 } })

    await s.erase(doc.rootId, 'default')

    expect(count(db, 'SELECT COUNT(*) n FROM documents WHERE root_id=?', doc.rootId).n).toBe(0)
    expect(count(db, 'SELECT COUNT(*) n FROM document_facets WHERE root_id=?', doc.rootId).n).toBe(0)
  })
})

describe('DocumentRepository.list — filters / facet / sort / tenant (D10)', () => {
  let db
  beforeEach(async () => {
    db = createTestD1()
    db.raw
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
         VALUES ('testimonial','testimonial','Testimonial','{}','[]','{}','system',1,1,1,1,1)`,
      )
      .run()
    // Migrations ship only the base documents schema; add this type's q_* generated columns.
    await db.applyScalarSchema('testimonial', TST_FIELDS)
  })
  afterEach(() => db.close())

  async function seed() {
    const s = svc(db)
    await s.create({ typeId: 'testimonial', tenantId: 'default', title: 'A', data: { rating: 5, authorCompany: 'Acme', sortOrder: 2, tags: ['vip', 'home'] }, publishOnCreate: true })
    await s.create({ typeId: 'testimonial', tenantId: 'default', title: 'B', data: { rating: 3, authorCompany: 'Beta', sortOrder: 1, tags: ['home'] }, publishOnCreate: true })
  }

  it('filters on a generated scalar column', async () => {
    await seed()
    const r = await new DocumentRepository(db, 'default').list({ typeId: 'testimonial', status: 'published', scalarFilters: [{ column: 'q_tst_rating', value: 5 }] })
    expect(r.map(d => d.title)).toEqual(['A'])
  })

  it('filters via the document_facets join', async () => {
    await seed()
    const repo = new DocumentRepository(db, 'default')
    expect((await repo.list({ typeId: 'testimonial', status: 'published', facetFilter: { field: 'tags', value: 'vip' } })).map(d => d.title)).toEqual(['A'])
    expect((await repo.list({ typeId: 'testimonial', status: 'published', facetFilter: { field: 'tags', value: 'home' } })).map(d => d.title).sort()).toEqual(['A', 'B'])
  })

  it('sorts by a generated column ascending', async () => {
    await seed()
    const r = await new DocumentRepository(db, 'default').list({ typeId: 'testimonial', status: 'published', sortColumn: 'q_tst_sort_order', sortDir: 'ASC' })
    expect(r.map(d => d.title)).toEqual(['B', 'A'])
  })

  it('rejects an unsafe filter/sort identifier (defense-in-depth)', async () => {
    const repo = new DocumentRepository(db, 'default')
    await expect(repo.list({ typeId: 'testimonial', scalarFilters: [{ column: 'q_tst_rating; DROP TABLE documents', value: 1 }] })).rejects.toThrow(/Unsafe/i)
    await expect(repo.list({ typeId: 'testimonial', sortColumn: 'updated_at)); DROP' })).rejects.toThrow(/Unsafe/i)
  })

  it('is tenant-scoped', async () => {
    await seed()
    expect(await new DocumentRepository(db, 'other').list({ typeId: 'testimonial', status: 'published' })).toEqual([])
  })
})

describe('Blog posts document-backed (Option B, migration 044)', () => {
  let db

  const BLOG_FIELDS = [
    { name: 'difficulty', kind: 'scalar', type: 'text', column: 'q_blog_difficulty' },
    { name: 'author', kind: 'scalar', type: 'text', column: 'q_blog_author' },
  ]

  beforeEach(async () => {
    db = createTestD1()
    db.raw
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
         VALUES ('blog_post','blog_post','Blog Posts','{}','[]','{}','system',1,1,1,1,1)`,
      )
      .run()
    // Migrations ship only the base documents schema; add this type's q_* generated columns.
    await db.applyScalarSchema('blog_post', BLOG_FIELDS)
  })
  afterEach(() => db.close())

  it('create populates q_blog_* generated columns and filters via repo.list', async () => {
    const s = new DocumentsService(db, { queryableFields: BLOG_FIELDS, tenantId: 'default' })
    await s.create({ typeId: 'blog_post', tenantId: 'default', title: 'Hello', slug: 'hello', data: { difficulty: 'advanced', author: 'Lane', content: '<p>hi</p>', excerpt: 'x' }, publishOnCreate: true })
    await s.create({ typeId: 'blog_post', tenantId: 'default', title: 'Easy One', slug: 'easy', data: { difficulty: 'beginner', author: 'Sam', content: '<p>yo</p>' }, publishOnCreate: true })

    const row = db.raw.prepare("SELECT q_blog_difficulty d, q_blog_author a FROM documents WHERE slug='hello'").get()
    expect(row.d).toBe('advanced')
    expect(row.a).toBe('Lane')

    const filtered = await new DocumentRepository(db, 'default').list({ typeId: 'blog_post', status: 'published', scalarFilters: [{ column: 'q_blog_difficulty', value: 'advanced' }] })
    expect(filtered.map(d => d.title)).toEqual(['Hello'])
  })

  it('edit-while-published: saveDraft keeps the published post live, publish swaps it', async () => {
    const s = new DocumentsService(db, { queryableFields: BLOG_FIELDS, tenantId: 'default' })
    const post = await s.create({ typeId: 'blog_post', tenantId: 'default', title: 'V1', slug: 'p', data: { difficulty: 'beginner', author: 'Lane', content: 'v1' }, publishOnCreate: true })
    const draft = await s.saveDraft(post.rootId, { title: 'V2', data: { content: 'v2' } })
    // published row is still v1
    expect(db.raw.prepare('SELECT title FROM documents WHERE root_id=? AND is_published=1').get(post.rootId).title).toBe('V1')
    await s.publish(draft.id)
    expect(db.raw.prepare('SELECT title FROM documents WHERE root_id=? AND is_published=1').get(post.rootId).title).toBe('V2')
  })
})

describe('Document ACL — isAllowed against real document_permissions (D5/D11)', () => {
  let db
  beforeEach(() => { db = createTestD1() })
  afterEach(() => db.close())

  const PUBLIC_READ = { baseGrants: { public: ['read'], editor: ['read', 'update'] } }   // faq/testimonial/media
  const NO_PUBLIC = { baseGrants: { admin: ['read', 'manage'], editor: ['read'] } }        // contact_message (PII)

  it('public principal can read a type that grants public:[read]', async () => {
    const repo = new DocumentRepository(db, 'default')
    expect(await repo.isAllowed([{ type: 'public', id: '*' }], 'root1', 'read', PUBLIC_READ)).toBe(true)
  })

  it('public principal is denied a type with no public grant (contact_message stays hidden)', async () => {
    const repo = new DocumentRepository(db, 'default')
    expect(await repo.isAllowed([{ type: 'public', id: '*' }], 'root1', 'read', NO_PUBLIC)).toBe(false)
  })

  it('explicit public deny override hides a published-but-public type (deny wins)', async () => {
    const perms = new DocumentPermissionsService(db)
    await perms.grantPermission({ tenantId: 'default', rootId: 'root1', principalType: 'public', principalId: '*', permission: 'read', effect: 'deny' })
    const repo = new DocumentRepository(db, 'default')
    expect(await repo.isAllowed([{ type: 'public', id: '*' }], 'root1', 'read', PUBLIC_READ)).toBe(false)
  })

  it('an authed user matches role base grants only when the role principal is included (D11)', async () => {
    const repo = new DocumentRepository(db, 'default')
    expect(await repo.isAllowed([{ type: 'user', id: 'u1' }], 'root1', 'update', PUBLIC_READ)).toBe(false)
    expect(await repo.isAllowed([{ type: 'user', id: 'u1' }, { type: 'role', id: 'editor' }], 'root1', 'update', PUBLIC_READ)).toBe(true)
  })

  it("'create' check with empty root falls to base grants (Phase 2b: editor yes, viewer no)", async () => {
    const repo = new DocumentRepository(db, 'default')
    const settings = { baseGrants: { editor: ['create', 'read'], viewer: ['read'] } }
    expect(await repo.isAllowed([{ type: 'role', id: 'editor' }], '', 'create', settings)).toBe(true)
    expect(await repo.isAllowed([{ type: 'role', id: 'viewer' }], '', 'create', settings)).toBe(false)
  })

  it('a deny override in tenant A does not affect resolution in tenant B', async () => {
    const perms = new DocumentPermissionsService(db)
    await perms.grantPermission({ tenantId: 'tenantA', rootId: 'root1', principalType: 'public', principalId: '*', permission: 'read', effect: 'deny' })
    const repoB = new DocumentRepository(db, 'tenantB')
    expect(await repoB.isAllowed([{ type: 'public', id: '*' }], 'root1', 'read', PUBLIC_READ)).toBe(true)
  })
})

describe('versioning off', () => {
  let db
  const VERSIONING_FIELDS = [
    { name: 'rating', kind: 'scalar', type: 'integer', column: 'q_tst_rating' },
    { name: 'tags', kind: 'facet', type: 'text' },
  ]

  function vSvc(db, versioning = false) {
    return new DocumentsService(db, { queryableFields: VERSIONING_FIELDS, tenantId: 'default', typeSchemaVersion: 1, versioning })
  }

  beforeEach(() => {
    db = createTestD1()
    db.raw
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
         VALUES ('verstest','verstest','VersionTest','{}','[]','{}','system',1,1,1,1,1)`,
      )
      .run()
  })
  afterEach(() => db.close())

  it('1. in-place edit keeps one row — version_number and id unchanged', async () => {
    const s = vSvc(db, false)
    const doc = await s.create({ typeId: 'verstest', tenantId: 'default', data: { rating: 1 } })
    const origId = doc.id
    const origVersion = doc.versionNumber

    await s.saveDraft(doc.rootId, { data: { rating: 2 } })
    await s.saveDraft(doc.rootId, { data: { rating: 3 } })

    const cnt = db.raw.prepare('SELECT COUNT(*) n FROM documents WHERE root_id=?').get(doc.rootId)
    expect(cnt.n).toBe(1)

    const row = db.raw.prepare('SELECT id, version_number, data FROM documents WHERE root_id=?').get(doc.rootId)
    expect(row.id).toBe(origId)
    expect(row.version_number).toBe(origVersion)
    expect(JSON.parse(row.data).rating).toBe(3)
  })

  it('2. derived rows rebuilt on in-place edit — facets match new tags, no stale rows', async () => {
    const s = vSvc(db, false)
    const doc = await s.create({ typeId: 'verstest', tenantId: 'default', data: { rating: 1, tags: ['a', 'b'] } })

    await s.saveDraft(doc.rootId, { data: { tags: ['c'] } })

    const facets = db.raw
      .prepare('SELECT value_text FROM document_facets WHERE document_id=? ORDER BY ordinal')
      .all(doc.id)
    expect(facets.map((f) => f.value_text)).toEqual(['c'])
  })

  it('3. publish deletes superseded row — no FK error, at most 2 rows', async () => {
    const s = vSvc(db, false)
    const doc = await s.create({ typeId: 'verstest', tenantId: 'default', data: { rating: 1 } })
    await s.publish(doc.id)

    // saveDraft on published row creates a new draft (published row stays live)
    const draft = await s.saveDraft(doc.rootId, { data: { rating: 2 } })
    expect(db.raw.prepare('SELECT COUNT(*) n FROM documents WHERE root_id=?').get(doc.rootId).n).toBe(2)

    // publish again — old published row should be deleted
    await expect(s.publish(draft.id)).resolves.not.toThrow()

    const rows = db.raw.prepare('SELECT COUNT(*) n FROM documents WHERE root_id=?').get(doc.rootId)
    expect(rows.n).toBeLessThanOrEqual(2)

    const pubRows = db.raw.prepare('SELECT COUNT(*) n FROM documents WHERE root_id=? AND is_published=1').get(doc.rootId)
    expect(pubRows.n).toBe(1)
  })

  it('4. draft-while-published still works — published data unchanged', async () => {
    const s = vSvc(db, false)
    const doc = await s.create({ typeId: 'verstest', tenantId: 'default', data: { rating: 1 } })
    await s.publish(doc.id)

    // saveDraft on the live published row creates a new draft row
    const draft = await s.saveDraft(doc.rootId, { data: { rating: 99 } })
    expect(draft.isCurrentDraft).toBe(true)
    expect(draft.isPublished).toBe(false)

    // Original published row data unchanged
    const pubRow = db.raw.prepare('SELECT data FROM documents WHERE root_id=? AND is_published=1').get(doc.rootId)
    expect(JSON.parse(pubRow.data).rating).toBe(1)
  })

  it('5. regression: versioning:true accumulates history rows', async () => {
    const s = vSvc(db, true)
    const doc = await s.create({ typeId: 'verstest', tenantId: 'default', data: { rating: 1 } })
    await s.saveDraft(doc.rootId, { data: { rating: 2 } })
    await s.saveDraft(doc.rootId, { data: { rating: 3 } })

    const cnt = db.raw.prepare('SELECT COUNT(*) n FROM documents WHERE root_id=?').get(doc.rootId)
    expect(cnt.n).toBe(3)

    const maxV = db.raw.prepare('SELECT MAX(version_number) m FROM documents WHERE root_id=?').get(doc.rootId)
    expect(maxV.m).toBe(3)
  })

  it('6. maxVersionsPerRoot irrelevant when versioning off — 60 saves leave <= 2 rows', async () => {
    const s = new DocumentsService(db, {
      queryableFields: VERSIONING_FIELDS,
      tenantId: 'default',
      typeSchemaVersion: 1,
      versioning: false,
      maxVersionsPerRoot: 1,
    })
    const doc = await s.create({ typeId: 'verstest', tenantId: 'default', data: { rating: 0 } })
    for (let i = 1; i <= 60; i++) {
      await s.saveDraft(doc.rootId, { data: { rating: i } })
    }
    const cnt = db.raw.prepare('SELECT COUNT(*) n FROM documents WHERE root_id=?').get(doc.rootId)
    expect(cnt.n).toBeLessThanOrEqual(2)
  })
})
