// @ts-nocheck
// Real-SQLite coverage for DocumentRepository's admin "All" index (listAdminIndex / countAdminIndex).
// Guards the D1-overload fix: the default All view must walk idx_docs_tenant_draft_updated in
// updated_at order (no temp B-tree sort), and the count must stop after cap + 1 matches.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import { DocumentRepository } from '../../services/document-repository'

const TYPES = ['article', 'event']

function seed(db, n: number, opts: { type?: string; tenant?: string; deleted?: boolean; published?: number; startTs?: number } = {}) {
  db.raw.prepare(
    `INSERT OR IGNORE INTO document_types (id, name, display_name, schema, queryable_fields, settings, source, schema_version, is_system, is_active, created_at, updated_at)
     VALUES (?, ?, ?, '{}', '[]', '{}', 'code', 1, 0, 1, 1, 1)`,
  ).run(opts.type ?? 'article', opts.type ?? 'article', (opts.type ?? 'article').toUpperCase())
  const ins = db.raw.prepare(
    `INSERT INTO documents (id, root_id, type_id, type_version, version_number, is_current_draft, is_published, status,
       parent_root_id, title, slug, tenant_id, locale, translation_group_id, data, metadata, deleted_at, created_at, updated_at)
     VALUES (?, ?, ?, 1, 1, 1, ?, 'draft', '', ?, ?, ?, 'en', ?, ?, '{}', ?, ?, ?)`,
  )
  const base = opts.startTs ?? 1_700_000_000
  for (let i = 0; i < n; i++) {
    const id = `${opts.type ?? 'article'}-${opts.tenant ?? 'default'}-${opts.deleted ? 'del-' : ''}${base}-${i}`
    ins.run(id, id, opts.type ?? 'article', opts.published ?? 1, `Title ${id}`, id, opts.tenant ?? 'default', id,
      JSON.stringify({ author: i === 0 ? 'Grace Hopper' : 'Ada' }), opts.deleted ? base : null, base + i, base + i)
  }
}

describe('DocumentRepository admin "All" index — real SQLite', () => {
  let db: any
  let repo: DocumentRepository

  beforeEach(() => {
    db = createTestD1()
    repo = new DocumentRepository(db, 'default')
  })
  afterEach(() => db.close())

  it('lists newest-first with page/offset and maps display name + author', async () => {
    seed(db, 5, { type: 'article' })
    seed(db, 3, { type: 'event', startTs: 1_800_000_000 })
    const page1 = await repo.listAdminIndex({ typeIds: TYPES, limit: 4, offset: 0 })
    expect(page1.map(r => r.updated_at)).toEqual([...page1.map(r => r.updated_at)].sort((a, b) => b - a))
    expect(page1[0].type_display_name).toBe('EVENT')
    expect(page1[0].author_label).toBe('System')
    const page2 = await repo.listAdminIndex({ typeIds: TYPES, limit: 4, offset: 4 })
    expect(page2).toHaveLength(4)
    expect(new Set([...page1, ...page2].map(r => r.root_id)).size).toBe(8)
  })

  it('is tenant-scoped and honours type, status, deleted and search filters', async () => {
    seed(db, 4, { type: 'article' })
    seed(db, 2, { type: 'article', tenant: 'other' })
    seed(db, 2, { type: 'article', deleted: true, startTs: 1_600_000_000 })
    seed(db, 3, { type: 'article', published: 0, startTs: 1_650_000_000 })
    seed(db, 2, { type: 'event', startTs: 1_750_000_000 })
    const count = (o) => repo.countAdminIndex({ typeIds: TYPES, ...o }, 1000).then(r => r.count)
    expect(await count({})).toBe(9) // 4 + 3 drafts + 2 events; other tenant + deleted excluded
    expect(await count({ typeIds: ['article'] })).toBe(7)
    expect(await count({ status: 'published' })).toBe(6)
    expect(await count({ status: 'draft' })).toBe(3)
    expect(await count({ status: 'deleted' })).toBe(2)
    expect(await count({ search: 'Grace' })).toBe(3) // one per non-deleted, default-tenant seed batch
  })

  it('caps the count at cap and reports a lower bound only when there are more matches', async () => {
    seed(db, 12)
    expect(await repo.countAdminIndex({ typeIds: TYPES }, 12)).toEqual({ count: 12, capped: false })
    expect(await repo.countAdminIndex({ typeIds: TYPES }, 11)).toEqual({ count: 11, capped: true })
    expect(await repo.countAdminIndex({ typeIds: TYPES }, 100)).toEqual({ count: 12, capped: false })
  })

  it('stops counting after cap + 1 matches (bounded subquery, not an exact COUNT(*))', async () => {
    seed(db, 12)
    const calls: Array<{ sql: string; binds: unknown[] }> = []
    const origPrepare = db.prepare.bind(db)
    db.prepare = (sql: string) => {
      const stmt = origPrepare(sql)
      const origBind = stmt.bind.bind(stmt)
      stmt.bind = (...binds: unknown[]) => { calls.push({ sql, binds }); return origBind(...binds) }
      return stmt
    }
    await repo.countAdminIndex({ typeIds: TYPES }, 5)
    expect(calls).toHaveLength(1)
    expect(calls[0].sql).toMatch(/FROM \(SELECT 1 FROM documents d WHERE .* LIMIT \?\)/s)
    expect(calls[0].binds.at(-1)).toBe(6)
    // And SQLite really reads no more than cap + 1 matching rows: the subquery yields exactly 6.
    const inner = calls[0].sql.replace(/^SELECT COUNT\(\*\) AS count FROM \((.*)\)$/s, '$1')
    expect(db.raw.prepare(inner).all(...calls[0].binds)).toHaveLength(6)
  })

  it('serves the default list from idx_docs_tenant_draft_updated without a temp sort', async () => {
    seed(db, 50, { type: 'article' })
    seed(db, 50, { type: 'event' })
    const plans: string[] = []
    const origPrepare = db.prepare.bind(db)
    db.prepare = (sql: string) => {
      if (sql.includes('FROM documents d')) {
        plans.push(db.raw.prepare(`EXPLAIN QUERY PLAN ${sql}`).all(
          'default', ...TYPES, ...(sql.includes('OFFSET') ? [20, 0] : [101]),
        ).map(r => r.detail).join(' | '))
      }
      return origPrepare(sql)
    }
    await repo.listAdminIndex({ typeIds: TYPES, limit: 20, offset: 0 })
    await repo.countAdminIndex({ typeIds: TYPES }, 100)
    const [listPlan, countPlan] = plans
    expect(listPlan).toContain('idx_docs_tenant_draft_updated')
    expect(listPlan).not.toContain('TEMP B-TREE')
    // The count has no ORDER BY, so its type predicate must stay indexable (no unary `+`).
    expect(countPlan).toBeDefined()
  })

  it('keeps the unary + only on the ordered list query, not the count', async () => {
    const seen: string[] = []
    const origPrepare = db.prepare.bind(db)
    db.prepare = (sql: string) => { seen.push(sql); return origPrepare(sql) }
    await repo.listAdminIndex({ typeIds: TYPES, limit: 5, offset: 0 })
    await repo.countAdminIndex({ typeIds: TYPES }, 10)
    expect(seen[0]).toContain('+d.type_id IN')
    expect(seen[1]).toContain('d.type_id IN')
    expect(seen[1]).not.toContain('+d.type_id')
  })
})
