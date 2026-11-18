// @ts-nocheck
// Auto-DDL: ensureScalarSchema creates VIRTUAL generated columns + indexes for a type's scalar
// queryable fields, idempotently. resolveColumn honors explicit `column` and derives otherwise.
import { describe, it, expect, vi } from 'vitest'
import Database from 'better-sqlite3'
import { ensureScalarSchema, resolveColumn } from '../../services/document-scalar-schema'

function adapter(sqlite: any) {
  const norm = (v: any) => (v === undefined || v === null ? null : typeof v === 'boolean' ? (v ? 1 : 0) : v)
  const mk = (sql: string, binds: any[] = []) => ({
    bind: (...a: any[]) => mk(sql, a.map(norm)),
    async run() { const i = sqlite.prepare(sql).run(...binds); return { success: true, meta: { changes: i.changes } } },
    async all() { return { results: sqlite.prepare(sql).all(...binds), success: true, meta: {} } },
    async first(col?: string) { const r = sqlite.prepare(sql).get(...binds); return r == null ? null : (col ? r[col] : r) },
  })
  return { prepare: (sql: string) => mk(sql) }
}

function freshDocuments() {
  const sqlite = new Database(':memory:')
  sqlite.exec(`CREATE TABLE documents (
    id TEXT PRIMARY KEY, root_id TEXT, type_id TEXT, tenant_id TEXT DEFAULT 'default',
    data TEXT NOT NULL DEFAULT '{}', created_at INTEGER, updated_at INTEGER)`)
  return sqlite
}

describe('resolveColumn', () => {
  it('honors an explicit column name', () => {
    expect(resolveColumn('blog_post', { name: 'author', kind: 'scalar', column: 'q_blog_author' })).toBe('q_blog_author')
  })
  it('derives a sanitized name when column is omitted', () => {
    expect(resolveColumn('Projects', { name: 'launchDate', kind: 'scalar' })).toBe('q_projects_launchdate')
  })
})

describe('ensureScalarSchema', () => {
  it('adds a generated column + index for a new scalar field and computes its value', async () => {
    const sqlite = freshDocuments()
    sqlite.prepare("INSERT INTO documents (id, root_id, type_id, data) VALUES ('1','1','project', ?)")
      .run('{"status":"active","budget":1000}')

    const added = await ensureScalarSchema(adapter(sqlite) as any, 'project', [
      { name: 'status', kind: 'scalar', type: 'text' },
      { name: 'budget', kind: 'scalar', type: 'number' },
      { name: 'tags', kind: 'facet' }, // ignored — facets need no DDL
    ])

    expect(added).toEqual(['q_project_status', 'q_project_budget'])
    const idx = sqlite.prepare("SELECT name FROM sqlite_master WHERE type='index'").all().map((r: any) => r.name)
    expect(idx).toContain('idx_q_project_status')
    expect(idx).toContain('idx_q_project_budget')

    const row = sqlite.prepare("SELECT q_project_status s, q_project_budget b FROM documents WHERE id='1'").get() as any
    expect(row.s).toBe('active')
    expect(row.b).toBe(1000)
    sqlite.close()
  })

  it('is idempotent — second call adds nothing and does not throw', async () => {
    const sqlite = freshDocuments()
    const fields = [{ name: 'status', kind: 'scalar', type: 'text', column: 'q_proj_status' }]
    await ensureScalarSchema(adapter(sqlite) as any, 'project', fields as any)
    const added2 = await ensureScalarSchema(adapter(sqlite) as any, 'project', fields as any)
    expect(added2).toEqual([])
    const cols = sqlite.prepare("SELECT name FROM pragma_table_xinfo('documents')").all().map((r: any) => r.name)
    expect(cols.filter((c: string) => c === 'q_proj_status')).toHaveLength(1)
    sqlite.close()
  })

  it('returns empty and touches nothing when no scalar fields are present', async () => {
    const sqlite = freshDocuments()
    const added = await ensureScalarSchema(adapter(sqlite) as any, 'project', [{ name: 'tags', kind: 'facet' }])
    expect(added).toEqual([])
    sqlite.close()
  })
})

// The column/index cache is a module global, so the promise that fills it is shared with
// requests that did not create it. On Cloudflare a request's pending I/O is cancelled when its
// client disconnects, so a creator that is torn down mid-`batch` leaves that promise permanently
// pending — and every later caller on the isolate joins the same dead promise. These pin the
// deadline that stops it. See utils/shared-promise.
describe('ensureDocumentsCaches shared init promise', () => {
  it('fires its own PRAGMA batch when the shared promise never settles', async () => {
    const { resetScalarSchemaCache } = await import('../../services/document-scalar-schema')
    resetScalarSchemaCache()

    const wedged = {
      prepare: (sql: string) => ({ bind: () => wedged.prepare(sql) }),
      batch: () => new Promise(() => {}),
    }
    // The creator: never resolves, never awaited. This is the cancelled request.
    void ensureScalarSchema(wedged as any, 'project', [{ name: 'status', kind: 'scalar', type: 'text' }])
    await Promise.resolve()

    const sqlite = freshDocuments()
    const working = {
      ...adapter(sqlite),
      async batch(stmts: any[]) {
        return Promise.all(stmts.map((s: any) => s.all()))
      },
    }

    vi.useFakeTimers()
    try {
      const joined = ensureScalarSchema(working as any, 'project', [
        { name: 'status', kind: 'scalar', type: 'text' },
      ])
      // Past CACHE_INIT_DEADLINE_MS (5s): stop waiting on the dead promise, load it here.
      await vi.advanceTimersByTimeAsync(6_000)
      expect(await joined).toEqual(['q_project_status'])
    } finally {
      vi.useRealTimers()
      resetScalarSchemaCache()
    }
  })

  it('joins a healthy shared promise instead of duplicating the batch', async () => {
    const { resetScalarSchemaCache } = await import('../../services/document-scalar-schema')
    resetScalarSchemaCache()

    const sqlite = freshDocuments()
    let batches = 0
    const db = {
      ...adapter(sqlite),
      async batch(stmts: any[]) {
        batches += 1
        return Promise.all(stmts.map((s: any) => s.all()))
      },
    }

    try {
      const [a, b] = await Promise.all([
        ensureScalarSchema(db as any, 'project', [{ name: 'status', kind: 'scalar', type: 'text' }]),
        ensureScalarSchema(db as any, 'project', [{ name: 'status', kind: 'scalar', type: 'text' }]),
      ])
      // One PRAGMA batch for both callers — the dedupe the shared promise exists for.
      expect(batches).toBe(1)
      // Exactly one of them created the column; the other saw it already there.
      expect([a.length, b.length].sort()).toEqual([0, 1])
    } finally {
      resetScalarSchemaCache()
    }
  })
})
