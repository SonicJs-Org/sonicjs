// @ts-nocheck
// D45 regression: the document repository migration was renumbered (037 -> 043). A DB that applied the
// old 037 keeps a `documents` table, so `CREATE TABLE IF NOT EXISTS documents` is a no-op and the q_*
// VIRTUAL generated columns are never added — and every q_* query then 500s. MigrationService must
// self-heal at bootstrap by adding the missing columns. Real SQLite (better-sqlite3) with a documents
// table that predates the generated columns.
import { describe, it, expect } from 'vitest'
import Database from 'better-sqlite3'
import { MigrationService } from '../../services/migrations'

// Minimal D1-like adapter over better-sqlite3 (prepare/bind/run/all/first) — enough for MigrationService.
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

describe('MigrationService D45 — documents generated columns self-heal', () => {
  it('adds the missing q_* generated columns to a pre-existing documents table', async () => {
    const sqlite = new Database(':memory:')
    // A documents table from before the generated-column set was finalized (base columns + data only).
    sqlite.exec("CREATE TABLE documents (id TEXT PRIMARY KEY, root_id TEXT, type_id TEXT, data TEXT NOT NULL DEFAULT '{}', created_at INTEGER, updated_at INTEGER)")
    sqlite.prepare("INSERT INTO documents (id, root_id, type_id, data) VALUES ('1','1','testimonials', '{\"rating\":5,\"sortOrder\":2}')").run()

    const colsBefore = sqlite.prepare("SELECT name FROM pragma_table_xinfo('documents')").all().map((r: any) => r.name)
    expect(colsBefore.some((n: string) => n.startsWith('q_'))).toBe(false)

    // Bootstrap-time status check triggers autoDetectAppliedMigrations → ensureDocumentGeneratedColumns.
    await new MigrationService(adapter(sqlite) as any).getMigrationStatus()

    const colsAfter = sqlite.prepare("SELECT name FROM pragma_table_xinfo('documents')").all().map((r: any) => r.name)
    for (const c of ['q_tst_rating', 'q_tst_sort_order', 'q_tst_company', 'q_blog_author', 'q_blog_difficulty', 'q_media_mime', 'q_faq_category', 'q_msg_email']) {
      expect(colsAfter).toContain(c)
    }
    // Generated values are computed from the existing data JSON (no backfill needed).
    const row = sqlite.prepare("SELECT q_tst_rating r, q_tst_sort_order s FROM documents WHERE id='1'").get() as any
    expect(row.r).toBe(5)
    expect(row.s).toBe(2)
    sqlite.close()
  })

  it('is a no-op when the documents table already has every generated column', async () => {
    const sqlite = new Database(':memory:')
    sqlite.exec(`CREATE TABLE documents (id TEXT PRIMARY KEY, data TEXT NOT NULL DEFAULT '{}',
      q_tst_rating INTEGER AS (json_extract(data,'$.rating')) VIRTUAL)`)
    // Should not throw on the existing q_tst_rating column (duplicate-column errors are swallowed).
    await new MigrationService(adapter(sqlite) as any).getMigrationStatus()
    const cols = sqlite.prepare("SELECT name FROM pragma_table_xinfo('documents')").all().map((r: any) => r.name)
    expect(cols).toContain('q_tst_rating')
    expect(cols).toContain('q_blog_author') // the rest were still added
    sqlite.close()
  })
})
