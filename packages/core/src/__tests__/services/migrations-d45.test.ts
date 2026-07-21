// @ts-nocheck
// D45 regression: a DB that kept an older `documents` table (so `CREATE TABLE IF NOT EXISTS documents`
// is a no-op) is missing the q_* VIRTUAL generated columns, and every q_* query then 500s.
// MigrationService self-heals at bootstrap by reconciling the columns from each active document type's
// queryableFields (data-driven — no hardcoded column list). Real SQLite (better-sqlite3).
import { describe, it, expect, beforeEach } from 'vitest'
import Database from 'better-sqlite3'
import { MigrationService } from '../../services/migrations'
import { resetDocumentScalarSchemaCache } from '../../services/document-scalar-schema'

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

// Seed a documents table that predates the generated columns + a document_types row that declares them.
function seed(sqlite: any, typeId: string, queryableFields: any[], data: string) {
  sqlite.exec(`CREATE TABLE documents (
    id TEXT PRIMARY KEY, root_id TEXT, type_id TEXT, tenant_id TEXT DEFAULT 'default',
    data TEXT NOT NULL DEFAULT '{}', created_at INTEGER, updated_at INTEGER)`)
  sqlite.exec(`CREATE TABLE document_types (
    id TEXT PRIMARY KEY, queryable_fields TEXT NOT NULL DEFAULT '[]', is_active INTEGER NOT NULL DEFAULT 1)`)
  sqlite.prepare('INSERT INTO document_types (id, queryable_fields) VALUES (?, ?)')
    .run(typeId, JSON.stringify(queryableFields))
  sqlite.prepare('INSERT INTO documents (id, root_id, type_id, data) VALUES (?,?,?,?)')
    .run('1', '1', typeId, data)
}

describe('MigrationService D45 — documents generated columns self-heal (data-driven)', () => {
  beforeEach(() => {
    resetDocumentScalarSchemaCache()
  })

  it('adds the q_* generated columns + indexes declared by an active document type', async () => {
    const sqlite = new Database(':memory:')
    seed(sqlite, 'testimonial', [
      { name: 'rating', kind: 'scalar', type: 'integer', column: 'q_tst_rating' },
      { name: 'sortOrder', kind: 'scalar', type: 'integer', column: 'q_tst_sort_order' },
    ], '{"rating":5,"sortOrder":2}')

    const colsBefore = sqlite.prepare("SELECT name FROM pragma_table_xinfo('documents')").all().map((r: any) => r.name)
    expect(colsBefore.some((n: string) => n.startsWith('q_'))).toBe(false)

    // Bootstrap-time status check → ensureSchemaCompatibility → ensureDocumentGeneratedColumns.
    await new MigrationService(adapter(sqlite) as any).getMigrationStatus()

    const colsAfter = sqlite.prepare("SELECT name FROM pragma_table_xinfo('documents')").all().map((r: any) => r.name)
    expect(colsAfter).toContain('q_tst_rating')
    expect(colsAfter).toContain('q_tst_sort_order')

    // A filter index was created for each scalar column.
    const idx = sqlite.prepare("SELECT name FROM sqlite_master WHERE type='index'").all().map((r: any) => r.name)
    expect(idx).toContain('idx_q_tst_rating')

    // Generated values are computed from the existing data JSON (no backfill needed).
    const row = sqlite.prepare("SELECT q_tst_rating r, q_tst_sort_order s FROM documents WHERE id='1'").get() as any
    expect(row.r).toBe(5)
    expect(row.s).toBe(2)
    sqlite.close()
  })

  it('is a no-op when the columns already exist (idempotent, no throw)', async () => {
    const sqlite = new Database(':memory:')
    seed(sqlite, 'testimonial', [
      { name: 'rating', kind: 'scalar', type: 'integer', column: 'q_tst_rating' },
    ], '{"rating":5}')
    // First pass creates the column; second must not throw on the duplicate.
    await new MigrationService(adapter(sqlite) as any).getMigrationStatus()
    await new MigrationService(adapter(sqlite) as any).getMigrationStatus()
    const cols = sqlite.prepare("SELECT name FROM pragma_table_xinfo('documents')").all().map((r: any) => r.name)
    expect(cols).toContain('q_tst_rating')
    sqlite.close()
  })

  it('does not throw when document_types is absent', async () => {
    const sqlite = new Database(':memory:')
    sqlite.exec("CREATE TABLE documents (id TEXT PRIMARY KEY, data TEXT NOT NULL DEFAULT '{}')")
    await expect(new MigrationService(adapter(sqlite) as any).getMigrationStatus()).resolves.toBeTruthy()
    sqlite.close()
  })
})
